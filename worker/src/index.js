const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const OBJECT_KEY = "catalogue/outils.json";

function response(body, status, origin, extraHeaders = {}) {
  return new Response(body, {
    status,
    headers: {
      ...JSON_HEADERS,
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, PUT, OPTIONS",
      "access-control-allow-headers": "content-type",
      "vary": "Origin",
      ...extraHeaders
    }
  });
}

function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGIN || "https://ben-scap.github.io")
    .split(",").map(value => value.trim()).filter(Boolean);
  return allowed.includes(origin) ? origin : null;
}

function validCatalog(value) {
  if (!value || typeof value !== "object" || !Array.isArray(value.tools)) return false;
  if (value.tools.length > 1000) return false;
  const ids = new Set();

  for (const tool of value.tools) {
    if (!tool || typeof tool !== "object" || Array.isArray(tool)) return false;
    if (typeof tool.id !== "string" || !/^[a-zA-Z0-9_-]{1,100}$/.test(tool.id)) return false;
    if (ids.has(tool.id)) return false;
    ids.add(tool.id);
    if (typeof tool.name !== "string" || !tool.name.trim() || tool.name.length > 200) return false;
    if (typeof tool.category !== "string" || tool.category.length > 80) return false;
    if (typeof tool.type !== "string" || tool.type.length > 120) return false;
    if (typeof tool.description !== "string" || tool.description.length > 5000) return false;
    if (typeof tool.link_url !== "string" || !/^https:\/\//i.test(tool.link_url)) return false;
    if (typeof tool.link_label !== "string" || tool.link_label.length > 200) return false;
    if (tool.comments !== undefined && !Array.isArray(tool.comments)) return false;
    if (tool.custom_fields !== undefined &&
        (!tool.custom_fields || typeof tool.custom_fields !== "object" || Array.isArray(tool.custom_fields))) return false;
  }
  return true;
}

async function verifyAccessJwt(token, env) {
  if (!token || !env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return false;
  try {
    const team = env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//, "").replace(/\/$/, "");
    const issuer = `https://${team}`;
    const [headerPart, payloadPart, signaturePart] = token.split(".");
    if (!headerPart || !payloadPart || !signaturePart) return false;

    const decode = part => JSON.parse(atob(part.replace(/-/g, "+").replace(/_/g, "/")));
    const header = decode(headerPart);
    const payload = decode(payloadPart);
    if (header.alg !== "RS256" || !header.kid) return false;
    if (payload.iss !== issuer || !Array.isArray(payload.aud) || !payload.aud.includes(env.ACCESS_AUD)) return false;
    if (typeof payload.exp !== "number" || payload.exp <= Math.floor(Date.now() / 1000)) return false;

    const certResponse = await fetch(`${issuer}/cdn-cgi/access/certs`);
    if (!certResponse.ok) return false;
    const certs = await certResponse.json();
    const jwk = certs.keys?.find(key => key.kid === header.kid);
    if (!jwk) return false;

    const key = await crypto.subtle.importKey(
      "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
    );
    const data = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
    const signature = Uint8Array.from(
      atob(signaturePart.replace(/-/g, "+").replace(/_/g, "/")),
      char => char.charCodeAt(0)
    );
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, data);
  } catch {
    return false;
  }
}

export default {
  async fetch(request, env) {
    const origin = allowedOrigin(request, env);
    if (request.method === "OPTIONS") {
      if (!origin) return new Response(null, { status: 403 });
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": origin,
          "access-control-allow-methods": "GET, PUT, OPTIONS",
          "access-control-allow-headers": "content-type",
          "access-control-max-age": "86400",
          "vary": "Origin"
        }
      });
    }

    if (!origin) return response(JSON.stringify({ error: "Origin non autorisée." }), 403, "null");
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/api/outils") {
      if (!env.OUTILS_BUCKET) return response(JSON.stringify({ error: "Liaison R2 OUTILS_BUCKET absente." }), 503, origin);
      const object = await env.OUTILS_BUCKET.get(OBJECT_KEY);
      if (!object) return response(JSON.stringify({ version: 1, tools: [] }), 200, origin);
      return new Response(object.body, {
        status: 200,
        headers: { ...JSON_HEADERS, "access-control-allow-origin": origin, "vary": "Origin" }
      });
    }

    if (request.method === "PUT" && url.pathname === "/api/admin/outils") {
      const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
      if (!await verifyAccessJwt(jwt, env)) {
        return response(JSON.stringify({ error: "Authentification Cloudflare Access invalide ou absente." }), 401, origin);
      }
      if (!env.OUTILS_BUCKET) return response(JSON.stringify({ error: "Liaison R2 OUTILS_BUCKET absente." }), 503, origin);
      const declaredLength = Number(request.headers.get("Content-Length") || 0);
      if (declaredLength > MAX_BODY_BYTES) return response(JSON.stringify({ error: "Catalogue trop volumineux." }), 413, origin);

      let catalog;
      try {
        const raw = await request.text();
        if (new TextEncoder().encode(raw).byteLength > MAX_BODY_BYTES) {
          return response(JSON.stringify({ error: "Catalogue trop volumineux." }), 413, origin);
        }
        catalog = JSON.parse(raw);
      } catch {
        return response(JSON.stringify({ error: "JSON invalide." }), 400, origin);
      }
      if (!validCatalog(catalog)) return response(JSON.stringify({ error: "Structure du catalogue invalide." }), 422, origin);

      catalog.version = 1;
      await env.OUTILS_BUCKET.put(OBJECT_KEY, JSON.stringify(catalog, null, 2), {
        httpMetadata: { contentType: "application/json; charset=utf-8" }
      });
      return response(JSON.stringify({ ok: true, key: OBJECT_KEY, tools: catalog.tools.length }), 200, origin);
    }

    return response(JSON.stringify({ error: "Route introuvable." }), 404, origin);
  }
};
