const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const MAX_BODY = 256 * 1024;
const MAX_TOOLS = 1000;
const MAX_COMMENTS = 5000;
const ID_RE = /^[a-zA-Z0-9_-]{1,100}$/;
const TOOL_PREFIX = "tools/";
const COMMENT_PREFIX = "comments/";

function json(data, status, origin, env, extra = {}) {
  const headers = new Headers({ ...HEADERS, ...extra });
  if (origin) {
    headers.set("access-control-allow-origin", origin);
    headers.set("access-control-allow-credentials", "true");
    headers.set("vary", "Origin");
  }
  return new Response(JSON.stringify(data), { status, headers });
}
function getOrigin(request, env) {
  const origin = request.headers.get("Origin") || "";
  const allowed = (env.ALLOWED_ORIGIN || "https://ben-scap.github.io").split(",").map(x => x.trim());
  return allowed.includes(origin) ? origin : null;
}
function validId(id) { return typeof id === "string" && ID_RE.test(id); }
function validUrl(value) {
  if (typeof value !== "string" || value.length > 2048) return false;
  try { const u = new URL(value); return ["http:", "https:"].includes(u.protocol); } catch { return false; }
}
function validJsonValue(value, depth = 0) {
  if (depth > 8) return false;
  if (value === null || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") return value.length <= 10000;
  if (Array.isArray(value)) return value.length <= 200 && value.every(v => validJsonValue(v, depth + 1));
  if (typeof value === "object") {
    const entries = Object.entries(value);
    return entries.length <= 100 && entries.every(([k, v]) => k.length <= 100 && validJsonValue(v, depth + 1));
  }
  return false;
}
function validTool(tool, id) {
  if (!tool || typeof tool !== "object" || Array.isArray(tool)) return false;
  if (tool.toolId !== id || !validId(id)) return false;
  if (typeof tool.name !== "string" || !tool.name.trim() || tool.name.length > 200) return false;
  if (typeof tool.category !== "string" || !/^(app|code|context|quality|delivery|ops)$/.test(tool.category)) return false;
  if (typeof tool.type !== "string" || !tool.type.trim() || tool.type.length > 120) return false;
  if (typeof tool.description !== "string" || tool.description.length > 5000) return false;
  if (!validUrl(tool.link_url)) return false;
  if (typeof tool.link_label !== "string" || tool.link_label.length > 200) return false;
  if (!tool.custom_fields || typeof tool.custom_fields !== "object" || Array.isArray(tool.custom_fields) || !validJsonValue(tool.custom_fields)) return false;
  return true;
}
function decodePart(part) {
  const padded = part.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(padded + "=".repeat((4 - padded.length % 4) % 4)));
}
async function verifyAccess(request, env) {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return false;
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) return false;
  try {
    const team = env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//, "").replace(/\/$/, "");
    const issuer = `https://${team}`;
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const header = decodePart(parts[0]), payload = decodePart(parts[1]);
    if (header.alg !== "RS256" || !header.kid || payload.iss !== issuer) return false;
    const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!aud.includes(env.ACCESS_AUD)) return false;
    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== "number" || payload.exp <= now || (payload.nbf && payload.nbf > now)) return false;
    const response = await fetch(`${issuer}/cdn-cgi/access/certs`);
    if (!response.ok) return false;
    const keys = await response.json();
    const jwk = keys.keys?.find(k => k.kid === header.kid);
    if (!jwk) return false;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const signature = Uint8Array.from(atob(parts[2].replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
    return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, new TextEncoder().encode(parts[0] + "." + parts[1]));
  } catch { return false; }
}
async function readJson(request) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_BODY) throw new Error("BODY_TOO_LARGE");
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_BODY) throw new Error("BODY_TOO_LARGE");
  return JSON.parse(raw);
}
async function listAll(bucket, prefix) {
  const keys = [];
  let cursor;
  do {
    const page = await bucket.list({ prefix, cursor, limit: 1000 });
    keys.push(...page.objects);
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return keys;
}
async function getTool(bucket, id) {
  const obj = await bucket.get(TOOL_PREFIX + id + ".json");
  if (!obj) return null;
  const tool = await obj.json();
  const comments = [];
  const keys = await listAll(bucket, COMMENT_PREFIX + id + "/");
  for (const key of keys) {
    const commentObj = await bucket.get(key.key);
    if (commentObj) comments.push(await commentObj.json());
  }
  comments.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
  return { ...tool, comments };
}
function accessReady(env) {
  return env.ACCESS_APP_CONFIGURED === "true" && Boolean(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD);
}
async function requireAdmin(request, env, origin) {
  if (!accessReady(env)) {
    return json({ error: "Modifications désactivées : Cloudflare Access n'est pas configuré côté Worker." }, 503, origin, env);
  }
  if (!await verifyAccess(request, env)) return json({ error: "Authentification Cloudflare Access requise." }, 401, origin, env);
  return null;
}

export default {
  async fetch(request, env) {
    const origin = getOrigin(request, env);
    if (request.method === "OPTIONS") {
      if (!origin) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: {
        "access-control-allow-origin": origin,
        "access-control-allow-credentials": "true",
        "access-control-allow-methods": "GET, POST, PUT, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "86400",
        "vary": "Origin"
      }});
    }
    if (!origin) return json({ error: "Origin non autorisée." }, 403, null, env);
    if (!env.OUTILS_BUCKET) return json({ error: "Liaison R2 OUTILS_BUCKET absente." }, 503, origin, env);
    const url = new URL(request.url);
    let path = url.pathname.replace(/\\/+$/, "") || "/";
    // Routes françaises demandées pour le catalogue public.
    const frenchCommentsMatch = path.match(/^\\/api\\/outils\\/([a-zA-Z0-9_-]{1,100})\\/commentaires$/);
    const frenchToolMatch = path.match(/^\\/api\\/outils\\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "GET" && frenchCommentsMatch) {
      const tool = await getTool(env.OUTILS_BUCKET, frenchCommentsMatch[1]);
      return tool ? json({ commentaires: tool.comments }, 200, origin, env) : json({ error: "Fiche introuvable." }, 404, origin, env);
    }
    if (request.method === "PUT" && frenchToolMatch) path = "/api/admin/tools/" + frenchToolMatch[1];
    if (request.method === "POST" && frenchCommentsMatch) path = "/api/admin/tools/" + frenchCommentsMatch[1] + "/comments";
    if (path === "/api/outils") path = "/api/tools";
    if (request.method === "GET" && frenchToolMatch) path = "/api/tools/" + frenchToolMatch[1];
    if (request.method === "GET" && path === "/api/status") {
      return json({ adminEnabled: accessReady(env) }, 200, origin, env);
    }
    if (request.method === "GET" && path === "/api/tools") {
      const keys = await listAll(env.OUTILS_BUCKET, TOOL_PREFIX);
      const result = [];
      for (const item of keys) {
        const id = item.key.slice(TOOL_PREFIX.length).replace(/\.json$/, "");
        if (validId(id)) {
          const tool = await getTool(env.OUTILS_BUCKET, id);
          if (tool) result.push(tool);
        }
      }
      return json({ tools: result }, 200, origin, env);
    }
    const toolMatch = path.match(/^\/api\/tools\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "GET" && toolMatch) {
      const tool = await getTool(env.OUTILS_BUCKET, toolMatch[1]);
      return tool ? json({ tool }, 200, origin, env) : json({ error: "Fiche introuvable." }, 404, origin, env);
    }
    if (path.startsWith("/api/admin/")) {
      const denied = await requireAdmin(request, env, origin);
      if (denied) return denied;
    }
    if (request.method === "POST" && path === "/api/admin/initialize") {
      let body;
      try { body = await readJson(request); } catch (e) { return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env); }
      if (!Array.isArray(body.tools) || body.tools.length > MAX_TOOLS) return json({ error: "Liste initiale invalide." }, 422, origin, env);
      const uniqueIds = new Set();
      for (const tool of body.tools) {
        const id = tool?.toolId;
        if (!validTool(tool, id) || uniqueIds.has(id)) return json({ error: "Une fiche initiale est invalide ou possède un identifiant en double.", toolId: id || null }, 422, origin, env);
        uniqueIds.add(id);
      }
      let created = 0, skipped = 0;
      for (const tool of body.tools) {
        const id = tool.toolId;
        const key = TOOL_PREFIX + id + ".json";
        const existing = await env.OUTILS_BUCKET.get(key);
        if (existing) { skipped++; continue; }
        const inserted = await env.OUTILS_BUCKET.put(key, JSON.stringify({ ...tool, version: 1, updatedAt: new Date().toISOString() }), {
          onlyIf: { etagDoesNotMatch: "*" },
          httpMetadata: { contentType: "application/json; charset=utf-8" }
        });
        if (inserted) created++; else skipped++;
      }
      return json({ ok: true, created, skipped }, 200, origin, env);
    }
    const editMatch = path.match(/^\/api\/admin\/tools\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "PUT" && editMatch) {
      const id = editMatch[1];
      let body;
      try { body = await readJson(request); } catch (e) { return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env); }
      const key = TOOL_PREFIX + id + ".json";
      const currentObj = await env.OUTILS_BUCKET.get(key);
      if (!currentObj) return json({ error: "Fiche absente. Initialisez le catalogue avant modification." }, 404, origin, env);
      const current = await currentObj.json();
      if (body.expectedVersion !== current.version) return json({ error: "CONFLICT", message: "Cette fiche a été modifiée depuis son ouverture. Rechargez-la avant de recommencer.", currentVersion: current.version }, 409, origin, env);
      const tool = body.tool;
      if (!validTool(tool, id)) return json({ error: "Fiche invalide : vérifiez les champs, les types et l'URL http/https." }, 422, origin, env);
      const updated = { ...tool, version: current.version + 1, updatedAt: new Date().toISOString() };
      const stored = await env.OUTILS_BUCKET.put(key, JSON.stringify(updated), {
        onlyIf: { etagMatches: currentObj.etag },
        httpMetadata: { contentType: "application/json; charset=utf-8" }
      });
      if (!stored) return json({ error: "CONFLICT", message: "La fiche a changé pendant l'enregistrement. Rechargez-la." }, 409, origin, env);
      return json({ ok: true, tool: updated }, 200, origin, env);
    }
    const commentMatch = path.match(/^\/api\/admin\/tools\/([a-zA-Z0-9_-]{1,100})\/comments$/);
    if (request.method === "POST" && commentMatch) {
      const id = commentMatch[1];
      const toolObj = await env.OUTILS_BUCKET.get(TOOL_PREFIX + id + ".json");
      if (!toolObj) return json({ error: "Fiche introuvable." }, 404, origin, env);
      let body;
      try { body = await readJson(request); } catch (e) { return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env); }
      if (typeof body.text !== "string" || !body.text.trim() || body.text.length > 5000) return json({ error: "Commentaire vide ou trop long (5000 caractères maximum)." }, 422, origin, env);
      const existingComments = await listAll(env.OUTILS_BUCKET, COMMENT_PREFIX + id + "/");
      if (existingComments.length >= MAX_COMMENTS) return json({ error: "Nombre maximal de commentaires atteint." }, 429, origin, env);
      const commentId = crypto.randomUUID();
      const comment = { commentId, toolId: id, text: body.text.trim(), createdAt: new Date().toISOString() };
      await env.OUTILS_BUCKET.put(COMMENT_PREFIX + id + "/" + commentId + ".json", JSON.stringify(comment), { httpMetadata: { contentType: "application/json; charset=utf-8" } });
      return json({ ok: true, comment }, 201, origin, env);
    }
    return json({ error: "Route introuvable." }, 404, origin, env);
  }
};
