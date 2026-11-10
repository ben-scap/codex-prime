const CATEGORIES = new Set(["app", "code", "context", "quality", "delivery", "ops"]);
const MAX_BODY_BYTES = 32_768;
const MAX_COMMENT_LENGTH = 2_000;
const RESERVED_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const RESERVED_TOOL_FIELDS = new Set(["_version", "comments"]);
let cachedJwks = null;
let cachedJwksAt = 0;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers }
  });
}

function configured(env) {
  return env.ACCESS_ENABLED === "true" && Boolean(env.ACCESS_TEAM_DOMAIN && env.ACCESS_AUD && env.EDITOR_EMAILS);
}

function issuerFor(env) {
  const domain = String(env.ACCESS_TEAM_DOMAIN || "").trim().replace(/^https?:\/\//, "").replace(/\/+$/, "");
  return domain ? "https://" + domain : "";
}

function decodeBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function decodeJwtPart(value) {
  return JSON.parse(new TextDecoder().decode(decodeBase64Url(value)));
}

async function accessClaims(request, env) {
  if (!configured(env)) throw Object.assign(new Error("Protection Cloudflare Access non configurée."), { status: 503 });
  const token = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!token) throw Object.assign(new Error("Authentification Cloudflare Access requise."), { status: 401 });

  const parts = token.split(".");
  if (parts.length !== 3) throw Object.assign(new Error("Jeton Access invalide."), { status: 401 });
  let header, claims;
  try {
    header = decodeJwtPart(parts[0]);
    claims = decodeJwtPart(parts[1]);
  } catch {
    throw Object.assign(new Error("Jeton Access illisible."), { status: 401 });
  }

  const issuer = issuerFor(env);
  if (claims.iss !== issuer) throw Object.assign(new Error("Émetteur Access invalide."), { status: 403 });
  const audience = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audience.includes(String(env.ACCESS_AUD))) throw Object.assign(new Error("Audience Access invalide."), { status: 403 });
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== "number" || claims.exp <= now || (claims.nbf && claims.nbf > now + 60)) {
    throw Object.assign(new Error("Jeton Access expiré ou pas encore valide."), { status: 401 });
  }
  if (header.alg !== "RS256" || !header.kid) throw Object.assign(new Error("Algorithme de jeton non accepté."), { status: 401 });

  if (!cachedJwks || Date.now() - cachedJwksAt > 5 * 60 * 1000) {
    const response = await fetch(issuer + "/cdn-cgi/access/certs");
    if (!response.ok) throw Object.assign(new Error("Impossible de vérifier les clés Cloudflare Access."), { status: 503 });
    cachedJwks = await response.json();
    cachedJwksAt = Date.now();
  }
  const jwk = (cachedJwks.keys || []).find(key => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) throw Object.assign(new Error("Clé de signature Access inconnue."), { status: 401 });
  const publicKey = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", publicKey, decodeBase64Url(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1])
  );
  if (!valid) throw Object.assign(new Error("Signature Access invalide."), { status: 401 });

  const email = String(claims.email || "").trim().toLowerCase();
  const allowed = String(env.EDITOR_EMAILS).split(",").map(value => value.trim().toLowerCase()).filter(Boolean);
  if (!email || !allowed.includes(email)) throw Object.assign(new Error("Cet utilisateur n’est pas autorisé à modifier le catalogue."), { status: 403 });
  return { email };
}

function validateJsonValue(value, depth = 0) {
  if (depth > 5) throw new Error("Les champs personnalisés sont trop imbriqués.");
  if (typeof value === "string") {
    if (value.length > 4_000) throw new Error("Un champ texte dépasse 4 000 caractères.");
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Nombre invalide.");
    return;
  }
  if (typeof value === "boolean" || value === null) return;
  if (Array.isArray(value)) {
    if (value.length > 100) throw new Error("Une liste ne peut pas dépasser 100 éléments.");
    value.forEach(item => validateJsonValue(item, depth + 1));
    return;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length > 50) throw new Error("Un objet personnalisé ne peut pas dépasser 50 propriétés.");
    for (const [key, child] of entries) {
      if (!key || key.length > 80 || RESERVED_KEYS.has(key)) throw new Error("Nom de champ personnalisé invalide.");
      validateJsonValue(child, depth + 1);
    }
    return;
  }
  throw new Error("Type de champ non pris en charge.");
}

function validateTool(input, expectedId) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Fiche JSON invalide.");
  const tool = structuredClone(input);
  if (tool.toolId !== expectedId || !/^tool-[a-z0-9-]{1,80}$/.test(tool.toolId)) throw new Error("Identifiant technique invalide.");
  if (Object.keys(tool).length > 60) throw new Error("La fiche contient trop de champs.");
  for (const [key, value] of Object.entries(tool)) {
    if (RESERVED_KEYS.has(key) || RESERVED_TOOL_FIELDS.has(key) || key.length > 80) throw new Error("Nom de champ réservé ou invalide.");
    validateJsonValue(value);
  }
  const requiredStrings = [
    ["name", 120], ["type", 100], ["description", 2_000],
    ["linkLabel", 120], ["linkRel", 200]
  ];
  for (const [key, max] of requiredStrings) {
    if (typeof tool[key] !== "string" || !tool[key].trim() || tool[key].length > max) {
      throw new Error("Champ obligatoire invalide : " + key + ".");
    }
  }
  if (!CATEGORIES.has(tool.category)) throw new Error("Catégorie invalide.");
  if (typeof tool.url !== "string" || tool.url.length > 2_048) throw new Error("URL invalide ou trop longue.");
  let parsedUrl;
  try { parsedUrl = new URL(tool.url); } catch { throw new Error("L’URL doit être une adresse valide."); }
  if (!["http:", "https:"].includes(parsedUrl.protocol) || parsedUrl.username || parsedUrl.password) {
    throw new Error("Seules les URL http:// et https:// sans identifiants sont autorisées.");
  }
  if (!["_blank", "_self"].includes(tool.linkTarget)) throw new Error("Cible de lien invalide.");
  if (!Number.isInteger(tool.sortOrder) || tool.sortOrder < 1 || tool.sortOrder > 10_000) {
    throw new Error("Ordre d’affichage invalide.");
  }
  if (new TextEncoder().encode(JSON.stringify(tool)).length > MAX_BODY_BYTES) throw new Error("Fiche trop volumineuse.");
  return tool;
}

async function readAllTools(bucket) {
  const tools = [];
  let cursor;
  do {
    const page = await bucket.list({ prefix: "tools/", cursor });
    for (const item of page.objects || []) {
      const object = await bucket.get(item.key);
      if (!object) continue;
      const tool = await object.json();
      const comments = [];
      let commentCursor;
      do {
        const commentPage = await bucket.list({ prefix: "comments/" + tool.toolId + "/", cursor: commentCursor });
        for (const commentItem of commentPage.objects || []) {
          const commentObject = await bucket.get(commentItem.key);
          if (commentObject) comments.push(await commentObject.json());
        }
        commentCursor = commentPage.truncated ? commentPage.cursor : undefined;
      } while (commentCursor);
      comments.sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)));
      tools.push({ ...tool, _version: object.etag, comments });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  tools.sort((a, b) => a.sortOrder - b.sortOrder);
  return tools;
}

async function requireEditor(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin || origin !== new URL(request.url).origin) {
    throw Object.assign(new Error("Origine de requête non autorisée."), { status: 403 });
  }
  return accessClaims(request, env);
}

async function readBody(request) {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) throw Object.assign(new Error("Requête trop volumineuse."), { status: 413 });
  try { return JSON.parse(text); } catch { throw Object.assign(new Error("JSON invalide."), { status: 400 }); }
}

async function initialize(request, env) {
  const editor = await requireEditor(request, env);
  const bucket = env.TOOLS_R2;
  if (!bucket) return json({ error: "Binding R2 TOOLS_R2 manquant." }, 503);
  const markerKey = "meta/catalog-initialized.json";
  if (await bucket.head(markerKey)) return json({ error: "Le catalogue a déjà été initialisé. Aucune fiche n’a été remplacée." }, 409);

  const body = await readBody(request);
  if (!body || !Array.isArray(body.tools) || body.tools.length < 1 || body.tools.length > 100) {
    return json({ error: "La liste initiale doit contenir de 1 à 100 fiches." }, 400);
  }
  const validated = [];
  const ids = new Set();
  try {
    for (const input of body.tools) {
      const tool = validateTool(input, input.toolId);
      if (ids.has(tool.toolId)) throw new Error("Identifiant outilId en double.");
      ids.add(tool.toolId);
      validated.push(tool);
    }
  } catch (error) {
    return json({ error: error.message }, 400);
  }

  let created = 0, skipped = 0;
  try {
    for (const tool of validated) {
      const key = "tools/" + tool.toolId + ".json";
      const result = await bucket.put(key, JSON.stringify(tool), {
        httpMetadata: { contentType: "application/json; charset=utf-8" },
        onlyIf: { etagDoesNotMatch: "*" }
      });
      if (result) created++; else skipped++;
    }
    const marker = await bucket.put(markerKey, JSON.stringify({
      initializedAt: new Date().toISOString(), count: validated.length, toolIds: [...ids], initializedBy: editor.email
    }), {
      httpMetadata: { contentType: "application/json; charset=utf-8" },
      onlyIf: { etagDoesNotMatch: "*" }
    });
    if (!marker) return json({ error: "Initialisation déjà effectuée par une autre requête.", created, skipped }, 409);
  } catch {
    return json({ error: "Initialisation interrompue. Relancez-la : les fiches déjà créées ne seront pas écrasées.", created, skipped }, 503);
  }
  return json({ initialized: true, created, skipped });
}

async function updateTool(request, env, toolId) {
  const editor = await requireEditor(request, env);
  const bucket = env.TOOLS_R2;
  if (!bucket) return json({ error: "Binding R2 TOOLS_R2 manquant." }, 503);
  if (!/^tool-[a-z0-9-]{1,80}$/.test(toolId)) return json({ error: "outilId invalide." }, 400);
  const key = "tools/" + toolId + ".json";
  const current = await bucket.get(key);
  if (!current) return json({ error: "Fiche inconnue. Initialisez d’abord le catalogue." }, 404);
  const expected = request.headers.get("If-Match");
  if (!expected) return json({ error: "En-tête If-Match requis." }, 428);
  if (expected !== current.etag) return json({ error: "Conflit : cette fiche a été modifiée depuis son chargement. Rechargez-la avant de réessayer." }, 409);

  const body = await readBody(request);
  let tool;
  try { tool = validateTool(body, toolId); } catch (error) { return json({ error: error.message }, 400); }
  const result = await bucket.put(key, JSON.stringify(tool), {
    httpMetadata: { contentType: "application/json; charset=utf-8" },
    onlyIf: { etagMatches: current.etag }
  });
  if (!result) return json({ error: "Conflit : une autre modification vient d’être enregistrée. Rechargez la fiche." }, 409);
  return json({ tool: { ...tool, _version: result.etag }, updatedBy: editor.email });
}

async function addComment(request, env, toolId) {
  const editor = await requireEditor(request, env);
  const bucket = env.TOOLS_R2;
  if (!bucket) return json({ error: "Binding R2 TOOLS_R2 manquant." }, 503);
  if (!/^tool-[a-z0-9-]{1,80}$/.test(toolId)) return json({ error: "outilId invalide." }, 400);
  if (!await bucket.head("tools/" + toolId + ".json")) return json({ error: "Outil inconnu." }, 404);
  const body = await readBody(request);
  const text = typeof body?.text === "string" ? body.text.trim() : "";
  if (!text || text.length > MAX_COMMENT_LENGTH) return json({ error: "Le commentaire doit contenir de 1 à 2 000 caractères." }, 400);

  const comment = {
    commentId: crypto.randomUUID(),
    toolId,
    text,
    author: "Équipe Codex Prime",
    createdAt: new Date().toISOString()
  };
  await bucket.put("comments/" + toolId + "/" + comment.commentId + ".json", JSON.stringify(comment), {
    httpMetadata: { contentType: "application/json; charset=utf-8" },
    onlyIf: { etagDoesNotMatch: "*" }
  });
  return json({ comment }, 201);
}

async function route({ request, env }) {
  const url = new URL(request.url);
  if (url.pathname === "/api/catalog" && request.method === "GET") {
    if (!env.TOOLS_R2) return json({ error: "Binding R2 TOOLS_R2 manquant.", initialized: false, tools: [], writeProtectionConfigured: configured(env) }, 503);
    const tools = await readAllTools(env.TOOLS_R2);
    const initialized = Boolean(await env.TOOLS_R2.head("meta/catalog-initialized.json"));
    return json({ initialized, tools, writeProtectionConfigured: configured(env) });
  }
  if (url.pathname === "/api/admin/initialize" && request.method === "POST") return initialize(request, env);

  const commentMatch = url.pathname.match(/^\/api\/tools\/(tool-[a-z0-9-]{1,80})\/comments$/);
  if (commentMatch && request.method === "POST") return addComment(request, env, commentMatch[1]);

  const toolMatch = url.pathname.match(/^\/api\/tools\/(tool-[a-z0-9-]{1,80})$/);
  if (toolMatch && request.method === "PUT") return updateTool(request, env, toolMatch[1]);

  return json({ error: "Route API inconnue." }, 404);
}

export async function onRequest(context) {
  try {
    return await route(context);
  } catch (error) {
    return json({ error: error?.message || "Erreur interne." }, error?.status || 500);
  }
}

export default { onRequest };
