const HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };
const MAX_BODY = 256 * 1024;
const MAX_TOOLS = 1000;
const ID_RE = /^[a-zA-Z0-9_-]{1,100}$/;
const TOOL_PREFIX = "tools/";

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
function accessEmail(request) {
  try {
    const token = request.headers.get("Cf-Access-Jwt-Assertion");
    const payload = decodePart(token.split(".")[1]);
    return typeof payload.email === "string" && payload.email.trim()
      ? payload.email.trim().slice(0, 120)
      : "Utilisateur";
  } catch { return "Utilisateur"; }
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
  return obj ? obj.json() : null;
}
function encodeCursor(value) {
  return JSON.stringify(value);
}
function decodeCursor(value) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    if (!parsed || typeof parsed.createdAt !== "string" || typeof parsed.id !== "string") return null;
    return parsed;
  } catch { return null; }
}
function commentView(row) {
  return {
    commentId: row.id, toolId: row.outil_id, text: row.texte,
    author: row.auteur, createdAt: row.cree_le,
    id: row.id, outil_id: row.outil_id, texte: row.texte, auteur: row.auteur, cree_le: row.cree_le
  };
}
async function listD1Comments(db, toolId, cursor) {
  const limit = 20;
  const statement = cursor
    ? db.prepare("SELECT id, outil_id, texte, auteur, cree_le FROM commentaires_legacy WHERE outil_id = ? AND (cree_le < ? OR (cree_le = ? AND id < ?)) ORDER BY cree_le DESC, id DESC LIMIT ?").bind(toolId, cursor.createdAt, cursor.createdAt, cursor.id, limit + 1)
    : db.prepare("SELECT id, outil_id, texte, auteur, cree_le FROM commentaires_legacy WHERE outil_id = ? ORDER BY cree_le DESC, id DESC LIMIT ?").bind(toolId, limit + 1);
  const result = await statement.all();
  const rows = result.results || [];
  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  return {
    commentaires: page.map(commentView),
    pagination: { limit, hasMore, nextCursor: hasMore && last ? encodeCursor({ createdAt: last.cree_le, id: last.id }) : null }
  };
}
async function listRelationalComments(db, ficheId, cursor) {
  const limit = 20;
  const statement = cursor
    ? db.prepare("SELECT id, fiche_id, auteur_email, texte, created_at FROM commentaires WHERE fiche_id = ? AND (created_at < ? OR (created_at = ? AND id < ?)) ORDER BY created_at DESC, id DESC LIMIT ?").bind(ficheId, cursor.createdAt, cursor.createdAt, cursor.id, limit + 1)
    : db.prepare("SELECT id, fiche_id, auteur_email, texte, created_at FROM commentaires WHERE fiche_id = ? ORDER BY created_at DESC, id DESC LIMIT ?").bind(ficheId, limit + 1);
  const result = await statement.all();
  const rows = result.results || [];
  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  return {
    commentaires: page.map(row => ({
      commentId: row.id, toolId: row.fiche_id, text: row.texte,
      author: row.auteur_email, createdAt: row.created_at
    })),
    pagination: { limit, hasMore, nextCursor: hasMore && last ? encodeCursor({ createdAt: last.created_at, id: String(last.id) }) : null }
  };
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
    const url = new URL(request.url);
    let path = url.pathname.replace(/\/+$/, "") || "/";

    // Cette route est protégée en amont par Cloudflare Access.
    // Elle doit être traitée avant le contrôle JWT du Worker pour établir la session.
    if (request.method === "GET" && path === "/api/admin/login") {
      const allowedOrigins = (env.ALLOWED_ORIGIN || "https://ben-scap.github.io").split(",").map(x => x.trim());
      let destination = allowedOrigins[0];
      try {
        const requested = new URL(url.searchParams.get("return") || destination);
        if (allowedOrigins.includes(requested.origin)) destination = requested.href;
      } catch {}
      return Response.redirect(destination, 302);
    }

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
    if (!(env.DATA || env.OUTILS_BUCKET)) return json({ error: "Liaison R2 DATA absente." }, 503, origin, env);
    // Catalogue D1 : lecture publique, filtrée et paginée.
    if (request.method === "GET" && path === "/api/fiches") {
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      const category = url.searchParams.get("categorie");
      const rawOffset = url.searchParams.get("offset") ?? "0";
      if (category !== null && (!category.trim() || category.length > 100)) {
        return json({ error: "Catégorie invalide." }, 400, origin, env);
      }
      if (!/^\d+$/.test(rawOffset) || !Number.isSafeInteger(Number(rawOffset)) || Number(rawOffset) > 1000000) {
        return json({ error: "Offset de pagination invalide." }, 400, origin, env);
      }
      const offset = Number(rawOffset);
      const limit = 20;
      const statement = category === null
        ? env.DB.prepare("SELECT id, slug, titre, description, categorie, auteur_email, version, updated_at FROM fiches ORDER BY updated_at DESC LIMIT ? OFFSET ?").bind(limit, offset)
        : env.DB.prepare("SELECT id, slug, titre, description, categorie, auteur_email, version, updated_at FROM fiches WHERE categorie = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?").bind(category.trim(), limit, offset);
      const result = await statement.all();
      return json({ fiches: result.results || [], pagination: { limit, offset, nextOffset: (result.results || []).length === limit ? offset + limit : null } }, 200, origin, env);
    }
    // Routes françaises demandées pour le catalogue public.
    const frenchCommentsMatch = path.match(/^\/api\/outils\/([a-zA-Z0-9_-]{1,100})\/commentaires$/);
    const frenchToolMatch = path.match(/^\/api\/outils\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "GET" && frenchCommentsMatch) {
      const tool = await getTool((env.DATA || env.OUTILS_BUCKET), frenchCommentsMatch[1]);
      if (!tool) return json({ error: "Fiche introuvable." }, 404, origin, env);
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      const cursor = decodeCursor(url.searchParams.get("cursor"));
      if (url.searchParams.has("cursor") && !cursor) return json({ error: "Curseur de pagination invalide." }, 400, origin, env);
      const result = await listD1Comments(env.DB, frenchCommentsMatch[1], cursor);
      return json(result, 200, origin, env);
    }
    if (request.method === "PUT" && frenchToolMatch) path = "/api/admin/tools/" + frenchToolMatch[1];
    if (request.method === "POST" && frenchCommentsMatch) path = "/api/admin/tools/" + frenchCommentsMatch[1] + "/comments";
    if (path === "/api/outils") path = "/api/tools";
    if (request.method === "GET" && frenchToolMatch) path = "/api/tools/" + frenchToolMatch[1];
    if (request.method === "POST" && path === "/api/commentaires") {
      const denied = await requireAdmin(request, env, origin);
      if (denied) return denied;
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      let body;
      try { body = await readJson(request); } catch (e) {
        return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env);
      }
      if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "Corps JSON invalide." }, 400, origin, env);
      const ficheId = typeof body.ficheId === "string" ? body.ficheId.trim() : "";
      const texte = typeof body.texte === "string" ? body.texte.trim() : "";
      if (!ficheId || ficheId.length > 100 || !ID_RE.test(ficheId) || !texte || texte.length > 5000) {
        return json({ error: "Les champs ficheId et texte sont obligatoires (texte : 5000 caractères maximum)." }, 400, origin, env);
      }
      const auteurEmail = accessEmail(request);
      if (!auteurEmail || auteurEmail === "Utilisateur") return json({ error: "Adresse e-mail de l'auteur indisponible dans la session Cloudflare Access." }, 401, origin, env);
      const fiche = await env.DB.prepare("SELECT id FROM fiches WHERE id = ? LIMIT 1").bind(ficheId).first();
      if (!fiche) return json({ error: "Fiche introuvable." }, 400, origin, env);
      const createdAt = new Date().toISOString();
      const result = await env.DB.prepare("INSERT INTO commentaires (fiche_id, auteur_email, texte, created_at) VALUES (?, ?, ?, ?)")
        .bind(ficheId, auteurEmail, texte, createdAt).run();
      return json({ ok: true, commentaire: { id: result.meta?.last_row_id ?? null, ficheId, auteurEmail, texte, createdAt } }, 201, origin, env);
    }
    if (request.method === "GET" && path === "/api/status") {
      return json({ adminEnabled: accessReady(env) }, 200, origin, env);
    }
    if (request.method === "GET" && path === "/api/tools") {
      const keys = await listAll((env.DATA || env.OUTILS_BUCKET), TOOL_PREFIX);
      const result = [];
      for (const item of keys) {
        const id = item.key.slice(TOOL_PREFIX.length).replace(/\.json$/, "");
        if (validId(id)) {
          const tool = await getTool((env.DATA || env.OUTILS_BUCKET), id);
          if (tool) result.push(tool);
        }
      }
      return json({ tools: result }, 200, origin, env);
    }
    const toolMatch = path.match(/^\/api\/tools\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "GET" && toolMatch) {
      const tool = await getTool((env.DATA || env.OUTILS_BUCKET), toolMatch[1]);
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
        const existing = await (env.DATA || env.OUTILS_BUCKET).get(key);
        if (existing) { skipped++; continue; }
        const inserted = await (env.DATA || env.OUTILS_BUCKET).put(key, JSON.stringify({ ...tool, version: 1, updatedAt: new Date().toISOString() }), {
          onlyIf: { etagDoesNotMatch: "*" },
          httpMetadata: { contentType: "application/json; charset=utf-8" }
        });
        if (inserted) created++; else skipped++;
      }
      return json({ ok: true, created, skipped }, 200, origin, env);
    }
    if (request.method === "POST" && path === "/api/admin/import-r2-fiches") {
      let body;
      try { body = await readJson(request); } catch (e) {
        return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env);
      }
      if (!body || !["preview", "apply"].includes(body.mode)) {
        return json({ error: "Mode attendu : preview ou apply." }, 422, origin, env);
      }
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      const bucket = env.DATA || env.OUTILS_BUCKET;
      const keys = await listAll(bucket, TOOL_PREFIX);
      let scanned = 0, valid = 0, invalid = 0, imported = 0, alreadyPresent = 0, slugConflicts = 0;
      for (const item of keys) {
        scanned++;
        try {
          const match = item.key.match(/^tools\/([a-zA-Z0-9_-]{1,100})\.json$/);
          if (!match) { invalid++; continue; }
          const id = match[1];
          const object = await bucket.get(item.key);
          if (!object) continue;
          const tool = await object.json();
          const titre = typeof tool.name === "string" ? tool.name.trim() : "";
          const description = typeof tool.description === "string" ? tool.description : "";
          const categorie = typeof tool.category === "string" ? tool.category : "";
          const version = Number.isSafeInteger(tool.version) && tool.version > 0 ? tool.version : 1;
          const updatedAt = typeof tool.updatedAt === "string" && Number.isFinite(Date.parse(tool.updatedAt))
            ? new Date(tool.updatedAt).toISOString()
            : new Date().toISOString();
          if (tool.toolId !== id || !titre || titre.length > 200 || description.length > 5000 ||
              !/^(app|code|context|quality|delivery|ops)$/.test(categorie)) {
            invalid++; continue;
          }
          valid++;
          const existing = await env.DB.prepare("SELECT id, slug FROM fiches WHERE id = ? OR slug = ? LIMIT 1")
            .bind(id, id).first();
          if (existing) {
            if (existing.id === id && existing.slug === id) alreadyPresent++;
            else slugConflicts++;
            continue;
          }
          if (body.mode === "preview") continue;
          const result = await env.DB.prepare(
            "INSERT OR IGNORE INTO fiches (id, slug, titre, description, categorie, auteur_email, version, updated_at) VALUES (?, ?, ?, ?, ?, NULL, ?, ?)"
          ).bind(id, id, titre, description, categorie, version, updatedAt).run();
          if (result.meta?.changes) imported++;
          else alreadyPresent++;
        } catch { invalid++; }
      }
      return json({
        ok: true, mode: body.mode, scanned, valid, invalid,
        imported, alreadyPresent, slugConflicts,
        r2ObjectsDeleted: 0,
        message: body.mode === "preview"
          ? "Aucune écriture effectuée. Les identifiants R2 seront conservés comme id et slug dans D1."
          : "Import terminé. Aucun objet R2 n'a été supprimé."
      }, 200, origin, env);
    }
    if (request.method === "POST" && path === "/api/admin/import-r2-comments") {
      let body;
      try { body = await readJson(request); } catch (e) {
        return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env);
      }
      if (!["preview", "apply"].includes(body.mode)) return json({ error: "Mode attendu : preview ou apply." }, 422, origin, env);
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      const bucket = env.DATA || env.OUTILS_BUCKET;
      const keys = await listAll(bucket, "comments/");
      let scanned = 0, valid = 0, invalid = 0, imported = 0, alreadyPresent = 0;
      for (const item of keys) {
        scanned++;
        try {
          const match = item.key.match(/^comments\/([a-zA-Z0-9_-]{1,100})\/([a-zA-Z0-9_-]{1,100})\.json$/);
          if (!match) { invalid++; continue; }
          const object = await bucket.get(item.key);
          if (!object) continue;
          const legacy = await object.json();
          const id = typeof legacy.commentId === "string" && ID_RE.test(legacy.commentId) ? legacy.commentId : match[2];
          const outilId = typeof legacy.toolId === "string" && validId(legacy.toolId) ? legacy.toolId : match[1];
          const texte = typeof legacy.text === "string" ? legacy.text.trim() : "";
          const auteur = typeof legacy.author === "string" && legacy.author.trim() ? legacy.author.trim().slice(0, 120) : "Utilisateur";
          const date = legacy.createdAt;
          if (!validId(id) || !validId(outilId) || !texte || texte.length > 5000 || typeof date !== "string" || !Number.isFinite(Date.parse(date))) {
            invalid++; continue;
          }
          valid++;
          if (body.mode === "preview") continue;
          const result = await env.DB.prepare("INSERT OR IGNORE INTO commentaires_legacy (id, outil_id, texte, auteur, cree_le) VALUES (?, ?, ?, ?, ?)")
            .bind(id, outilId, texte, auteur, new Date(date).toISOString()).run();
          if (result.meta?.changes) imported++; else alreadyPresent++;
        } catch { invalid++; }
      }
      return json({
        ok: true, mode: body.mode, scanned, valid, invalid,
        imported, alreadyPresent,
        r2ObjectsDeleted: 0,
        message: body.mode === "preview"
          ? "Aucune écriture effectuée. R2 reste intact."
          : "Import terminé. Aucun objet R2 n'a été supprimé."
      }, 200, origin, env);
    }
    const editMatch = path.match(/^\/api\/admin\/tools\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "PUT" && editMatch) {
      const id = editMatch[1];
      let body;
      try { body = await readJson(request); } catch (e) { return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env); }
      const key = TOOL_PREFIX + id + ".json";
      const currentObj = await (env.DATA || env.OUTILS_BUCKET).get(key);
      if (!currentObj) return json({ error: "Fiche absente. Initialisez le catalogue avant modification." }, 404, origin, env);
      const current = await currentObj.json();
      if (body.expectedVersion !== current.version) return json({ error: "CONFLICT", message: "Cette fiche a été modifiée depuis son ouverture. Rechargez-la avant de recommencer.", currentVersion: current.version }, 409, origin, env);
      const tool = body.tool;
      if (!validTool(tool, id)) return json({ error: "Fiche invalide : vérifiez les champs, les types et l'URL http/https." }, 422, origin, env);
      const updated = { ...tool, version: current.version + 1, updatedAt: new Date().toISOString() };
      const stored = await (env.DATA || env.OUTILS_BUCKET).put(key, JSON.stringify(updated), {
        onlyIf: { etagMatches: currentObj.etag },
        httpMetadata: { contentType: "application/json; charset=utf-8" }
      });
      if (!stored) return json({ error: "CONFLICT", message: "La fiche a changé pendant l'enregistrement. Rechargez-la." }, 409, origin, env);
      return json({ ok: true, tool: updated }, 200, origin, env);
    }
    const commentMatch = path.match(/^\/api\/admin\/tools\/([a-zA-Z0-9_-]{1,100})\/comments$/);
    if (request.method === "POST" && commentMatch) {
      const id = commentMatch[1];
      const toolObj = await (env.DATA || env.OUTILS_BUCKET).get(TOOL_PREFIX + id + ".json");
      if (!toolObj) return json({ error: "Fiche introuvable." }, 404, origin, env);
      let body;
      try { body = await readJson(request); } catch (e) { return json({ error: e.message === "BODY_TOO_LARGE" ? "Corps trop volumineux." : "JSON invalide." }, e.message === "BODY_TOO_LARGE" ? 413 : 400, origin, env); }
      if (typeof body.text !== "string" || !body.text.trim() || body.text.length > 5000) return json({ error: "Commentaire vide ou trop long (5000 caractères maximum)." }, 422, origin, env);
      if (!env.DB) return json({ error: "Liaison D1 DB absente." }, 503, origin, env);
      const auteur = accessEmail(request);
      const commentId = crypto.randomUUID();
      const creeLe = new Date().toISOString();
      await env.DB.prepare("INSERT INTO commentaires_legacy (id, outil_id, texte, auteur, cree_le) VALUES (?, ?, ?, ?, ?)")
        .bind(commentId, id, body.text.trim(), auteur, creeLe).run();
      const comment = { commentId, toolId: id, text: body.text.trim(), author: auteur, createdAt: creeLe };
      return json({ ok: true, comment }, 201, origin, env);
    }
    return json({ error: "Route introuvable." }, 404, origin, env);
  },
  async scheduled(event, env, ctx) {
    if (!env.DB) throw new Error("Liaison D1 DB absente.");
    const cutoff = new Date();
    cutoff.setUTCFullYear(cutoff.getUTCFullYear() - 1);
    const result = await env.DB.prepare("DELETE FROM commentaires_legacy WHERE cree_le < ?")
      .bind(cutoff.toISOString()).run();
    return result;
  }
};
