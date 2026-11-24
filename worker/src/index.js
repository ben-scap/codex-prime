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
    // Routes françaises demandées pour le catalogue public.
    const frenchCommentsMatch = path.match(/^\/api\/outils\/([a-zA-Z0-9_-]{1,100})\/commentaires$/);
    const frenchToolMatch = path.match(/^\/api\/outils\/([a-zA-Z0-9_-]{1,100})$/);
    if (request.method === "GET" && frenchCommentsMatch) {
      const tool = await getTool((env.DATA || env.OUTILS_BUCKET), frenchCommentsMatch[1]);
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
      const existingComments = await listAll((env.DATA || env.OUTILS_BUCKET), COMMENT_PREFIX + id + "/");
      if (existingComments.length >= MAX_COMMENTS) return json({ error: "Nombre maximal de commentaires atteint." }, 429, origin, env);
      const commentId = crypto.randomUUID();
      const comment = { commentId, toolId: id, text: body.text.trim(), createdAt: new Date().toISOString() };
      await (env.DATA || env.OUTILS_BUCKET).put(COMMENT_PREFIX + id + "/" + commentId + ".json", JSON.stringify(comment), { httpMetadata: { contentType: "application/json; charset=utf-8" } });
      return json({ ok: true, comment }, 201, origin, env);
    }
    return json({ error: "Route introuvable." }, 404, origin, env);
  }
};
