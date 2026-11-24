import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.js";

const encoder = new TextEncoder();
const b64 = value => Buffer.from(value).toString("base64url");
let privateKey, publicJwk;
const team = "codex-prime-test.cloudflareaccess.com";
const audience = "test-access-audience";

async function makeToken() {
  const header = b64(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" }));
  const payload = b64(JSON.stringify({
    iss: "https://" + team, aud: [audience],
    exp: Math.floor(Date.now() / 1000) + 300,
    email: "test@example.com"
  }));
  const input = header + "." + payload;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, encoder.encode(input));
  return input + "." + Buffer.from(signature).toString("base64url");
}

class MemoryD1 {
  constructor() { this.rows = []; this.relationalRows = []; this.fiches = new Set(["tool-a-uuid", "tool-b-uuid"]); this.nextCommentId = 1; }
  prepare(sql) {
    const db = this;
    return { bind(...values) {
      return {
        async first() {
          if (sql.includes("FROM fiches")) return db.fiches.has(values[0]) ? { id: values[0] } : null;
          return null;
        },
        async all() {
          if (sql.includes("FROM commentaires WHERE fiche_id = ?")) {
            let rows = db.relationalRows.filter(row => row.fiche_id === values[0]);
            if (sql.includes("created_at < ?")) {
              const [, createdAt, , id] = values;
              rows = rows.filter(row => row.created_at < createdAt || (row.created_at === createdAt && row.id < Number(id)));
            }
            rows.sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id - a.id);
            return { results: rows.slice(0, values[values.length - 1]) };
          }
          let rows = db.rows.filter(row => row.outil_id === values[0]);
          if (sql.includes("cree_le < ?")) {
            const [, createdAt, , id] = values;
            rows = rows.filter(row => row.cree_le < createdAt || (row.cree_le === createdAt && row.id < id));
          }
          rows.sort((a, b) => b.cree_le.localeCompare(a.cree_le) || b.id.localeCompare(a.id));
          return { results: rows.slice(0, values[values.length - 1]) };
        },
        async run() {
          if (sql.startsWith("INSERT INTO commentaires (")) {
            const [fiche_id, auteur_email, texte, created_at] = values;
            const id = db.nextCommentId++;
            db.relationalRows.push({ id, fiche_id, auteur_email, texte, created_at });
            return { meta: { changes: 1, last_row_id: id } };
          }
          if (sql.startsWith("INSERT")) {
            const [id, outil_id, texte, auteur, cree_le] = values;
            if (db.rows.some(row => row.id === id)) return { meta: { changes: 0 } };
            db.rows.push({ id, outil_id, texte, auteur, cree_le });
            return { meta: { changes: 1 } };
          }
          if (sql.startsWith("DELETE")) {
            const before = db.rows.length;
            db.rows = db.rows.filter(row => row.cree_le >= values[0]);
            return { meta: { changes: before - db.rows.length } };
          }
          return { meta: { changes: 0 } };
        }
      };
    }};
  }
}

class MemoryR2 {
  constructor() { this.items = new Map(); this.serial = 0; }
  async get(key) {
    const item = this.items.get(key);
    if (!item) return null;
    return { etag: item.etag, body: item.value, json: async () => JSON.parse(item.value) };
  }
  async put(key, value, options = {}) {
    const current = this.items.get(key);
    if (options.onlyIf?.etagMatches && current?.etag !== options.onlyIf.etagMatches) return null;
    if (options.onlyIf?.etagDoesNotMatch === "*" && current) return null;
    const etag = "etag-" + (++this.serial);
    this.items.set(key, { value: String(value), etag });
    return { etag };
  }
  async list({ prefix = "" } = {}) {
    return { objects: [...this.items.keys()].filter(key => key.startsWith(prefix)).map(key => ({ key })), truncated: false };
  }
}

const bucket = new MemoryR2();
const db = new MemoryD1();
let token;
const env = {
  OUTILS_BUCKET: bucket,
  DB: db,
  ALLOWED_ORIGIN: "https://ben-scap.github.io",
  ACCESS_TEAM_DOMAIN: team,
  ACCESS_AUD: audience,
  ACCESS_APP_CONFIGURED: "true"
};
const A = {
  toolId: "tool-a-uuid", name: "Outil A", category: "app", type: "Web",
  description: "Description A", link_url: "https://a.example/", link_label: "A officiel",
  custom_fields: {}
};
const B = {
  toolId: "tool-b-uuid", name: "Outil B", category: "code", type: "CLI",
  description: "Description B", link_url: "http://b.example/", link_label: "B officiel",
  custom_fields: {}
};
async function call(method, path, body, authenticated = true) {
  const headers = { Origin: "https://ben-scap.github.io" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (authenticated && token) headers["Cf-Access-Jwt-Assertion"] = token;
  return worker.fetch(new Request("https://codex-prime-api.example.workers.dev" + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body)
  }), env);
}

test("la navigation de connexion Access fonctionne sans Origin ni JWT, sans redirection externe", async () => {
  const loginEnv = { ALLOWED_ORIGIN: "https://ben-scap.github.io,https://codex-prime-852.pages.dev" };

  let response = await worker.fetch(new Request(
    "https://codex-prime-api.example.workers.dev/api/admin/login?return=" +
    encodeURIComponent("https://ben-scap.github.io/outils.html?admin=1#edition")
  ), loginEnv);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://ben-scap.github.io/outils.html?admin=1#edition");

  response = await worker.fetch(new Request(
    "https://codex-prime-api.example.workers.dev/api/admin/login?return=" +
    encodeURIComponent("https://evil.example/phishing")
  ), loginEnv);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("location"), "https://ben-scap.github.io/");
});

test("R2 fiches individuelles, initialisation non destructive, commentaires isolés et contrôle de version", async () => {
  const keys = await crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1,0,1]), hash: "SHA-256"
  }, true, ["sign", "verify"]);
  privateKey = keys.privateKey;
  publicJwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  publicJwk.kid = "test-key";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ keys: [publicJwk] }), {
    status: 200, headers: { "content-type": "application/json" }
  });
  try {
    token = await makeToken();

    let response = await call("POST", "/api/admin/initialize", { tools: [A, B] });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, created: 2, skipped: 0 });

    const changedSeed = { ...A, description: "NE DOIT PAS REMPLACER" };
    response = await call("POST", "/api/admin/initialize", { tools: [changedSeed, B] });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true, created: 0, skipped: 2 });

    let stored = await bucket.get("tools/tool-a-uuid.json");
    assert.equal((await stored.json()).description, "Description A");
    assert.ok(await bucket.get("tools/tool-b-uuid.json"));

    const updatedA = {
      ...A, name: "A modifié", category: "quality", type: "MCP",
      description: "Description modifiée", link_url: "http://a-new.example/path",
      link_label: "Nouveau lien",
      custom_fields: { active: true, releaseDate: "2026-11-23", tags: ["ia", "code"], score: 4 }
    };
    response = await call("PUT", "/api/outils/tool-a-uuid", { expectedVersion: 1, tool: updatedA });
    assert.equal(response.status, 200);
    let result = await response.json();
    assert.equal(result.tool.version, 2);
    assert.deepEqual(result.tool.custom_fields, updatedA.custom_fields);

    response = await call("POST", "/api/outils/tool-a-uuid/commentaires", { text: "Commentaire propre à A" });
    assert.equal(response.status, 201);
    const createdComment = (await response.clone().json()).comment;
    assert.equal(db.rows.length, 1);
    assert.equal(db.rows[0].texte, "Commentaire propre à A");
    assert.equal(await bucket.get("comments/tool-a-uuid/" + createdComment.commentId + ".json"), null);
    // The relational D1 endpoint stores and reads comments through fiches.id.
    response = await call("POST", "/api/commentaires", {
      ficheId: "tool-a-uuid", texte: "Commentaire relationnel"
    });
    assert.equal(response.status, 201);
    const relationalCreated = await response.json();
    assert.equal(relationalCreated.commentaire.ficheId, "tool-a-uuid");
    assert.equal(db.relationalRows.length, 1);
    response = await call("GET", "/api/fiches/tool-a-uuid/commentaires", undefined, false);
    assert.equal(response.status, 200);
    const relationalPage = await response.json();
    assert.equal(relationalPage.commentaires.length, 1);
    assert.equal(relationalPage.commentaires[0].text, "Commentaire relationnel");
    assert.equal(relationalPage.commentaires[0].author, "test@example.com");

    response = await call("GET", "/api/outils/tool-a-uuid/commentaires", undefined, false);
    assert.equal(response.status, 200);
    const commentPage = await response.json();
    assert.equal(commentPage.commentaires.length, 1);
    assert.equal(commentPage.commentaires[0].text, "Commentaire propre à A");
    assert.equal(commentPage.pagination.hasMore, false);

    for (let i = 0; i < 21; i++) {
      db.rows.push({
        id: "seed-" + String(i).padStart(2, "0"), outil_id: "tool-a-uuid",
        texte: "Commentaire " + i, auteur: "Test",
        cree_le: new Date(Date.UTC(2025, 0, 1, 0, i, 0)).toISOString()
      });
    }
    response = await call("GET", "/api/outils/tool-a-uuid/commentaires", undefined, false);
    const firstPage = await response.json();
    assert.equal(firstPage.commentaires.length, 20);
    assert.equal(firstPage.pagination.hasMore, true);
    response = await call("GET", "/api/outils/tool-a-uuid/commentaires?cursor=" + encodeURIComponent(firstPage.pagination.nextCursor), undefined, false);
    const secondPage = await response.json();
    assert.equal(secondPage.commentaires.length, 2);
    assert.equal(secondPage.pagination.hasMore, false);

    response = await call("PUT", "/api/outils/tool-a-uuid", {
      expectedVersion: 2, tool: { ...updatedA, link_url: "https://a-final.example/" }
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).tool.version, 3);

    response = await call("PUT", "/api/outils/tool-a-uuid", {
      expectedVersion: 3, tool: { ...updatedA, link_url: "javascript:alert(1)" }
    });
    assert.equal(response.status, 422);

    response = await call("PUT", "/api/outils/tool-a-uuid", {
      expectedVersion: 1, tool: updatedA
    });
    assert.equal(response.status, 409);

    const noAuth = await worker.fetch(new Request("https://codex-prime-api.example.workers.dev/api/admin/tools/tool-a-uuid", {
      method: "PUT", headers: { Origin: "https://ben-scap.github.io", "content-type": "application/json" },
      body: JSON.stringify({ expectedVersion: 3, tool: updatedA })
    }), env);
    assert.equal(noAuth.status, 401);

    response = await call("GET", "/api/outils", undefined, false);
    assert.equal(response.status, 200);
    const catalog = await response.json();
    const savedA = catalog.tools.find(item => item.toolId === "tool-a-uuid");
    const savedB = catalog.tools.find(item => item.toolId === "tool-b-uuid");
    assert.equal(savedA.link_url, "https://a-final.example/");
    assert.equal("comments" in savedB, false);
    assert.equal(savedB.description, "Description B");
    assert.equal(db.rows.length, 22);

    // Import legacy R2 comments is preview-only until an explicit "apply" request.
    const legacyKey = "comments/tool-a-uuid/legacy-001.json";
    const legacyValue = {
      commentId: "legacy-001", toolId: "tool-a-uuid", text: "Ancien commentaire R2",
      author: "Ancien auteur", createdAt: "2024-10-01T10:00:00.000Z"
    };
    await bucket.put(legacyKey, JSON.stringify(legacyValue));
    response = await call("POST", "/api/admin/import-r2-comments", { mode: "preview" });
    assert.equal(response.status, 200);
    const preview = await response.json();
    assert.equal(preview.mode, "preview");
    assert.equal(preview.valid, 1);
    assert.equal(preview.imported, 0);
    assert.equal(preview.r2ObjectsDeleted, 0);
    assert.ok(await bucket.get(legacyKey));
    assert.equal(db.rows.some(row => row.id === "legacy-001"), false);

    response = await call("POST", "/api/admin/import-r2-comments", { mode: "apply" });
    assert.equal(response.status, 200);
    const imported = await response.json();
    assert.equal(imported.imported, 1);
    assert.equal(imported.alreadyPresent, 0);
    assert.equal(imported.r2ObjectsDeleted, 0);
    assert.ok(await bucket.get(legacyKey));
    response = await call("POST", "/api/admin/import-r2-comments", { mode: "apply" });
    assert.equal(response.status, 200);
    const repeated = await response.json();
    assert.equal(repeated.imported, 0);
    assert.equal(repeated.alreadyPresent, 1);
    assert.ok(await bucket.get(legacyKey));

    // Daily retention removes rows older than 12 months, without touching R2.
    await worker.scheduled({}, env, { waitUntil() {} });
    assert.equal(db.rows.some(row => row.id === "legacy-001"), false);
    assert.equal(db.rows.length, 1);
    assert.ok(await bucket.get(legacyKey));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
