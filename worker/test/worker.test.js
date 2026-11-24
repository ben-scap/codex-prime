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
    exp: Math.floor(Date.now() / 1000) + 300
  }));
  const input = header + "." + payload;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, encoder.encode(input));
  return input + "." + Buffer.from(signature).toString("base64url");
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
let token;
const env = {
  OUTILS_BUCKET: bucket,
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
    assert.ok(await bucket.get("comments/tool-a-uuid/" + (await response.clone().json()).comment.commentId + ".json"));
    response = await call("GET", "/api/outils/tool-a-uuid/commentaires", undefined, false);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).commentaires.length, 1);

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
    assert.equal(savedA.comments.length, 1);
    assert.equal(savedB.comments.length, 0);
    assert.equal(savedB.description, "Description B");
    assert.equal(bucket.items.has("comments/tool-a-uuid/" + savedA.comments[0].commentId + ".json"), true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
