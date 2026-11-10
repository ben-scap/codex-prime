import test, { before, after } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { onRequest } from "../functions/api/[[path]].js";

const cryptoApi = webcrypto;
let keyPair;
let publicJwk;
const originalFetch = globalThis.fetch;

function base64url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function makeToken(email = "editor@example.com") {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "unit-test-key" })));
  const payload = base64url(Buffer.from(JSON.stringify({
    iss: "https://team.cloudflareaccess.com",
    aud: ["codex-prime-access-audience"],
    sub: "test-subject",
    email,
    iat: now,
    nbf: now - 5,
    exp: now + 3600
  })));
  const signingInput = header + "." + payload;
  const signature = await cryptoApi.subtle.sign(
    "RSASSA-PKCS1-v1_5", keyPair.privateKey, Buffer.from(signingInput)
  );
  return signingInput + "." + base64url(new Uint8Array(signature));
}

class MemoryR2 {
  constructor() { this.objects = new Map(); this.counter = 0; }
  async head(key) {
    const item = this.objects.get(key);
    return item ? { etag: item.etag, key } : null;
  }
  async get(key) {
    const item = this.objects.get(key);
    if (!item) return null;
    return {
      key, etag: item.etag,
      async text() { return item.body; },
      async json() { return JSON.parse(item.body); }
    };
  }
  async put(key, value, options = {}) {
    const current = this.objects.get(key);
    const condition = options.onlyIf || {};
    if (condition.etagDoesNotMatch === "*" && current) return null;
    if (condition.etagMatches && (!current || current.etag !== condition.etagMatches)) return null;
    const etag = "test-etag-" + (++this.counter);
    this.objects.set(key, { body: typeof value === "string" ? value : await new Response(value).text(), etag });
    return { etag };
  }
  async list({ prefix = "", cursor } = {}) {
    const keys = [...this.objects.keys()].filter(key => key.startsWith(prefix)).sort();
    const start = cursor ? Number(cursor) : 0;
    const slice = keys.slice(start, start + 1000);
    const next = start + slice.length;
    return {
      objects: slice.map(key => ({ key })),
      truncated: next < keys.length,
      cursor: next < keys.length ? String(next) : undefined
    };
  }
}

const bucket = new MemoryR2();
const env = {
  TOOLS_R2: bucket,
  ACCESS_ENABLED: "true",
  ACCESS_TEAM_DOMAIN: "team.cloudflareaccess.com",
  ACCESS_AUD: "codex-prime-access-audience",
  EDITOR_EMAILS: "editor@example.com"
};

before(async () => {
  keyPair = await cryptoApi.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  }, true, ["sign", "verify"]);
  publicJwk = await cryptoApi.subtle.exportKey("jwk", keyPair.publicKey);
  publicJwk.kid = "unit-test-key";
  publicJwk.alg = "RS256";
  globalThis.fetch = async url => {
    if (String(url).endsWith("/cdn-cgi/access/certs")) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        headers: { "Content-Type": "application/json" }
      });
    }
    return originalFetch(url);
  };
});

after(() => { globalThis.fetch = originalFetch; });

async function call(method, path, body, extraHeaders = {}, currentEnv = env) {
  const headers = new Headers({ Origin: "https://site.test", ...extraHeaders });
  if (body !== undefined) headers.set("Content-Type", "application/json");
  const request = new Request("https://site.test" + path, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body)
  });
  const response = await onRequest({ request, env: currentEnv });
  const data = await response.json();
  return { response, data };
}

async function editorHeaders(extra = {}) {
  return { "Cf-Access-Jwt-Assertion": await makeToken(), ...extra };
}

const initialA = {
  toolId: "tool-alpha",
  name: "Alpha",
  type: "Web",
  description: "Description initiale",
  category: "app",
  url: "https://alpha.example/",
  linkLabel: "Site officiel",
  linkTarget: "_blank",
  linkRel: "noopener noreferrer",
  sortOrder: 1
};
const initialB = {
  ...initialA,
  toolId: "tool-beta",
  name: "Beta",
  url: "https://beta.example/",
  sortOrder: 2
};

test("initialise une seule fois et ne remplace jamais une fiche existante", async () => {
  const headers = await editorHeaders();
  const first = await call("POST", "/api/admin/initialize", { tools: [initialA, initialB] }, headers);
  assert.equal(first.response.status, 200);
  assert.equal(first.data.created, 2);

  const changed = { ...initialA, name: "Alpha déjà modifié" };
  const second = await call("POST", "/api/admin/initialize", { tools: [changed, initialB] }, headers);
  assert.equal(second.response.status, 409);

  const loaded = await call("GET", "/api/catalog");
  assert.equal(loaded.response.status, 200);
  assert.equal(loaded.data.initialized, true);
  assert.equal(loaded.data.tools.find(tool => tool.toolId === "tool-alpha").name, "Alpha");
});

test("modifie chaque champ, conserve les types et retrouve la fiche après rechargement", async () => {
  const loaded = await call("GET", "/api/catalog");
  const original = loaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  const changed = {
    ...initialA,
    name: "Alpha renommé",
    type: "Desktop",
    description: "Nouvelle description",
    category: "code",
    url: "https://new-alpha.example/path",
    linkLabel: "Documentation",
    linkTarget: "_self",
    linkRel: "noopener",
    sortOrder: 17,
    enabled: false,
    verifiedAt: "2026-11-10",
    tags: ["agent", "test"],
    metadata: { source: "manual", rank: 2 }
  };
  const saved = await call("PUT", "/api/tools/tool-alpha", changed, await editorHeaders({ "If-Match": original._version }));
  assert.equal(saved.response.status, 200);

  const reloaded = await call("GET", "/api/catalog");
  const record = reloaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  for (const key of Object.keys(changed)) assert.deepEqual(record[key], changed[key], "champ " + key);
  assert.equal(typeof record.enabled, "boolean");
  assert.ok(Array.isArray(record.tags));
  assert.equal(typeof record.metadata, "object");
  assert.equal(record.verifiedAt, "2026-11-10");
});

test("un commentaire sur A reste séparé de B et survit au changement d’URL de A", async () => {
  let loaded = await call("GET", "/api/catalog");
  let alpha = loaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  const comment = await call("POST", "/api/tools/tool-alpha/comments", {
    text: "Commentaire lié à Alpha"
  }, await editorHeaders());
  assert.equal(comment.response.status, 201);

  loaded = await call("GET", "/api/catalog");
  alpha = loaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  const renamedUrl = { ...alpha };
  delete renamedUrl._version;
  delete renamedUrl.comments;
  renamedUrl.url = "https://alpha-new.example/";
  const update = await call("PUT", "/api/tools/tool-alpha", renamedUrl, await editorHeaders({ "If-Match": alpha._version }));
  assert.equal(update.response.status, 200);

  const after = await call("GET", "/api/catalog");
  const a = after.data.tools.find(tool => tool.toolId === "tool-alpha");
  const b = after.data.tools.find(tool => tool.toolId === "tool-beta");
  assert.equal(a.url, "https://alpha-new.example/");
  assert.equal(a.comments.length, 1);
  assert.equal(a.comments[0].text, "Commentaire lié à Alpha");
  assert.equal(b.comments.length, 0);
});

test("refuse une URL invalide et un commentaire vide ou trop long", async () => {
  const loaded = await call("GET", "/api/catalog");
  const alpha = loaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  const bad = { ...initialA, url: "javascript:alert(1)" };
  const invalidUrl = await call("PUT", "/api/tools/tool-alpha", bad, await editorHeaders({ "If-Match": alpha._version }));
  assert.equal(invalidUrl.response.status, 400);

  const emptyComment = await call("POST", "/api/tools/tool-alpha/comments", { text: "   " }, await editorHeaders());
  assert.equal(emptyComment.response.status, 400);
  const longComment = await call("POST", "/api/tools/tool-alpha/comments", { text: "x".repeat(2001) }, await editorHeaders());
  assert.equal(longComment.response.status, 400);
});

test("refuse un accès non autorisé et une adresse non inscrite dans la liste", async () => {
  const unauthenticated = await call("POST", "/api/tools/tool-alpha/comments", { text: "intrusion" });
  assert.equal(unauthenticated.response.status, 401);

  const forbidden = await call("POST", "/api/tools/tool-alpha/comments", { text: "intrusion" }, {
    "Cf-Access-Jwt-Assertion": await makeToken("intrus@example.com")
  });
  assert.equal(forbidden.response.status, 403);
});

test("signale un conflit de versions au lieu d’écraser une modification récente", async () => {
  const loaded = await call("GET", "/api/catalog");
  const alpha = loaded.data.tools.find(tool => tool.toolId === "tool-alpha");
  const version = alpha._version;
  const updateOne = await call("PUT", "/api/tools/tool-alpha", {
    ...initialA, name: "Édition numéro un"
  }, await editorHeaders({ "If-Match": version }));
  assert.equal(updateOne.response.status, 200);

  const updateTwo = await call("PUT", "/api/tools/tool-alpha", {
    ...initialA, name: "Édition obsolète"
  }, await editorHeaders({ "If-Match": version }));
  assert.equal(updateTwo.response.status, 409);
  const final = await call("GET", "/api/catalog");
  assert.equal(final.data.tools.find(tool => tool.toolId === "tool-alpha").name, "Édition numéro un");
});

test("refuse les écritures si la configuration Access n’est pas présente", async () => {
  const unconfigured = { TOOLS_R2: bucket };
  const response = await call("POST", "/api/tools/tool-alpha/comments", { text: "bloqué" }, {}, unconfigured);
  assert.equal(response.response.status, 503);
});
