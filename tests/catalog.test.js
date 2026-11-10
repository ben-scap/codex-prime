import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("outils.html garde un rendu textuel sûr et les contrôles d’édition", async () => {
  const html = await readFile(new URL("../outils.html", import.meta.url), "utf8");
  assert.match(html, /data-tool-id=/);
  assert.match(html, /Modifier la fiche/);
  assert.match(html, /Ajouter un commentaire/);
  assert.match(html, /textContent/);
  assert.doesNotMatch(html, /\.innerHTML\s*=/);
  assert.match(html, /\/api\/tools/);
});

test("le catalogue statique conserve ses 43 fiches et ses six catégories", async () => {
  const html = await readFile(new URL("../outils.html", import.meta.url), "utf8");
  const cards = [...html.matchAll(/<article class="card" data-category="([^"]+)" data-tool-id="([^"]+)">/g)];
  assert.equal(cards.length, 43);
  assert.equal(new Set(cards.map(match => match[2])).size, 43);
  assert.deepEqual([...new Set(cards.map(match => match[1]))].sort(), ["app", "code", "context", "delivery", "ops", "quality"]);
});

test("le JavaScript intégré de la page est syntaxiquement valide", async () => {
  const html = await readFile(new URL("../outils.html", import.meta.url), "utf8");
  const start = html.lastIndexOf("<script>");
  const end = html.indexOf("</script>", start);
  assert.ok(start >= 0 && end > start);
  const script = html.slice(start + 8, end);
  assert.doesNotThrow(() => new Function(script));
});
