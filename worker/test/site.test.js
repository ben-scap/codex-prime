import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("la page conserve les 43 outils, leurs champs et les actions de fiche/commentaire", async () => {
  const html = await readFile(new URL("../../outils.html", import.meta.url), "utf8");
  const cards = [...html.matchAll(/<article class="card" data-category="([^"]+)" data-tool-id="([^"]+)">([\s\S]*?)<\/article>/g)];
  assert.equal(cards.length, 43);
  const ids = cards.map(card => card[2]);
  assert.equal(new Set(ids).size, 43, "les toolId doivent être uniques");
  for (const [, category, id, body] of cards) {
    assert.match(id, /^[0-9a-f-]{36}$/i);
    assert.match(category, /^(app|code|context|quality|delivery|ops)$/);
    assert.match(body, /<h3>/);
    assert.match(body, /class="type"/);
    assert.match(body, /<p>/);
    assert.match(body, /<a href="https?:/);
    assert.match(body, /class="tool-action edit-tool"/);
    assert.match(body, /class="tool-action add-comment"/);
  }
  assert.match(html, /textContent/);
  assert.doesNotMatch(html, /innerHTML/);
  assert.match(html, /const API_BASE_URL = "https:\/\/codex-prime-api\.toupe-benoit\.workers\.dev"/);
  assert.ok(html.includes("list: () => '/api/outils'"));
  assert.ok(html.includes("edit: id => '/api/outils/'+encodeURIComponent(id)"));
  assert.ok(html.includes("comments: id => '/api/outils/'+encodeURIComponent(id)+'/commentaires'"));
  assert.ok(html.includes('enableButtons(true)'));
  assert.ok(html.includes('commentSubmit.disabled=!adminEnabled'));
});
