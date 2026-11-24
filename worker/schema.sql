-- Schéma cible de la base D1 de CODEX-PRIME.
-- Ce fichier décrit les tables et index ; il ne modifie pas à lui seul
-- une base D1 déjà déployée.

CREATE TABLE IF NOT EXISTS fiches (
  id TEXT PRIMARY KEY NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  titre TEXT NOT NULL,
  description TEXT,
  categorie TEXT,
  auteur_email TEXT,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS commentaires (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fiche_id TEXT NOT NULL,
  auteur_email TEXT,
  texte TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (fiche_id) REFERENCES fiches(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_fiches_categorie
  ON fiches (categorie);

CREATE INDEX IF NOT EXISTS idx_commentaires_fiche_id
  ON commentaires (fiche_id);
