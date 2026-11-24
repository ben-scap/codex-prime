CREATE TABLE IF NOT EXISTS commentaires (
  id TEXT PRIMARY KEY NOT NULL,
  outil_id TEXT NOT NULL,
  texte TEXT NOT NULL,
  auteur TEXT NOT NULL,
  cree_le TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_commentaires_outil_cree_le
  ON commentaires (outil_id, cree_le);
