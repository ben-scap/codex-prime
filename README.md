# Codex Prime

Site web statique prêt à être publié avec **GitHub Pages**.

## Contenu

- `index.html` — page d'accueil autonome, sans dépendance externe.
- `.nojekyll` — permet à GitHub Pages de servir directement les fichiers statiques.

## Publication avec GitHub Pages

1. Ouvrir **Settings → Pages** dans le dépôt.
2. Dans **Build and deployment**, choisir **Deploy from a branch**.
3. Sélectionner la branche `main` et le dossier `/(root)`.
4. Enregistrer.

Le site sera ensuite disponible à l'adresse :

`https://ben-scap.github.io/codex-prime/`

## Développement local

Ouvrir simplement `index.html` dans un navigateur, ou lancer un serveur statique local :

```bash
python -m http.server 8000
```

Puis ouvrir `http://localhost:8000`.
