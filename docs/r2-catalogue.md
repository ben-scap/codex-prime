# Catalogue éditable de Codex Prime

## Architecture retenue

Le site reste un site HTML statique. `index.html`, `README.md`, les 43 cartes, la recherche et les filtres ne sont pas remplacés par une application ou un framework.

- `outils.html` : interface d’édition, identifiants techniques fixes et affichage des commentaires.
- `functions/api/[[path]].js` : Cloudflare Pages Function (runtime Worker) pour lire/écrire les fiches et commentaires.
- `wrangler.toml` : liaison déclarative au bucket R2 `codex-prime-tools`.
- `tests/worker.test.js` et `tests/catalog.test.js` : tests API, persistance, sécurité et structure du catalogue.
- `.github/workflows/catalog-tests.yml` : tests sur `feat/pied-de-page` et les pull requests vers `main`. Ce workflow ne publie pas le site.

## Données R2

- Une fiche par objet : `tools/{outilId}.json`.
- Un commentaire par objet : `comments/{outilId}/{commentId}.json`.
- Marqueur d’initialisation : `meta/catalog-initialized.json`.

Les identifiants `outilId` sont des UUID opaques inscrits une fois dans les attributs `data-tool-id`. Ils ne dépendent pas du nom, de l’URL ou de l’ordre d’affichage.

L’initialisation est manuelle depuis le bouton de la page. Le Worker crée les objets uniquement s’ils n’existent pas, puis pose un marqueur. Une nouvelle initialisation est refusée ; une reprise après interruption ne remplace jamais les objets déjà créés. Ne supprime pas le marqueur pour relancer l’initialisation.

Les modifications utilisent l’ETag R2 dans `If-Match` et une écriture conditionnelle R2. Une version périmée donne une réponse HTTP 409, sans écraser la fiche récente.

## Réglages Cloudflare à effectuer

1. Créer un bucket R2 nommé exactement `codex-prime-tools`.
2. Dans Cloudflare Pages > projet `codex-prime` > Settings > Functions, lier le bucket avec le binding `TOOLS_R2`. Le fichier `wrangler.toml` décrit également ce binding ; vérifier qu’il apparaît dans l’environnement Preview utilisé.
3. Créer une application Cloudflare Access protégeant les chemins d’API d’écriture :
   - `/api/tools/*`
   - `/api/admin/*`
   Autoriser uniquement l’adresse e-mail de l’éditeur prévue. L’endpoint public de lecture `GET /api/catalog` reste hors de ces motifs.
4. Dans les variables d’environnement Pages Functions (Preview d’abord, puis Production si souhaité), définir :
   - `ACCESS_TEAM_DOMAIN` : domaine de l’équipe, par exemple `mon-equipe.cloudflareaccess.com` (sans protocole).
   - `ACCESS_AUD` : Audience (AUD) de l’application Access.
   - `EDITOR_EMAILS` : liste d’adresses autorisées, séparées par des virgules.
   - `ACCESS_ENABLED` : mettre `true` seulement après avoir réellement activé l’application Access et vérifié ses chemins/politiques.
5. Déployer d’abord sur la prévisualisation de `feat/pied-de-page`, puis vérifier que `GET /api/catalog` répond et que les boutons restent désactivés tant que `ACCESS_ENABLED` n’est pas `true`.
6. Après activation d’Access, ouvrir la prévisualisation, s’authentifier et cliquer une seule fois sur « Initialiser les 43 fiches dans R2 ».

Aucun mot de passe, jeton partagé, secret ou clé privée n’est placé dans le JavaScript ou dans le dépôt. Le Worker vérifie la signature RS256 du JWT Cloudflare Access, son émetteur, son audience, son expiration et l’adresse autorisée. CORS n’est pas utilisé comme mécanisme d’autorisation.

## Routes

- `GET /api/catalog` : lecture des fiches et commentaires.
- `POST /api/admin/initialize` : initialisation unique, Access obligatoire.
- `PUT /api/tools/{outilId}` : remplacement conditionnel de la fiche, Access et `If-Match` obligatoires.
- `POST /api/tools/{outilId}/comments` : ajout d’un commentaire séparé, Access obligatoire.

Les commentaires sont affichés par `textContent`, jamais injectés comme HTML. Les URL de fiche sont limitées à HTTP/HTTPS. Les tailles, longueurs, catégories, types et structures JSON sont validés côté serveur.

## Tests

Lancer localement avec Node.js 22 ou plus récent :

```bash
npm test
```

Le workflow GitHub Actions exécute les mêmes tests. Les tests automatisés couvrent l’initialisation non destructive, la modification des champs et des types, la relecture après chargement, l’isolation des commentaires, la conservation des commentaires après changement d’URL, les URL/commentaires invalides, les utilisateurs non autorisés et les conflits de version.

Les tests utilisent un bucket R2 simulé et une signature Access de test ; ils ne remplacent pas un essai réel sur Cloudflare Pages, Access et R2.
