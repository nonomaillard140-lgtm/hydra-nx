# HYDRA — console défensive de surface

HYDRA est un binaire Go autonome avec SQLite, une console React embarquée et un dépôt public de listes. Il détecte des expositions sur des actifs que l’opérateur possède ou est autorisé à tester, puis enregistre des preuves **rédigées** pour guider la rotation et la remédiation.

## Périmètre de sécurité

Cette implémentation exclut volontairement les capacités qui transformeraient le produit en outil d’exploitation de credentials :

- aucun contournement de WAF, padding au-delà de 8 Ko, null byte, double/triple encodage ou injection d’en-têtes ;
- aucune validation d’un secret découvert auprès d’AWS, Stripe, SMTP ou d’un autre compte tiers ;
- aucune valeur de secret conservée ou affichée : preuve rédigée et empreinte HMAC uniquement ;
- aucun déploiement de mailer PHP, webshell, probe persistant ou adaptation FTP/SFTP ;
- aucun envoi en lot : le module SMTP envoie uniquement à une adresse de contrôle configurée par l’opérateur ;
- aucune découverte par wildcard, balayage ASN ou expansion de cible hors du périmètre déclaré.

Le registre d’addons effectue une classification locale et recommande une révocation. Le champ `cash_score` du modèle historique est utilisé comme **priorité de remédiation sur 100**, jamais comme estimation de gain financier. Les intégrations de paiement Stripe/crypto ne sont pas incluses ; l’administrateur provisionne les licences depuis la console.

## Fonctions livrées

- premier compte admin généré au démarrage, Argon2id, TOTP, huit codes de récupération, sessions signées HttpOnly et liaison d’appareils ;
- rôle admin illimité, plans, licences Ed25519 hors ligne, crédits journaliers et registre ;
- migrations SQLite versionnées, chiffrement AES-GCM des configurations sensibles, audit et purge à 90 jours ;
- listes L7/L4 normalisées, dédoublonnées et soumises à confirmation d’autorisation ;
- corpus de chemins, variantes canoniques, référence 403/404, moteur de diff et filtrage de leurres ;
- parseurs `.env`, `wp-config`, Git HEAD et source maps ; entropie sans divulgation de la valeur ;
- workers, limite par hôte, gigue, HTTP/2 standard, backoff sur 429/503 et reprise des scans ;
- bibliothèque de hits dédupliquée, filtres, export CSV rédigé et notifications Telegram/Discord/webhook ;
- console d’envoi SMTP de contrôle avec 587/465/25, TLS et journal ;
- pages publiques sans JavaScript, dépôt de listes avec manifest, taille, lignes, SHA-256 et compteurs ;
- sauvegarde cohérente par `VACUUM INTO`, restauration des sessions, migration SSH, diagnostic et installation Debian 12 ;
- frontend React 18 + TypeScript + Vite + Tailwind, embarqué avec `go:embed`, responsive et installable en PWA.

## Arborescence

```text
cmd/nx/              binaire et sous-commandes
internal/api/        routeur chi, handlers et middlewares
internal/auth/       Argon2id, sessions et TOTP
internal/license/    licences Ed25519
internal/store/      SQLite, migrations, requêtes et sauvegardes
internal/scan/       ordonnanceur, limiteur et moteur HTTP
internal/discover/   normalisation du périmètre et DNS explicite
internal/fuzz/       corpus canonique et moteur de diff
internal/extract/    parseurs et preuves rédigées
internal/addons/     registre d’analyse locale
internal/send/       SMTP de contrôle
internal/publiclists/ publication, manifest et checksums
internal/notify/     notifications sortantes
internal/score/      gravité et priorité
web/                 sources React et compilation embarquée
deploy/              Docker, compose, systemd et installateur
data/public/lists/   fichiers publiés à l’exécution
```

## Compiler

Prérequis : Go 1.22 ou supérieur, Node.js 20 ou supérieur et npm. La compilation finale n’utilise pas cgo.

```sh
go mod tidy
cd web && npm ci --no-audit --no-fund && npm run build && cd ..
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o nx ./cmd/nx
```

Ou simplement :

```sh
make build
```

Les artefacts `web/dist/` sont inclus dans l’archive : `go build ./...` fonctionne donc sans réinstaller npm. Pour produire les deux binaires Linux :

```sh
make cross
```

## Vérification

```sh
gofmt -l .
go vet ./...
go build ./...
go test ./...
```

`gofmt -l .` doit être silencieux. Les tests couvrent les parseurs, encodeurs canoniques, diff, authentification, TOTP, licences, chiffrement, migrations, déduplication, sauvegarde/restauration, publication, configuration SMTP, scan local et API.

Démarrage local :

```sh
./nx migrate --data ./data
./nx serve --data ./data --addr 127.0.0.1:8080
```

Le premier démarrage affiche une seule fois l’utilisateur `admin` et son mot de passe aléatoire. Ouvrir `http://127.0.0.1:8080/login`. Sans TLS local, ne pas activer `--secure-cookie`.

## Déploiement Debian 12

### Prérequis DNS et pare-feu

1. Créer les enregistrements A et, si utilisé, AAAA du domaine vers le VPS.
2. Autoriser les ports 80 et 443 pour Caddy/ACME. Le port 8080 reste lié à `127.0.0.1`.
3. Copier le binaire `nx` et le dossier `deploy/` sur le serveur.

### Installation en une commande

```sh
sudo sh deploy/install.sh --binary ./nx --domain hydra.example.com
```

Le script :

- vérifie la distribution et crée l’utilisateur système non-root `hydra` ;
- installe `/opt/hydra/nx` et l’unité systemd durcie ;
- crée `/var/lib/hydra` avec des permissions restrictives ;
- démarre le service et affiche les identifiants initiaux s’ils viennent d’être créés ;
- installe Caddy si nécessaire, configure le reverse proxy et obtient le certificat ACME.

La console est alors disponible sur `https://hydra.example.com/login`. Les secrets d’exécution sont générés dans `/var/lib/hydra`, jamais dans le script.

Simulation sans modification :

```sh
sh deploy/install.sh --binary ./nx --domain hydra.example.com --dry-run
```

L’installation est réexécutable. Pour suivre le service :

```sh
sudo systemctl status hydra
sudo journalctl -u hydra -n 100 --no-pager
```

Réinitialisation hors ligne du mot de passe admin :

```sh
sudo systemctl stop hydra
sudo /opt/hydra/nx passwd --admin --data /var/lib/hydra
sudo systemctl start hydra
```

### Caddy déjà installé

Configuration équivalente :

```caddy
hydra.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}
```

Puis :

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Un certificat et une clé existants peuvent aussi être passés directement à `nx serve --tls-cert ... --tls-key ... --secure-cookie`.

## Docker

```sh
docker compose -f deploy/compose.yaml up --build -d
docker compose -f deploy/compose.yaml logs -f
```

Le volume `hydra-data` conserve base, clés et listes. Le service écoute sur `127.0.0.1:8080`; placer Caddy devant pour HTTPS et passer `HYDRA_SECURE_COOKIE` à `"true"`.

## Publication de listes

```sh
./nx publish-list --data ./data --file targets.txt --name "Actifs exemple" --kind L7
./nx publish-list --data ./data --file paths.txt --name "Chemins défensifs" --kind PATHS
```

Routes publiques :

- `/lists` : index HTML sans JavaScript ;
- `/lists/:id` : métadonnées et checksum ;
- `/lists/:id/raw` : téléchargement avec `Content-Disposition` ;
- `/lists/manifest.json` : consommation outillage.

Chaque téléchargement vérifie taille et SHA-256 avant d’incrémenter le compteur.

## Sauvegarde, restauration et déplacement

Sauvegarde cohérente, y compris sessions et clés :

```sh
./nx backup --data ./data --file hydra-backup.tar.gz
```

Restauration dans un répertoire vide, service arrêté :

```sh
./nx restore --data ./data-restored --file hydra-backup.tar.gz
```

Conserver la clé `master.key` est indispensable pour déchiffrer les configurations. Une restauration sans cette clé ne permet pas de récupérer les secrets de transport.

Migration vers un nouveau VPS par SSH :

```sh
./nx migrate --data ./data --to root@nouveau-vps \
  --remote-dir /opt/hydra --remote-data /var/lib/hydra
```

La commande crée une sauvegarde, pousse binaire et archive avec `scp`, restaure dans un répertoire nouveau puis bascule le service. L’ancienne donnée distante est conservée avec le suffixe `.previous`. Les outils `ssh` et `scp` sont requis localement et `systemd` sur le distant.

## Sous-commandes

```text
serve          panneau HTTP/HTTPS et workers
worker         workers seuls avec reprise des files
migrate        migrations SQLite, ou migration VPS avec --to
selfinstall    binaire et unité systemd de base, en root
backup         archive cohérente du répertoire de données
restore        restauration dans un répertoire vide
passwd         réinitialisation admin hors ligne
keygen         génération/lecture de la clé publique Ed25519
doctor         SQLite, permissions, port, DNS, disque et horloge
publish-list   publication avec dédoublonnage et SHA-256
cleanup        sessions expirées et envois de plus de 90 jours
```

## API et exploitation

Toutes les mutations authentifiées exigent `X-Requested-With: XMLHttpRequest`. Le cookie `nx_session` contient un jeton aléatoire signé ; seul son hash SHA-256 est stocké. Les routes privées commencent par `/api/auth`, `/api/lists`, `/api/paths`, `/api/scans`, `/api/hits`, `/api/notifications`, `/api/send` et `/api/license`. Les routes `/api/admin` exigent le rôle admin.

L’impersonation admin est une agrégation en lecture seule et produit un événement d’audit. L’export de base complet se fait par `nx backup`, ce qui évite d’exposer une archive sensible via le navigateur.

## Production

- Sauvegarder régulièrement le répertoire de données et tester la restauration.
- Conserver Caddy à jour et ne pas exposer directement le port 8080.
- Examiner les preuves rédigées, révoquer les secrets signalés et vérifier les journaux des actifs concernés.
- Les scans doivent rester limités à un périmètre dont l’autorisation est documentée.
