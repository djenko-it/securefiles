# SecureFiles

Application web de **partage sécurisé de fichiers** auto-hébergée. Déposez un fichier, obtenez un lien unique, configurez une expiration et un mot de passe — rien de plus.

## Fonctionnalités

- **Glisser-déposer** — interface drag & drop intuitive
- **Lien unique** — chaque fichier reçoit un identifiant UUID non devinable
- **Expiration configurable** — 3 heures · 1 jour · 1 semaine · 1 mois
- **Limite de téléchargements** — 1 / 5 / 10 / illimité
- **Protection par mot de passe** — hachage bcrypt via Werkzeug
- **Protection CSRF** — Flask-WTF sur tous les formulaires
- **Rate limiting** — Flask-Limiter + Redis (200/jour · 50/heure par IP)
- **Types de fichiers autorisés** — `txt` `pdf` `png` `jpg` `jpeg` `gif` `zip` `rar`
- **Taille maximale** — configurable (défaut : 10 Mo)

## Stack technique

| Couche | Technologie |
|---|---|
| Backend | Python 3.9, Flask 2.0, Gunicorn |
| Base de données | SQLite (métadonnées fichiers) |
| Cache / Rate limit | Redis |
| Frontend | Jinja2, Bootstrap 4.5, Tailwind CSS 3, Font Awesome 5 |
| Conteneurisation | Docker, Docker Compose |

## Prérequis

- [Docker](https://docs.docker.com/get-docker/) ≥ 20
- [Docker Compose](https://docs.docker.com/compose/) ≥ 1.29

## Installation

```bash
git clone <url-du-dépôt>
cd securefiles
```

Copiez le fichier d'environnement et adaptez les valeurs :

```bash
cp .env .env.local
```

Démarrez l'application :

```bash
docker compose up --build
```

L'application est accessible sur `http://localhost:5000`.

## Configuration

Toutes les options sont définies dans le fichier `.env` :

| Variable | Défaut | Description |
|---|---|---|
| `SECRET_KEY` | `supersecretkey` | Clé secrète Flask — **à changer en production** |
| `SOFTWARE_NAME` | `FileShareApp` | Nom affiché dans l'interface |
| `MAX_FILE_SIZE` | `10` | Taille maximale d'un fichier en Mo |
| `CONTACT_EMAIL` | `djenko-it@protonmail.com` | Adresse affichée dans la modal Contact |
| `TITLE_UPLOAD_FILE` | `Téléverser un Fichier` | Titre de la page d'envoi |
| `TITLE_DOWNLOAD_FILE` | `Télécharger un Fichier` | Titre de la page de téléchargement |
| `SHOW_DELETE_ON_READ` | `true` | Suppression automatique à la lecture |
| `SHOW_PASSWORD_PROTECT` | `true` | Activation de la protection par mot de passe |
| `REDIS_URL` | `redis://redis:6379/0` | URL de connexion Redis |
| `ENCRYPTION_KEY` | — | Clé Fernet — **générer une nouvelle clé en production** |
| `FLASK_ENV` | `development` | Environnement Flask (`development` / `production`) |

> **Important** — Ne commitez jamais votre `.env` avec des secrets réels. Ajoutez-le à `.gitignore` en production.

### Générer une clé de chiffrement

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

## Utilisation

1. Ouvrez `http://localhost:5000`
2. Glissez un fichier dans la zone de dépôt (ou cliquez pour parcourir)
3. Dans la modale, définissez :
   - Un mot de passe optionnel
   - La durée de validité
   - Le nombre maximal de téléchargements
4. Cliquez sur **Téléverser** — un lien unique est généré
5. Copiez et partagez le lien

Le destinataire accède au fichier via le lien. Si un mot de passe a été défini, il lui sera demandé avant le téléchargement.

## Structure du projet

```
securefiles/
├── app.py                  # Application Flask (routes, logique métier)
├── requirements.txt        # Dépendances Python
├── package.json            # Dépendances Node.js (Tailwind)
├── tailwind.config.js      # Configuration Tailwind CSS
├── src/tailwind.css        # CSS source Tailwind
├── Dockerfile              # Image Docker de l'application
├── docker-compose.yml      # Orchestration (app + Redis)
├── entrypoint.sh           # Script d'entrée du conteneur
├── .env                    # Variables d'environnement
└── templates/
    ├── index.html          # Page principale (upload)
    ├── upload.html         # Formulaire d'envoi alternatif
    ├── download.html       # Page de téléchargement
    ├── password_required.html  # Saisie du mot de passe
    ├── file_not_found.html # Fichier introuvable
    └── file_expired.html   # Fichier expiré
```

## Développement local (sans Docker)

```bash
# Dépendances Python
pip install -r requirements.txt

# Dépendances Node.js et build CSS
npm install
npm run build:css

# Démarrer Redis (nécessaire pour le rate limiting)
redis-server &

# Initialiser la base de données et lancer Flask
python app.py
```

## Sécurité

- Les mots de passe sont hachés avec **PBKDF2-SHA256** (Werkzeug)
- Protection **CSRF** active sur tous les formulaires POST
- **Rate limiting** par IP via Redis
- Les noms de fichiers sont assainis avec `werkzeug.utils.secure_filename`
- Les fichiers expirés ou épuisés sont supprimés automatiquement de la base

## Licence

MIT
