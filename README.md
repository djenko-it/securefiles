# SecureFiles

Application web de partage de fichiers sécurisé avec liens temporaires, protection par mot de passe et limitation des téléchargements.

## Fonctionnalités

- Upload de fichiers via une interface web
- Génération d'un lien unique (UUID) par fichier
- Expiration configurable : 3 heures, 1 jour, 1 semaine, 1 mois
- Limite de téléchargements : 1, 5, 10 ou illimité
- Protection optionnelle par mot de passe (hashé avec bcrypt)
- Rate limiting anti brute-force via Redis
- Protection CSRF intégrée (Flask-WTF)
- Interface responsive Tailwind CSS
- Suppression automatique des fichiers expirés

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Python 3.9 / Flask 2.0 |
| Base de données | SQLite |
| Cache / Rate limiting | Redis |
| CSS | Tailwind CSS 3 |
| Serveur WSGI | Gunicorn |
| Conteneurisation | Docker / Docker Compose |

## Prérequis

- [Docker](https://docs.docker.com/get-docker/) >= 20.x
- [Docker Compose](https://docs.docker.com/compose/install/) >= 2.x

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/djenko-it/securefiles.git
cd securefiles
```

### 2. Configurer les variables d'environnement

Copier le fichier `.env` d'exemple et l'adapter :

```bash
cp .env .env.local
```

Modifier `.env` avec vos valeurs :

```env
FLASK_ENV=production
SOFTWARE_NAME=SecureFiles
CONTACT_EMAIL=votre@email.com
TITLE_UPLOAD_FILE="Téléverser un Fichier"
TITLE_DOWNLOAD_FILE="Télécharger un Fichier"
SECRET_KEY=changez-cette-cle-secrete
REDIS_URL="redis://redis:6379/0"
ENCRYPTION_KEY="votre-cle-de-chiffrement-generee"
MAX_FILE_SIZE="10"
```

> **Important :** Générez une `SECRET_KEY` et une `ENCRYPTION_KEY` uniques pour la production. Ne commitez jamais le fichier `.env` avec de vraies clés.

Pour générer une clé sécurisée :
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 3. Lancer avec Docker Compose

```bash
docker compose up -d --build
```

L'application sera accessible sur : [http://localhost:5000](http://localhost:5000)

### 4. Vérifier que les conteneurs sont actifs

```bash
docker compose ps
```

### 5. Consulter les logs

```bash
docker compose logs -f web
docker compose logs -f redis
```

## Structure du projet

```
securefiles/
├── app.py                  # Application Flask principale
├── Dockerfile              # Image Docker
├── docker-compose.yml      # Orchestration des services
├── entrypoint.sh           # Script d'initialisation du conteneur
├── requirements.txt        # Dépendances Python
├── package.json            # Dépendances Node.js (Tailwind)
├── tailwind.config.js      # Configuration Tailwind CSS
├── src/
│   └── tailwind.css        # CSS source Tailwind
└── templates/
    ├── index.html          # Page d'accueil / upload
    ├── download.html       # Page de téléchargement
    ├── upload.html         # Confirmation d'upload
    ├── password_required.html  # Page mot de passe
    ├── file_not_found.html # Page fichier introuvable
    └── file_expired.html   # Page fichier expiré
```

## Types de fichiers acceptés

`txt` `pdf` `png` `jpg` `jpeg` `gif` `zip` `rar`

## Arrêter l'application

```bash
docker compose down
```

Pour supprimer également les volumes (données Redis) :

```bash
docker compose down -v
```

## Développement local (sans Docker)

```bash
# Installer les dépendances Python
pip install -r requirements.txt

# Installer les dépendances Node.js et compiler le CSS
npm install
npm run build:css

# Démarrer Redis localement (requis)
redis-server

# Initialiser la base de données et lancer Flask
python -c "from app import init_db; init_db()"
flask run
```

## Licence

MIT — voir [LICENSE](LICENSE) pour plus de détails.

## Contact

djenko-it@protonmail.com
