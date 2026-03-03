# SecureFiles

Application web de **partage sécurisé de fichiers** auto-hébergée. Déposez un fichier, obtenez un lien unique, configurez une expiration et un mot de passe — rien de plus.

## Fonctionnalités

### Partage de fichiers
- **Glisser-déposer** — interface drag & drop intuitive
- **Lien unique** — chaque fichier reçoit un identifiant UUID non devinable
- **Expiration configurable** — 3 heures · 1 jour · 1 semaine · 1 mois
- **Limite de téléchargements** — 1 / 5 / 10 / illimité
- **Protection par mot de passe** — hachage PBKDF2-SHA256 via Werkzeug
- **Suppression à la lecture** — option pour autodétruire le fichier après le premier téléchargement
- **Lien de dépôt personnel** — token unique par utilisateur pour recevoir des fichiers sans compte

### Sécurité
- **Chiffrement Fernet** — fichiers chiffrés au repos (AES-128-CBC)
- **Protection CSRF** — Flask-WTF sur tous les formulaires
- **Rate limiting** — Flask-Limiter + Redis (200/jour · 50/heure par IP)
- **Extensions bloquées** — `exe` `bat` `cmd` `sh` `msi` `dll` `com` `scr` `vbs` `ps1` (configurable)
- **Taille maximale** — configurable via le panel d'administration (défaut : 16 Mo)

### Authentification & Comptes
- **Inscription / Connexion** — système de comptes utilisateurs
- **MFA TOTP** — authentification à deux facteurs via application (Google Authenticator, Authy…)
- **MFA WebAuthn** — clé de sécurité matérielle (YubiKey, passkey) optionnelle
- **Profil utilisateur** — changement de mot de passe, avatar initiale, couleur d'avatar
- **Thème sombre** — bascule clair/sombre persistée par compte
- **Dashboard** — liste de tous ses fichiers avec statut et actions

### Administration
- **Panel d'administration** — accessible aux comptes marqués administrateur
- **Gestion des utilisateurs** — liste, suppression, promotion/rétrogradation admin
- **Paramètres globaux** — nom de l'application, e-mail de contact, quotas, extensions bloquées, autorisation des inscriptions
- **Journal d'audit** — traçabilité des actions sensibles (upload, téléchargement, suppression, connexion…)
- **Nettoyage automatique** — purge planifiée des fichiers expirés ou épuisés

## Stack technique

| Couche | Technologie |
|---|---|
| Backend | Python 3.9, Flask 2.0, Gunicorn |
| Authentification | Flask-Login, Flask-WTF (CSRF) |
| MFA | pyotp (TOTP), py_webauthn (WebAuthn) |
| Base de données | SQLite (métadonnées fichiers et utilisateurs) |
| Chiffrement | cryptography (Fernet / AES-128) |
| Cache / Rate limit | Redis, Flask-Limiter |
| Tâches planifiées | APScheduler |
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

### Variables d'environnement (`.env`)

| Variable | Défaut | Description |
|---|---|---|
| `SECRET_KEY` | `supersecretkey` | Clé secrète Flask — **à changer en production** |
| `ENCRYPTION_KEY` | — | Clé Fernet — **générer une nouvelle clé en production** |
| `REDIS_URL` | `redis://redis:6379/0` | URL de connexion Redis |
| `FLASK_ENV` | `development` | Environnement Flask (`development` / `production`) |
| `WEBAUTHN_RP_ID` | `localhost` | Domaine de l'application pour WebAuthn |
| `WEBAUTHN_RP_ORIGIN` | `http://localhost:5000` | Origine complète pour WebAuthn |

> **Important** — Ne commitez jamais votre `.env` avec des secrets réels. Ajoutez-le à `.gitignore` en production.

### Paramètres d'application (panel admin)

Les paramètres suivants sont modifiables depuis le panel d'administration (`/admin`) :

| Paramètre | Défaut | Description |
|---|---|---|
| Nom de l'application | `FileShareApp` | Nom affiché dans l'interface |
| E-mail de contact | — | Adresse affichée dans la modal Contact |
| Taille max des fichiers | `16 Mo` | Taille maximale d'un fichier |
| Extensions bloquées | `exe,bat,cmd…` | Liste des extensions interdites |
| Autoriser les inscriptions | `oui` | Activer/désactiver l'inscription publique |
| Expiration par défaut | `1 jour` | Durée d'expiration pré-sélectionnée |
| Quota fichiers / utilisateur | `0` (illimité) | Nombre max de fichiers par compte |
| Quota stockage / utilisateur | `0` (illimité) | Espace max par compte en Mo |

### Générer une clé de chiffrement

```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

## Utilisation

### Envoyer un fichier

1. Ouvrez `http://localhost:5000`
2. Glissez un fichier dans la zone de dépôt (ou cliquez pour parcourir)
3. Dans la modale, définissez :
   - Un mot de passe optionnel
   - La durée de validité
   - Le nombre maximal de téléchargements
4. Cliquez sur **Téléverser** — un lien unique est généré
5. Copiez et partagez le lien

Le destinataire accède au fichier via le lien. Si un mot de passe a été défini, il lui sera demandé avant le téléchargement.

### Créer un compte

1. Rendez-vous sur `/register`
2. Renseignez un nom d'utilisateur et un mot de passe (10 caractères minimum)
3. Une fois connecté, accédez à votre **dashboard** pour gérer vos fichiers

### Activer le MFA

Depuis votre profil (`/profile`) :
- **TOTP** : scannez le QR code avec une application d'authentification, saisissez le code pour confirmer
- **WebAuthn** : enregistrez une clé de sécurité matérielle ou une passkey

## Structure du projet

```
securefiles/
├── app.py                      # Application Flask (routes, logique métier)
├── requirements.txt            # Dépendances Python
├── package.json                # Dépendances Node.js (Tailwind)
├── tailwind.config.js          # Configuration Tailwind CSS
├── src/tailwind.css            # CSS source Tailwind
├── Dockerfile                  # Image Docker de l'application
├── docker-compose.yml          # Orchestration (app + Redis)
├── entrypoint.sh               # Script d'entrée du conteneur
├── .env                        # Variables d'environnement
├── static/css/                 # CSS compilé
└── templates/
    ├── index.html              # Page principale (upload / drag & drop)
    ├── upload.html             # Formulaire d'envoi alternatif
    ├── download.html           # Page de téléchargement
    ├── password_required.html  # Saisie du mot de passe
    ├── file_not_found.html     # Fichier introuvable
    ├── file_expired.html       # Fichier expiré
    ├── drop.html               # Page de dépôt via token personnel
    ├── login.html              # Connexion
    ├── register.html           # Inscription
    ├── mfa.html                # Vérification MFA (TOTP / WebAuthn)
    ├── dashboard.html          # Tableau de bord utilisateur
    ├── profile.html            # Profil (mot de passe, avatar, MFA, thème)
    └── admin.html              # Panel d'administration
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

- Les fichiers sont **chiffrés au repos** avec Fernet (AES-128-CBC)
- Les mots de passe sont hachés avec **PBKDF2-SHA256** (Werkzeug)
- Les secrets TOTP sont chiffrés en base avec Fernet
- Protection **CSRF** active sur tous les formulaires POST
- **Rate limiting** par IP via Redis
- Les noms de fichiers sont assainis avec `werkzeug.utils.secure_filename`
- Les fichiers expirés ou épuisés sont **supprimés automatiquement** (tâche planifiée)
- **WebAuthn** : authentification sans mot de passe par clé matérielle ou passkey

## Licence

MIT
