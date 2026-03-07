# SecureFiles

**Alternative self-hostée à WeTransfer.** Partagez des fichiers de façon éphémère, chiffrée et maîtrisée — sans dépendre d'un tiers.

---

## Pourquoi SecureFiles ?

Les services de partage grand public (WeTransfer, Smash, Filemail…) traitent vos fichiers sur leurs infrastructures. SecureFiles vous rend le contrôle : vous choisissez le serveur, les règles d'accès et la durée de vie des données.

- **Vos données restent chez vous** — aucun tiers n'a accès à vos fichiers
- **Chiffrement au repos** — les fichiers sont chiffrés sur le disque (Fernet : AES-128-CBC + HMAC-SHA256)
- **Chiffrement de bout en bout (E2E)** — en mode E2E, le fichier est chiffré côté navigateur (AES-256-GCM) avant envoi ; le serveur ne voit jamais le contenu en clair
- **Éphémère par nature** — expiration automatique, suppression après téléchargement
- **Déploiement simple** — un `docker compose up` suffit

---

## Fonctionnalités

### Partage de fichiers

| Fonctionnalité | Détail |
|---|---|
| Drag & drop | Dépôt par glisser-lâcher ou clic |
| Lien unique | Identifiant UUID non devinable, non listé |
| Expiration | 3 h · 1 j · 1 sem · 1 mois — ou valeur par défaut admin |
| Limite de téléchargements | 1 / 5 / 10 / illimité |
| Protection par mot de passe | Accès conditionné à un mot de passe |
| Autodestruction | Suppression dès le premier téléchargement |
| Lien de dépôt | Recevez des fichiers sans que l'expéditeur ait un compte |

### Authentification & Comptes

| Fonctionnalité | Détail |
|---|---|
| SSO OIDC | Connexion via votre fournisseur d'identité (Keycloak, Authentik, Azure AD…) |
| MFA TOTP | Google Authenticator, Authy ou compatible RFC 6238 |
| MFA WebAuthn | Clé matérielle (YubiKey), Touch ID, Windows Hello |
| Codes de récupération | Codes de secours en cas de perte du second facteur |
| Verrouillage de compte | Blocage temporaire après tentatives échouées |
| Thème clair / sombre | Préférence persistée par compte |

### Administration

| Fonctionnalité | Détail |
|---|---|
| Panel d'administration | Gestion centralisée depuis `/admin` |
| Gestion des utilisateurs | Création, suppression, promotion admin |
| Quotas | Limite de stockage et de fichiers par compte |
| Extensions bloquées | Liste configurable (exe, bat, sh…) |
| Inscriptions publiques | Activation / désactivation |
| Journal d'audit | Traçabilité de toutes les actions sensibles |
| Nettoyage automatique | Purge planifiée des fichiers expirés |

---

## Déploiement

### Prérequis

- [Docker](https://docs.docker.com/get-docker/) ≥ 20
- [Docker Compose](https://docs.docker.com/compose/) ≥ 2

### Démarrage rapide

```bash
git clone <url-du-dépôt> && cd securefiles
cp .env.example .env
```

Éditez `.env` et renseignez au minimum :

```env
# Générer avec : python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<clé aléatoire>

# Générer avec : python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=<clé Fernet>
```

Puis :

```bash
docker compose up -d --build
```

L'application écoute sur `http://127.0.0.1:5000`. Placez un proxy HTTPS (nginx, Caddy…) devant.

### Variables d'environnement

| Variable | Description |
|---|---|
| `SECRET_KEY` | Clé secrète Flask — **obligatoire** |
| `ENCRYPTION_KEY` | Clé Fernet pour le chiffrement des fichiers — **obligatoire** |
| `WEBAUTHN_RP_ID` | Domaine de l'app (ex. `share.example.com`) — requis si WebAuthn |
| `WEBAUTHN_RP_ORIGIN` | Origine complète (ex. `https://share.example.com`) — requis si WebAuthn |
| `SSO_CLIENT_ID` | Client ID OIDC |
| `SSO_CLIENT_SECRET` | Secret OIDC |
| `SSO_DISCOVERY_URL` | URL de découverte OIDC (`.well-known/openid-configuration`) |

### Proxy HTTPS (exemple nginx)

```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host  $host;
    proxy_set_header Host              $host;
}
```

---

## Stack

Python · Flask · Gunicorn · SQLite · Docker

---

## Licence

MIT
