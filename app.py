import base64
import hashlib
import io
import json
import logging
import mimetypes
import os
import re
import secrets
import sqlite3
import uuid
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode, urlparse

import mistune
import requests
import nh3

import pyotp
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, send_file, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import (BooleanField, FileField, IntegerField, PasswordField,
                     SelectField, StringField, SubmitField, TextAreaField)
from wtforms.validators import DataRequired, EqualTo, Length, NumberRange, Optional, Regexp

try:
    from webauthn import (
        generate_authentication_options,
        generate_registration_options,
        options_to_json,
        verify_authentication_response,
        verify_registration_response,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    WEBAUTHN_AVAILABLE = True
except ImportError:
    WEBAUTHN_AVAILABLE = False

# ── Application ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
_secret_key = os.environ.get('SECRET_KEY', '')
if not _secret_key or _secret_key == 'supersecretkey':
    raise RuntimeError(
        "SECRET_KEY non définie ou valeur par défaut insécurisée. "
        "Définissez SECRET_KEY dans votre .env avec une valeur aléatoire forte, "
        "par exemple : python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key
app.config.update(
    SESSION_COOKIE_SECURE=True,    # cookie uniquement sur HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # inaccessible au JS
    SESSION_COOKIE_SAMESITE='Lax', # protection CSRF de base
    REMEMBER_COOKIE_SECURE=True,
    REMEMBER_COOKIE_HTTPONLY=True,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024 * 1024,  # 10 Go max au niveau Flask (la limite applicative est dans les settings)
)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='memory://',
    default_limits=["200 per day", "50 per hour"],
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'warning'


@app.context_processor
def inject_branding():
    return {'has_logo': os.path.exists(LOGO_PATH)}


DATABASE      = '/app/data/messages.db'
UPLOAD_FOLDER = '/app/data/uploads'
LOGO_PATH     = '/app/data/logo'


def _darken_hex(h: str, amount: float = 0.15) -> str:
    h = h.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r = max(0, int(r * (1 - amount)))
    g = max(0, int(g * (1 - amount)))
    b = max(0, int(b * (1 - amount)))
    return f'#{r:02x}{g:02x}{b:02x}'


# ── Contenus légaux par défaut (modifiables en administration) ─────────────────
_DEFAULT_LEGAL_MENTIONS = """\
## Mentions légales

### Éditeur du site

Ce site est édité par : **[Nom / Raison sociale]**
Adresse : [Adresse complète]
Contact : [{contact_email}](mailto:{contact_email})

### Hébergement

Ce site est hébergé sur une infrastructure auto-hébergée, dont l'exploitant est responsable.

### Directeur de la publication

[Nom du directeur de la publication]

### Propriété intellectuelle

Le code source de cette application est distribué sous licence open source.
Toute reproduction partielle ou totale du contenu est interdite sans autorisation préalable.

### Données personnelles (RGPD)

Conformément au Règlement Général sur la Protection des Données (RGPD — UE 2016/679),
vous disposez d'un droit d'accès, de rectification, d'effacement et de portabilité
de vos données personnelles.

Données collectées : identifiant de connexion, adresse IP anonymisée, journaux d'activité.
Durée de conservation : 90 jours pour les journaux d'audit. Les fichiers sont supprimés
automatiquement à la date d'expiration choisie lors du dépôt.
Aucune donnée n'est transmise à des tiers.

Pour exercer vos droits, contactez : [{contact_email}](mailto:{contact_email})

### Cookies

Ce site utilise uniquement des cookies strictement nécessaires au fonctionnement
du service (session de connexion, jeton CSRF). Aucun cookie publicitaire ou de traçage
n'est utilisé.
"""

_DEFAULT_TERMS_OF_USE = """\
## Conditions Générales d'Utilisation

*En vigueur au {date}*

### 1. Objet

Les présentes Conditions Générales d'Utilisation (CGU) régissent l'accès et l'utilisation
de **{app_name}**, service de partage de fichiers éphémère et chiffré.
En accédant au service, l'utilisateur accepte sans réserve les présentes CGU.

### 2. Accès au service

L'accès est réservé aux personnes disposant d'un compte autorisé par l'administrateur.
Les liens de partage et les zones de dépôt peuvent être accessibles sans compte,
dans les limites définies par l'administrateur.

### 3. Utilisation acceptable

L'utilisateur s'engage à ne pas utiliser ce service pour :

- Transmettre des fichiers illégaux, malveillants ou portant atteinte aux droits de tiers ;
- Contourner les mesures de sécurité ou tenter d'accéder à des ressources non autorisées ;
- Partager du contenu protégé par le droit d'auteur sans autorisation ;
- Toute activité contraire aux lois et règlements en vigueur.

### 4. Durée de conservation des fichiers

Les fichiers sont automatiquement supprimés à l'expiration définie lors du dépôt.
L'administrateur se réserve le droit de supprimer tout contenu à tout moment,
notamment en cas de non-respect des présentes CGU.

### 5. Chiffrement et sécurité

Les fichiers sont chiffrés au repos sur le serveur (Fernet AES-128-CBC + HMAC-SHA256).
En mode chiffrement de bout en bout (E2E), les fichiers sont chiffrés côté navigateur
(AES-256-GCM) avant envoi : le serveur ne peut pas accéder au contenu.
Malgré ces mesures, aucun système n'offre une sécurité absolue.

### 6. Responsabilité

L'éditeur ne saurait être tenu responsable du contenu des fichiers partagés par les
utilisateurs, ni des conséquences d'une utilisation non conforme aux présentes CGU.
Le service est fourni « en l'état », sans garantie de disponibilité continue.

### 7. Données personnelles

Le traitement des données personnelles est décrit dans les
[Mentions légales](/mentions-legales).

### 8. Modification des CGU

Les présentes CGU peuvent être modifiées à tout moment par l'administrateur.
La poursuite de l'utilisation du service après modification vaut acceptation des nouvelles CGU.

### 9. Droit applicable

Les présentes CGU sont soumises au droit français. Tout litige relève de la compétence
exclusive des tribunaux compétents.
"""

SETTINGS_DEFAULTS = {
    'app_name':           'FileShareApp',
    'contact_email':      'djenko-it@protonmail.com',
    'max_file_size_mb':   '16',
    'blocked_extensions': 'exe,bat,cmd,sh,msi,dll,com,scr,vbs,ps1',
    'allow_registration': '1',
    'default_expiry':     '1d',
    'max_files_per_user': '0',
    'max_storage_mb':     '0',
    'max_storage_unit':   'mo',
    'welcome_banner':            '',
    'audit_log_retention_days':  '90',
    'max_file_size_unit':        'mo',
    'e2e_mode':                  'optional',
    'maintenance_mode':          '0',
    'maintenance_message':       'Le site est temporairement en maintenance. Merci de revenir plus tard.',
    'mfa_required':              '0',
    'allow_account_deletion':    '0',
    'accent_color':              '#4361ee',
    'logo_content_type':         '',
    # SSO / OIDC
    'sso_enabled':        '0',
    'sso_force':          '0',
    'sso_provider_name':  'SSO',
    'sso_discovery_url':  '',
    'sso_client_id':      '',
    'sso_client_secret':  '',
    # Mentions légales / CGU
    'legal_mentions': _DEFAULT_LEGAL_MENTIONS,
    'terms_of_use':   _DEFAULT_TERMS_OF_USE,
    # Stockage S3
    'storage_backend':   'local',   # 'local' | 's3'
    's3_bucket':         '',
    's3_region':         '',
    's3_endpoint_url':   '',        # vide = AWS standard ; sinon MinIO/R2/etc.
    's3_access_key':     '',
    's3_secret_key':     '',        # chiffré avec Fernet
    's3_prefix':         '',        # préfixe/dossier optionnel dans le bucket
}

LOGIN_MAX_ATTEMPTS    = 10
LOGIN_LOCKOUT_MINUTES = 15
BACKUP_CODE_COUNT     = 8

AVATAR_COLORS = [
    '#4361ee', '#e63946', '#2a9d8f', '#e9c46a', '#f4a261',
    '#264653', '#6c5ce7', '#00b894', '#fd79a8', '#636e72',
    '#0984e3', '#d63031', '#6ab04c', '#f9ca24', '#eb4d4b',
]

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ── WebAuthn config ───────────────────────────────────────────────────────────
RP_NAME = 'FileShareApp'


def get_rp_id():
    override = os.environ.get('WEBAUTHN_RP_ID')
    if override:
        return override
    return request.host.split(':')[0]  # domaine seul, sans port


def get_rp_origin():
    override = os.environ.get('WEBAUTHN_RP_ORIGIN')
    if override:
        return override
    return f"{request.scheme}://{request.host}"

# ── Chiffrement Fernet ────────────────────────────────────────────────────────
_raw_key = os.environ.get('ENCRYPTION_KEY', '').strip().strip('"').strip("'")
_raw_key = _raw_key.split('#')[0].strip()
if not _raw_key:
    raise RuntimeError(
        "ENCRYPTION_KEY non définie. Les fichiers seraient stockés en clair, "
        "ce qui est incompatible avec les exigences RGPD. "
        "Générez une clé avec : python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    )
try:
    fernet = Fernet(_raw_key.encode())
except Exception as exc:
    raise RuntimeError(
        f"ENCRYPTION_KEY invalide ({exc}). "
        "Générez une clé valide avec : python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
    ) from exc


def _encrypt(data: bytes) -> bytes:
    return fernet.encrypt(data)


def _decrypt(data: bytes) -> bytes:
    return fernet.decrypt(data)


def _encrypt_secret(secret: str) -> str:
    if secret:
        return fernet.encrypt(secret.encode()).decode()
    return secret


def _decrypt_secret(encrypted: str) -> str:
    if not encrypted:
        return ''
    return fernet.decrypt(encrypted.encode()).decode()


# ── Couche de stockage abstraite (local / S3) ─────────────────────────────────
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError as S3ClientError
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

# Antivirus ClamAV (optionnel - actif si le service est joignable)
try:
    import pyclamd
    _PYCLAMD_AVAILABLE = True
except ImportError:
    _PYCLAMD_AVAILABLE = False

_CLAMAV_HOST = os.environ.get('CLAMAV_HOST', 'clamav')
_CLAMAV_PORT = int(os.environ.get('CLAMAV_PORT', '3310'))


def _clamav_scan(data: bytes) -> tuple[bool, str]:
    """Scanne les donnees avec ClamAV via le socket reseau.

    Retourne (safe, message) :
    - (True, '') si sain ou si ClamAV est indisponible (mode degrade transparent)
    - (False, 'Nom du virus') si une menace est detectee
    """
    if not _PYCLAMD_AVAILABLE:
        return True, ''
    try:
        cd = pyclamd.ClamdNetworkSocket(host=_CLAMAV_HOST, port=_CLAMAV_PORT, timeout=15)
        result = cd.scan_stream(data)
        if result is None:
            return True, ''
        status, virus_name = result.get('stream', ('OK', ''))
        if status == 'FOUND':
            return False, virus_name or 'Virus inconnu'
        return True, ''
    except Exception as exc:
        app.logger.warning('ClamAV indisponible, scan ignore : %s', exc)
        return True, ''


def _clamav_available() -> bool:
    """Verifie si le daemon ClamAV est joignable (pour affichage admin)."""
    if not _PYCLAMD_AVAILABLE:
        return False
    try:
        cd = pyclamd.ClamdNetworkSocket(host=_CLAMAV_HOST, port=_CLAMAV_PORT, timeout=3)
        return cd.ping()
    except Exception:
        return False


def _get_s3_settings():
    """Retourne les paramètres S3 depuis la base de données (sans g, utilisable hors contexte)."""
    try:
        with sqlite3.connect(DATABASE) as conn:
            rows = conn.execute("SELECT key, value FROM settings WHERE key LIKE 's3_%' OR key = 'storage_backend'").fetchall()
        s = dict(SETTINGS_DEFAULTS)
        s.update({r[0]: r[1] for r in rows})
        return s
    except Exception:
        return dict(SETTINGS_DEFAULTS)


def _build_s3_client(s):
    """Construit un client boto3 à partir des paramètres s."""
    kwargs = {
        'aws_access_key_id':     s.get('s3_access_key') or None,
        'aws_secret_access_key': _decrypt_secret(s.get('s3_secret_key', '')) or None,
        'region_name':           s.get('s3_region') or None,
    }
    endpoint = s.get('s3_endpoint_url', '').strip()
    if endpoint:
        kwargs['endpoint_url'] = endpoint
    return boto3.client('s3', **kwargs)


def _s3_key(file_id: str, s=None) -> str:
    prefix = (s or {}).get('s3_prefix', '').strip().strip('/')
    return f"{prefix}/{file_id}" if prefix else file_id


def storage_write(file_id: str, data: bytes) -> None:
    """Écrit des données chiffrées dans le backend actif."""
    s = _get_s3_settings()
    if s.get('storage_backend') == 's3':
        if not _BOTO3_AVAILABLE:
            raise RuntimeError("boto3 non installé — impossible d'utiliser le backend S3.")
        client = _build_s3_client(s)
        client.put_object(Bucket=s['s3_bucket'], Key=_s3_key(file_id, s), Body=data)
    else:
        dest = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        with open(dest, 'wb') as fh:
            fh.write(data)


def storage_read(file_id: str) -> bytes:
    """Lit et retourne les données chiffrées depuis le backend actif."""
    s = _get_s3_settings()
    if s.get('storage_backend') == 's3':
        if not _BOTO3_AVAILABLE:
            raise RuntimeError("boto3 non installé.")
        client = _build_s3_client(s)
        resp = client.get_object(Bucket=s['s3_bucket'], Key=_s3_key(file_id, s))
        return resp['Body'].read()
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        with open(path, 'rb') as fh:
            return fh.read()


def storage_delete(file_id: str) -> bool:
    """Supprime un fichier du backend actif. Retourne True si supprimé."""
    s = _get_s3_settings()
    if s.get('storage_backend') == 's3':
        if not _BOTO3_AVAILABLE:
            return False
        try:
            client = _build_s3_client(s)
            client.delete_object(Bucket=s['s3_bucket'], Key=_s3_key(file_id, s))
            return True
        except Exception as exc:
            app.logger.error("S3 delete error %s: %s", file_id, exc)
            return False
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
        except OSError as exc:
            app.logger.error("Erreur suppression fichier %s : %s", file_id, exc)
        return False


def storage_get_size(file_id: str) -> int:
    """Retourne la taille en octets d'un fichier dans le backend actif (0 si absent)."""
    s = _get_s3_settings()
    if s.get('storage_backend') == 's3':
        if not _BOTO3_AVAILABLE:
            return 0
        try:
            client = _build_s3_client(s)
            resp = client.head_object(Bucket=s['s3_bucket'], Key=_s3_key(file_id, s))
            return resp['ContentLength']
        except Exception:
            return 0
    else:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        try:
            return os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            return 0


# ── Backup codes (TOTP recovery) ──────────────────────────────────────────────
def _hash_backup_code(code: str) -> str:
    """SHA-256 d'un code normalisé (minuscules, sans tiret)."""
    return hashlib.sha256(code.lower().replace('-', '').encode()).hexdigest()


def _generate_backup_codes():
    """Génère BACKUP_CODE_COUNT codes aléatoires.
    Retourne (codes_lisibles, json_des_hashes).
    Les codes sont au format 'xxxx-xxxx' (8 hex chars)."""
    raw     = [secrets.token_hex(4) for _ in range(BACKUP_CODE_COUNT)]
    display = [f"{c[:4]}-{c[4:]}" for c in raw]
    hashes  = json.dumps([_hash_backup_code(c) for c in raw])
    return display, hashes


# ── Modèle utilisateur ────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, password, drop_token, is_admin=False,
                 totp_secret=None, webauthn_credential_id=None,
                 webauthn_public_key=None, webauthn_sign_count=0,
                 webauthn_label=None,
                 theme='light', avatar_color='#4361ee', drop_enabled=True,
                 sso_user=False):
        self.id                     = id
        self.username               = username
        self.password               = password
        self.drop_token             = drop_token
        self.is_admin               = bool(is_admin)
        self.totp_secret            = totp_secret
        self.webauthn_credential_id = webauthn_credential_id
        self.webauthn_public_key    = webauthn_public_key
        self.webauthn_sign_count    = webauthn_sign_count or 0
        self.webauthn_label         = webauthn_label
        self.theme                  = theme or 'light'
        self.avatar_color           = avatar_color or '#4361ee'
        self.drop_enabled           = bool(drop_enabled) if drop_enabled is not None else True
        self.sso_user               = bool(sso_user)

    @property
    def has_mfa(self):
        return bool(self.totp_secret or self.webauthn_credential_id)

    @property
    def has_totp(self):
        return bool(self.totp_secret)

    @property
    def has_webauthn(self):
        return bool(self.webauthn_credential_id)

    @property
    def avatar_letter(self):
        return self.username[0].upper() if self.username else '?'


_USER_COLS = ('id, username, password, drop_token, is_admin, '
              'totp_secret, webauthn_credential_id, webauthn_public_key, '
              'webauthn_sign_count, webauthn_label, theme, avatar_color, drop_enabled, sso_user')


def _load_user_by(column, value):
    cur = get_db().execute(f'SELECT {_USER_COLS} FROM users WHERE {column} = ?', (value,))
    row = cur.fetchone()
    return User(*row) if row else None


@login_manager.user_loader
def load_user(user_id):
    return _load_user_by('id', user_id)


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Context processor (thème + avatar global) ─────────────────────────────────
@app.context_processor
def inject_globals():
    if current_user.is_authenticated:
        return {
            'user_theme':        current_user.theme,
            'user_avatar_color': current_user.avatar_color,
            'user_avatar_letter': current_user.avatar_letter,
            'csp_nonce': g.get('csp_nonce', ''),
        }
    return {'user_theme': 'light', 'user_avatar_color': '#4361ee', 'user_avatar_letter': '?', 'csp_nonce': g.get('csp_nonce', '')}


# ── Formulaires WTForms ───────────────────────────────────────────────────────
class PasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit   = SubmitField('Soumettre')


class FileUploadForm(FlaskForm):
    file     = FileField('Choisissez un fichier', validators=[DataRequired()])
    expiry   = SelectField('Durée de validité', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois'),
        ('custom', 'Date personnalisée…'),
    ])
    password = PasswordField('Mot de passe (optionnel)')
    submit   = SubmitField('Téléverser')


class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[
        DataRequired(), Length(min=3, max=32),
        Regexp(r'^[a-zA-Z0-9._-]+$',
               message="Uniquement lettres, chiffres, points, tirets et underscores."),
    ])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=10)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.'),
    ])
    submit   = SubmitField('Créer un compte')


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe',     validators=[DataRequired()])
    submit   = SubmitField('Se connecter')


class SetPasswordForm(FlaskForm):
    """Utilisé pour le reset via lien admin (sans connaître l'ancien mot de passe)."""
    password = PasswordField('Nouveau mot de passe', validators=[DataRequired(), Length(min=10)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.'),
    ])
    submit   = SubmitField('Définir le mot de passe')


class ChangePasswordForm(FlaskForm):
    current  = PasswordField('Mot de passe actuel', validators=[DataRequired()])
    password = PasswordField('Nouveau mot de passe', validators=[DataRequired(), Length(min=10)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.'),
    ])
    submit   = SubmitField('Modifier')


class AdminSettingsForm(FlaskForm):
    app_name                 = StringField('Nom de l\'application',
                                           validators=[DataRequired(), Length(max=64)])
    contact_email            = StringField('E-mail de contact',
                                           validators=[DataRequired(), Length(max=128)])
    welcome_banner           = TextAreaField('Bannière / message d\'accueil',
                                             validators=[Optional(), Length(max=512)])
    max_file_size_value      = IntegerField('Taille max des fichiers',
                                            validators=[DataRequired(), NumberRange(min=1, max=1048576)])
    max_file_size_unit       = SelectField('Unité', choices=[('mo', 'Mo'), ('go', 'Go')])
    blocked_extensions       = StringField('Extensions bloquées (virgules)',
                                           validators=[Optional(), Length(max=256)])
    allow_registration       = BooleanField('Autoriser les inscriptions')
    default_expiry           = SelectField('Expiration par défaut', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois'),
    ])
    max_files_per_user       = IntegerField('Quota fichiers / utilisateur (0 = illimité)',
                                            validators=[NumberRange(min=0)])
    max_storage_value        = IntegerField('Quota stockage / utilisateur (0 = illimité)',
                                            validators=[NumberRange(min=0)])
    max_storage_unit         = SelectField('Unité stockage', choices=[('mo', 'Mo'), ('go', 'Go')])
    audit_log_retention_days = IntegerField('Rétention des logs d\'audit (jours, 0 = illimité)',
                                            validators=[NumberRange(min=0)])
    e2e_mode                 = SelectField('Chiffrement de bout en bout', choices=[
        ('optional', 'Optionnel — l\'utilisateur choisit'),
        ('disabled', 'Désactivé — option masquée'),
        ('required', 'Obligatoire — forcé pour tous les partages'),
    ])
    maintenance_mode         = BooleanField('Activer le mode maintenance')
    maintenance_message      = TextAreaField('Message de maintenance',
                                             validators=[Optional(), Length(max=512)])
    mfa_required             = BooleanField('2FA obligatoire pour tous les comptes (hors SSO)')
    allow_account_deletion   = BooleanField('Autoriser les utilisateurs à supprimer leur propre compte')
    accent_color             = StringField('Couleur d\'accent', validators=[Optional(), Length(max=7)])
    submit                   = SubmitField('Sauvegarder')


class SSOSettingsForm(FlaskForm):
    sso_enabled       = BooleanField('Activer le SSO (OIDC)')
    sso_force         = BooleanField('Forcer le SSO (désactiver la connexion locale)')
    sso_provider_name = StringField('Nom du fournisseur',
                                    validators=[Optional(), Length(max=64)])
    sso_discovery_url = StringField('Discovery URL',
                                    validators=[Optional(), Length(max=512)])
    sso_client_id     = StringField('Client ID',
                                    validators=[Optional(), Length(max=256)])
    sso_client_secret = PasswordField('Client Secret (laisser vide pour ne pas changer)',
                                      validators=[Optional(), Length(max=512)])
    submit            = SubmitField('Sauvegarder SSO')


class LegalForm(FlaskForm):
    legal_mentions = TextAreaField('Mentions légales (Markdown)', validators=[Optional()])
    terms_of_use   = TextAreaField('Conditions Générales d\'Utilisation (Markdown)', validators=[Optional()])
    submit         = SubmitField('Sauvegarder')


class S3SettingsForm(FlaskForm):
    storage_backend = SelectField('Backend de stockage', choices=[
        ('local', 'Local (système de fichiers)'),
        ('s3',    'S3 (AWS, MinIO, Cloudflare R2…)'),
    ])
    s3_bucket       = StringField('Nom du bucket', validators=[Optional(), Length(max=128)])
    s3_region       = StringField('Région AWS (ex: eu-west-3)', validators=[Optional(), Length(max=64)])
    s3_endpoint_url = StringField('Endpoint URL (vide = AWS par défaut)',
                                  validators=[Optional(), Length(max=512)])
    s3_access_key   = StringField('Access Key ID', validators=[Optional(), Length(max=256)])
    s3_secret_key   = PasswordField('Secret Access Key (laisser vide pour ne pas changer)',
                                    validators=[Optional(), Length(max=512)])
    s3_prefix       = StringField('Préfixe (dossier dans le bucket)',
                                  validators=[Optional(), Length(max=256)])
    submit          = SubmitField('Sauvegarder le stockage')


# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                username   TEXT UNIQUE NOT NULL,
                password   TEXT NOT NULL,
                drop_token TEXT UNIQUE NOT NULL,
                is_admin   INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id                TEXT PRIMARY KEY,
                filename          TEXT,
                original_filename TEXT,
                expiry            TIMESTAMP,
                views             INTEGER DEFAULT 0,
                max_downloads     TEXT,
                password          TEXT
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id    INTEGER,
                username   TEXT,
                action     TEXT NOT NULL,
                target     TEXT,
                details    TEXT,
                ip_address TEXT
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs (timestamp DESC)')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS bundles (
                id         TEXT PRIMARY KEY,
                file_ids   TEXT NOT NULL,
                owner_id   INTEGER,
                password   TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS drop_tokens (
                id              TEXT PRIMARY KEY,
                owner_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                label           TEXT    DEFAULT '',
                expiry          TIMESTAMP NOT NULL,
                max_files       INTEGER DEFAULT 1,
                files_deposited INTEGER DEFAULT 0,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # ── Migrations ────────────────────────────────────────────────────────
        existing_files = {r[1] for r in conn.execute('PRAGMA table_info(files)')}
        for col, ddl in [('owner_id', 'INTEGER REFERENCES users(id)'),
                         ('deposited_by', 'TEXT')]:
            if col not in existing_files:
                conn.execute(f'ALTER TABLE files ADD COLUMN {col} {ddl}')

        existing_users = {r[1] for r in conn.execute('PRAGMA table_info(users)')}
        for col, ddl in [
            ('is_admin',               'INTEGER DEFAULT 0'),
            ('totp_secret',            'TEXT'),
            ('webauthn_credential_id', 'TEXT'),
            ('webauthn_public_key',    'TEXT'),
            ('webauthn_sign_count',    'INTEGER DEFAULT 0'),
            ('webauthn_label',         'TEXT'),
            ('theme',                  "TEXT DEFAULT 'light'"),
            ('avatar_color',           "TEXT DEFAULT '#4361ee'"),
            ('drop_enabled',           'INTEGER DEFAULT 1'),
            ('sso_user',               'INTEGER DEFAULT 0'),
            ('failed_attempts',        'INTEGER DEFAULT 0'),
            ('locked_until',           'TEXT'),
            ('totp_backup_codes',      'TEXT'),
            ('reset_token_hash',       'TEXT'),
            ('reset_token_expiry',     'TEXT'),
        ]:
            if col not in existing_users:
                conn.execute(f'ALTER TABLE users ADD COLUMN {col} {ddl}')


@app.before_request
def before_request():
    g.csp_nonce = secrets.token_urlsafe(16)
    g.db = get_db()
    if request.path.startswith('/static'):
        return
    settings = get_settings()

    # ── Mode maintenance ──────────────────────────────────────────────────────
    if settings.get('maintenance_mode') == '1':
        if not (current_user.is_authenticated and current_user.is_admin):
            _exempt_maint = ('/admin', '/login', '/logout', '/health',
                             '/auth/sso', '/mfa')
            if not any(request.path.startswith(p) for p in _exempt_maint):
                return render_template(
                    'maintenance.html',
                    message=settings.get('maintenance_message', ''),
                    settings=settings,
                ), 503

    # ── 2FA obligatoire ───────────────────────────────────────────────────────
    if (settings.get('mfa_required') == '1'
            and current_user.is_authenticated
            and not current_user.sso_user
            and not current_user.has_mfa):
        _exempt_mfa = ('/profile', '/mfa', '/logout', '/admin', '/health', '/auth/sso')
        if not any(request.path.startswith(p) for p in _exempt_mfa):
            flash('La double authentification (2FA) est obligatoire. '
                  'Veuillez l\'activer sur votre profil.', 'warning')
            return redirect(url_for('profile'))


@app.after_request
def set_security_headers(response):
    # /preview/ doit pouvoir s'afficher dans une iframe same-origin (aperçu PDF/vidéo)
    is_preview     = request.path.startswith('/preview/')
    frame_ancestors = "'self'" if is_preview else "'none'"
    nonce = g.get('csp_nonce', secrets.token_urlsafe(16))
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        f"frame-ancestors {frame_ancestors}; "
        "object-src 'none'; "
        "base-uri 'self';"
    )
    response.headers['Content-Security-Policy']   = csp
    response.headers['X-Frame-Options']           = 'SAMEORIGIN' if is_preview else 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']        = 'camera=(), microphone=(), geolocation=()'
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    return response


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


# ── Journal d'audit ───────────────────────────────────────────────────────────
def _anonymize_ip(ip: str) -> str:
    """Anonymise l'adresse IP pour conformité RGPD.
    IPv4 : masque le dernier octet  (192.168.1.42  → 192.168.1.x)
    IPv6 : masque les 64 derniers bits (2001:db8::1 → 2001:db8::x)
    """
    if not ip:
        return None
    if ':' in ip:
        parts = ip.split(':')
        return ':'.join(parts[:4]) + '::x'
    parts = ip.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3]) + '.x'
    return None


def audit_log(action: str, target: str = None, details: str = None):
    uid   = current_user.id       if current_user.is_authenticated else None
    uname = current_user.username if current_user.is_authenticated else None
    ip    = _anonymize_ip(request.remote_addr)
    try:
        g.db.execute(
            'INSERT INTO audit_logs (user_id, username, action, target, details, ip_address)'
            ' VALUES (?, ?, ?, ?, ?, ?)',
            (uid, uname, action, target, details, ip),
        )
        g.db.commit()
    except Exception as exc:
        app.logger.error("audit_log failed: %s", exc)


def _system_audit_log(action: str, details: str = None):
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute(
                'INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)',
                ('system', action, details),
            )
    except Exception as exc:
        app.logger.error("_system_audit_log failed: %s", exc)


# ── Nettoyage automatique ─────────────────────────────────────────────────────
def cleanup_expired_files():
    now = str(datetime.now())
    deleted = errors = 0
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            expired = conn.execute('SELECT id FROM files WHERE expiry < ?', (now,)).fetchall()
            for (fid,) in expired:
                if storage_delete(fid):
                    deleted += 1
                else:
                    errors += 1
            conn.execute('DELETE FROM files WHERE expiry < ?', (now,))
    except Exception:
        return
    if deleted or errors:
        detail = f"{deleted} fichier(s) supprimé(s)"
        if errors:
            detail += f", {errors} erreur(s)"
        _system_audit_log('cleanup', detail)


def purge_old_audit_logs():
    """Supprime les logs d'audit plus anciens que audit_log_retention_days jours (0 = pas de purge)."""
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('PRAGMA journal_mode=WAL')
            row = conn.execute("SELECT value FROM settings WHERE key='audit_log_retention_days'").fetchone()
            days = int(row[0]) if row and row[0] else 0
            if days <= 0:
                return
            cutoff = str(datetime.now() - timedelta(days=days))
            result = conn.execute('DELETE FROM audit_logs WHERE timestamp < ?', (cutoff,))
            if result.rowcount:
                conn.execute(
                    'INSERT INTO audit_logs (username, action, details) VALUES (?, ?, ?)',
                    ('system', 'cleanup', f'{result.rowcount} log(s) purgé(s) (rétention {days}j)'),
                )
    except Exception as exc:
        app.logger.error("purge_old_audit_logs failed: %s", exc)


_scheduler = BackgroundScheduler(daemon=True)
_scheduler.add_job(cleanup_expired_files, 'interval', hours=1, id='cleanup',
                   next_run_time=datetime.now() + timedelta(minutes=1))
_scheduler.add_job(purge_old_audit_logs, 'interval', hours=24, id='purge_logs',
                   next_run_time=datetime.now() + timedelta(minutes=2))
_scheduler.start()


# ── Helpers ───────────────────────────────────────────────────────────────────
def get_settings():
    rows = g.db.execute('SELECT key, value FROM settings').fetchall()
    s = dict(SETTINGS_DEFAULTS)
    s.update({r[0]: r[1] for r in rows})
    s['blocked_ext_set'] = {e.strip().lower() for e in s['blocked_extensions'].split(',') if e.strip()}
    return s


def allowed_file(filename):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    s = get_settings()
    return ext not in s.get('blocked_ext_set', set())


def get_expiry_time(expiry_option):
    deltas = {'3h': timedelta(hours=3), '1d': timedelta(days=1),
              '1w': timedelta(weeks=1),  '1m': timedelta(days=30)}
    return datetime.now() + deltas.get(expiry_option, timedelta(days=1))


def _parse_expiry(expiry_str):
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.strptime(expiry_str, fmt)
        except ValueError:
            continue
    raise ValueError(f"Format d'expiration inconnu : {expiry_str}")


def _require_uuid(file_id: str) -> None:
    try:
        uuid.UUID(file_id)
    except ValueError:
        abort(400)


def _remove_file(file_id: str) -> bool:
    return storage_delete(file_id)


# ── Routes principales ────────────────────────────────────────────────────────
@app.route('/health')
def health():
    return '', 200


@app.route('/')
@login_required
def index():
    return render_template('index.html', form=FileUploadForm(), settings=get_settings())


@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("30 per hour")
def upload_file():
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return {'success': False, 'message': 'Fichier absent ou type non autorisé.'}

    settings = get_settings()

    file.seek(0, 2)
    size_bytes = file.tell()
    file.seek(0)
    max_bytes = int(settings['max_file_size_mb']) * 1024 * 1024
    if size_bytes > max_bytes:
        return {'success': False,
                'message': f"Fichier trop grand (max {settings['max_file_size_mb']} Mo)."}

    max_files = int(settings['max_files_per_user'])
    if max_files > 0:
        count = g.db.execute(
            'SELECT COUNT(*) FROM files WHERE owner_id = ?', (current_user.id,)
        ).fetchone()[0]
        if count >= max_files:
            return {'success': False,
                    'message': f"Quota atteint ({max_files} fichiers maximum)."}

    max_storage = int(settings['max_storage_mb'])
    if max_storage > 0:
        file_ids = g.db.execute(
            'SELECT id FROM files WHERE owner_id = ?', (current_user.id,)
        ).fetchall()
        used = sum(storage_get_size(fid) for (fid,) in file_ids)
        if used + size_bytes > max_storage * 1024 * 1024:
            _s_unit = settings.get('max_storage_unit', 'mo')
            _s_disp = max_storage // 1024 if _s_unit == 'go' else max_storage
            _s_label = 'Go' if _s_unit == 'go' else 'Mo'
            return {'success': False,
                    'message': f"Quota de stockage dépassé ({_s_disp} {_s_label} maximum)."}

    file_id      = str(uuid.uuid4())
    expiry_str   = request.form.get('expiry', settings['default_expiry'])
    if expiry_str == 'custom':
        custom_val = request.form.get('expiry_custom', '').strip()
        try:
            expiry_time = datetime.strptime(custom_val, '%Y-%m-%dT%H:%M')
        except ValueError:
            return {'success': False, 'message': 'Format de date personnalisée invalide.'}
        if expiry_time <= datetime.now():
            return {'success': False, 'message': 'La date d\'expiration doit être dans le futur.'}
        if expiry_time > datetime.now() + timedelta(days=365):
            return {'success': False, 'message': 'La date d\'expiration ne peut pas dépasser 1 an.'}
    else:
        expiry_time = get_expiry_time(expiry_str)
    max_downloads = request.form.get('max_downloads', 'unlimited')
    if max_downloads != 'unlimited':
        try:
            max_dl_int = int(max_downloads)
            if max_dl_int < 1:
                return {'success': False, 'message': 'Le nombre de téléchargements doit être ≥ 1.'}
            max_downloads = str(max_dl_int)
        except ValueError:
            return {'success': False, 'message': 'Nombre de téléchargements invalide.'}
    password        = request.form.get('password', '')
    hashed_password = generate_password_hash(password) if password else None

    try:
        raw_data = file.read()
        safe, threat = _clamav_scan(raw_data)
        if not safe:
            audit_log('upload_blocked', details=f"{file.filename} - menace : {threat}")
            return {'success': False, 'message': f'Fichier refusé : menace détectée ({threat}).'}
        storage_write(file_id, _encrypt(raw_data))
    except Exception as exc:
        app.logger.error("Erreur écriture fichier %s : %s", file_id, exc)
        return {'success': False, 'message': 'Erreur interne lors de l\'enregistrement.'}

    g.db.execute(
        'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password, owner_id)'
        ' VALUES (?, ?, ?, ?, ?, ?, ?)',
        (file_id, file_id, secure_filename(file.filename), expiry_time, max_downloads, hashed_password, current_user.id),
    )
    g.db.commit()

    size_kb = round(size_bytes / 1024, 1)
    audit_log('upload', target=file_id,
              details=f"{file.filename} ({size_kb} Ko)")

    return {'success': True, 'link': url_for('download_file', file_id=file_id, _external=True)}


@app.route('/download/<file_id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def download_file(file_id):
    _require_uuid(file_id)
    form = PasswordForm()
    cur  = g.db.execute(
        'SELECT filename, original_filename, expiry, views, max_downloads, password FROM files WHERE id = ?',
        (file_id,),
    )
    row = cur.fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    filename, original_filename, expiry, views, max_downloads, hashed_password = row
    expiry_time = _parse_expiry(expiry)

    if datetime.now() > expiry_time:
        _remove_file(file_id)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
        return redirect(url_for('file_expired'))

    if max_downloads != 'unlimited':
        remaining = int(max_downloads) - views
        if remaining <= 0:
            _remove_file(file_id)
            g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            g.db.commit()
            return redirect(url_for('file_not_found'))
    else:
        remaining = 'Illimité'

    if form.validate_on_submit():
        if hashed_password and not check_password_hash(hashed_password, form.password.data):
            flash('Mot de passe incorrect.', 'danger')
            return render_template('password_required.html', file_id=file_id,
                                   form=form, settings=get_settings())
        if hashed_password:
            session[f'auth_{file_id}'] = datetime.now().timestamp()

    if hashed_password and request.method == 'GET':
        auth_ts = session.get(f'auth_{file_id}')
        if not auth_ts or (datetime.now().timestamp() - auth_ts) > 3600:
            session.pop(f'auth_{file_id}', None)
            return render_template('password_required.html', file_id=file_id,
                                   form=form, settings=get_settings())

    return render_template('download.html',
                           file_id=file_id,
                           original_filename=original_filename,
                           expiry_time=expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
                           remaining_downloads=remaining,
                           settings=get_settings())


@app.route('/download_direct/<file_id>')
def download_direct(file_id):
    _require_uuid(file_id)
    cur = g.db.execute(
        'SELECT original_filename, expiry, views, max_downloads, password, owner_id FROM files WHERE id = ?',
        (file_id,),
    )
    row = cur.fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    original_filename, expiry, views, max_downloads, hashed_password, owner_id = row

    # Un utilisateur authentifié ne peut accéder qu'à ses propres fichiers
    if owner_id and current_user.is_authenticated:
        if current_user.id != owner_id and not current_user.is_admin:
            abort(403)
    expiry_time = _parse_expiry(expiry)

    if datetime.now() > expiry_time:
        _remove_file(file_id)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
        return redirect(url_for('file_expired'))

    if max_downloads != 'unlimited' and int(max_downloads) - views <= 0:
        _remove_file(file_id)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
        return redirect(url_for('file_not_found'))

    if hashed_password:
        auth_ts = session.get(f'auth_{file_id}')
        if not auth_ts or (datetime.now().timestamp() - auth_ts) > 3600:
            session.pop(f'auth_{file_id}', None)
            return redirect(url_for('download_file', file_id=file_id))

    g.db.execute('UPDATE files SET views = views + 1 WHERE id = ?', (file_id,))
    g.db.commit()
    audit_log('download', target=file_id, details=original_filename)

    try:
        raw = storage_read(file_id)
    except Exception:
        return redirect(url_for('file_not_found'))

    try:
        data = _decrypt(raw)
    except InvalidToken:
        return redirect(url_for('file_not_found'))
    return send_file(io.BytesIO(data), as_attachment=True, download_name=original_filename)


@app.route('/preview/<file_id>')
def preview_file(file_id):
    """Sert le fichier inline pour l'aperçu (ne compte pas comme téléchargement)."""
    _require_uuid(file_id)
    cur = g.db.execute(
        'SELECT original_filename, expiry, views, max_downloads, password, owner_id FROM files WHERE id = ?',
        (file_id,),
    )
    row = cur.fetchone()
    if not row:
        abort(404)

    original_filename, expiry, views, max_downloads, hashed_password, owner_id = row

    # Un utilisateur authentifié ne peut accéder qu'à ses propres fichiers
    if owner_id and current_user.is_authenticated:
        if current_user.id != owner_id and not current_user.is_admin:
            abort(403)
    expiry_time = _parse_expiry(expiry)

    if datetime.now() > expiry_time:
        abort(410)

    if max_downloads != 'unlimited' and int(max_downloads) - views <= 0:
        abort(410)

    if hashed_password:
        auth_ts = session.get(f'auth_{file_id}')
        if not auth_ts or (datetime.now().timestamp() - auth_ts) > 3600:
            abort(403)

    try:
        raw = storage_read(file_id)
    except Exception:
        abort(404)

    try:
        data = _decrypt(raw)
    except InvalidToken:
        abort(404)
    mime_type, _ = mimetypes.guess_type(original_filename)
    return send_file(
        io.BytesIO(data),
        mimetype=mime_type or 'application/octet-stream',
        as_attachment=False,
        download_name=original_filename,
    )


# ── Bundles (archives ZIP multi-fichiers) ─────────────────────────────────────
@app.route('/bundle/create', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def bundle_create():
    data = request.get_json(silent=True) or {}
    file_ids = data.get('file_ids', [])
    if not isinstance(file_ids, list) or len(file_ids) < 2:
        return jsonify({'success': False, 'message': 'Au moins 2 fichiers requis.'})

    hashed_password = None
    for fid in file_ids:
        row = g.db.execute(
            'SELECT id, password FROM files WHERE id = ? AND owner_id = ?',
            (fid, current_user.id),
        ).fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'Fichier introuvable.'})
        if hashed_password is None:
            hashed_password = row[1]

    bundle_id = str(uuid.uuid4())
    g.db.execute(
        'INSERT INTO bundles (id, file_ids, owner_id, password) VALUES (?, ?, ?, ?)',
        (bundle_id, json.dumps(file_ids), current_user.id, hashed_password),
    )
    g.db.commit()
    audit_log('bundle_create', target=bundle_id, details=f'{len(file_ids)} fichiers')
    return jsonify({'success': True, 'link': url_for('bundle_download', bundle_id=bundle_id, _external=True)})


@app.route('/bundle/<bundle_id>', methods=['GET', 'POST'])
def bundle_download(bundle_id):
    _require_uuid(bundle_id)
    row = g.db.execute(
        'SELECT file_ids, password FROM bundles WHERE id = ?', (bundle_id,)
    ).fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    file_ids_json, hashed_password = row
    try:
        file_ids = json.loads(file_ids_json)
    except (ValueError, TypeError):
        return redirect(url_for('file_not_found'))

    valid_files = []
    earliest_expiry = None
    for fid in file_ids:
        frow = g.db.execute(
            'SELECT original_filename, expiry, views, max_downloads FROM files WHERE id = ?', (fid,)
        ).fetchone()
        if not frow:
            continue
        fname, expiry, views, max_downloads = frow
        expiry_time = _parse_expiry(expiry)
        if datetime.now() > expiry_time:
            continue
        if max_downloads != 'unlimited' and int(max_downloads) - views <= 0:
            continue
        valid_files.append(fname)
        if earliest_expiry is None or expiry_time < earliest_expiry:
            earliest_expiry = expiry_time

    if not valid_files:
        return redirect(url_for('file_expired'))

    form = PasswordForm()
    if form.validate_on_submit():
        if hashed_password and not check_password_hash(hashed_password, form.password.data):
            flash('Mot de passe incorrect.', 'danger')
            return render_template('bundle.html',
                                   bundle_id=bundle_id, form=form, needs_password=True,
                                   file_count=len(valid_files),
                                   expiry_time=earliest_expiry.strftime('%Y-%m-%d %H:%M:%S'),
                                   settings=get_settings())
        if hashed_password:
            session[f'auth_bundle_{bundle_id}'] = datetime.now().timestamp()

    if hashed_password and request.method == 'GET':
        auth_ts = session.get(f'auth_bundle_{bundle_id}')
        if not auth_ts or (datetime.now().timestamp() - auth_ts) > 3600:
            session.pop(f'auth_bundle_{bundle_id}', None)
            return render_template('bundle.html',
                                   bundle_id=bundle_id, form=form, needs_password=True,
                                   file_count=len(valid_files),
                                   expiry_time=earliest_expiry.strftime('%Y-%m-%d %H:%M:%S'),
                                   settings=get_settings())

    return render_template('bundle.html',
                           bundle_id=bundle_id, form=None, needs_password=False,
                           file_count=len(valid_files),
                           file_names=valid_files,
                           expiry_time=earliest_expiry.strftime('%Y-%m-%d %H:%M:%S'),
                           settings=get_settings())


@app.route('/bundle/<bundle_id>/zip')
def bundle_zip(bundle_id):
    _require_uuid(bundle_id)
    row = g.db.execute(
        'SELECT file_ids, password FROM bundles WHERE id = ?', (bundle_id,)
    ).fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    file_ids_json, hashed_password = row
    try:
        file_ids = json.loads(file_ids_json)
    except (ValueError, TypeError):
        return redirect(url_for('file_not_found'))

    if hashed_password:
        auth_ts = session.get(f'auth_bundle_{bundle_id}')
        if not auth_ts or (datetime.now().timestamp() - auth_ts) > 3600:
            session.pop(f'auth_bundle_{bundle_id}', None)
            return redirect(url_for('bundle_download', bundle_id=bundle_id))

    buf = io.BytesIO()
    added = 0
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fid in file_ids:
            frow = g.db.execute(
                'SELECT original_filename, expiry, views, max_downloads FROM files WHERE id = ?', (fid,)
            ).fetchone()
            if not frow:
                continue
            fname, expiry, views, max_downloads = frow
            expiry_time = _parse_expiry(expiry)
            if datetime.now() > expiry_time:
                continue
            if max_downloads != 'unlimited' and int(max_downloads) - views <= 0:
                continue
            try:
                raw = storage_read(fid)
                zf.writestr(fname, _decrypt(raw))
            except Exception:
                continue
            g.db.execute('UPDATE files SET views = views + 1 WHERE id = ?', (fid,))
            added += 1

    if added == 0:
        return redirect(url_for('file_expired'))

    g.db.commit()
    audit_log('bundle_download', target=bundle_id, details=f'{added} fichiers')
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name='archive.zip', mimetype='application/zip')


# ── Authentification ──────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    settings = get_settings()
    if settings.get('sso_force') == '1':
        return redirect(url_for('sso_login'))
    if settings['allow_registration'] == '0':
        flash("Les inscriptions sont désactivées.", 'warning')
        return redirect(url_for('login'))
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            user_count = g.db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            is_admin   = 1 if user_count == 0 else 0
            g.db.execute(
                'INSERT INTO users (username, password, drop_token, is_admin) VALUES (?, ?, ?, ?)',
                (form.username.data.strip(), generate_password_hash(form.password.data),
                 str(uuid.uuid4()), is_admin),
            )
            g.db.commit()
            audit_log('register', details=form.username.data.strip())
            flash('Compte créé ! Vous pouvez vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur est déjà pris.", 'danger')
    return render_template('register.html', form=form, settings=settings)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    settings = get_settings()
    # Mode SSO forcé : rediriger directement vers le fournisseur OIDC.
    # Le paramètre ?sso_error=1 est positionné par sso_callback() en cas d'échec
    # pour éviter une boucle infinie de redirections.
    if (settings.get('sso_enabled') == '1'
            and settings.get('sso_force') == '1'
            and not request.args.get('sso_error')):
        return redirect(url_for('sso_login'))
    form = LoginForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        user  = _load_user_by('username', uname)

        # ── Vérification du verrou de compte ─────────────────────────────────
        if user:
            lock_row = g.db.execute(
                'SELECT failed_attempts, locked_until FROM users WHERE id = ?',
                (user.id,)
            ).fetchone()
            if lock_row and lock_row[1]:
                try:
                    lock_time = _parse_expiry(lock_row[1])
                    if datetime.now() < lock_time:
                        remaining = max(1, int((lock_time - datetime.now()).total_seconds() / 60) + 1)
                        audit_log('login_blocked', target=uname)
                        flash(f'Compte verrouillé. Réessayez dans {remaining} minute(s).', 'danger')
                        return render_template('login.html', form=form, settings=settings)
                except ValueError:
                    pass  # date corrompue, on laisse passer

        if user and check_password_hash(user.password, form.password.data):
            # Réinitialiser le compteur d'échecs
            g.db.execute(
                'UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?',
                (user.id,)
            )
            g.db.commit()
            # MFA check
            if user.has_mfa:
                session['_mfa_user_id'] = user.id
                session['_mfa_methods'] = []
                if user.has_totp:
                    session['_mfa_methods'].append('totp')
                if user.has_webauthn:
                    session['_mfa_methods'].append('webauthn')
                return redirect(url_for('mfa_verify'))
            session.clear()
            login_user(user)
            audit_log('login')
            next_url = request.args.get('next', '')
            return redirect(next_url if next_url and next_url.startswith('/') and not next_url.startswith('//') else url_for('dashboard'))

        # ── Échec : incrémenter le compteur ──────────────────────────────────
        if user:
            attempts = (lock_row[0] or 0) + 1 if lock_row else 1
            if attempts >= LOGIN_MAX_ATTEMPTS:
                locked_until = (datetime.now() + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
                                ).strftime('%Y-%m-%d %H:%M:%S')
                g.db.execute(
                    'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?',
                    (attempts, locked_until, user.id)
                )
                g.db.commit()
                audit_log('login_locked', target=uname,
                          details=f'Verrou {LOGIN_LOCKOUT_MINUTES} min après {attempts} échecs')
                flash(f'Compte verrouillé pendant {LOGIN_LOCKOUT_MINUTES} minutes '
                      f'après trop de tentatives.', 'danger')
                return render_template('login.html', form=form, settings=settings)
            g.db.execute(
                'UPDATE users SET failed_attempts = ? WHERE id = ?',
                (attempts, user.id)
            )
            g.db.commit()
        audit_log('login_failed', target=uname)
        flash('Identifiants incorrects.', 'danger')
    return render_template('login.html', form=form, settings=settings)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    row = g.db.execute(
        'SELECT id, username, reset_token_expiry FROM users WHERE reset_token_hash = ?',
        (token_hash,),
    ).fetchone()
    if not row:
        flash("Lien invalide ou déjà utilisé.", 'danger')
        return redirect(url_for('login'))
    user_id, username, expiry_str = row
    if datetime.utcnow() > datetime.fromisoformat(expiry_str):
        g.db.execute('UPDATE users SET reset_token_hash = NULL, reset_token_expiry = NULL WHERE id = ?', (user_id,))
        g.db.commit()
        flash("Ce lien a expiré. Demandez un nouveau lien à l'administrateur.", 'danger')
        return redirect(url_for('login'))
    form = SetPasswordForm()
    if form.validate_on_submit():
        g.db.execute(
            'UPDATE users SET password = ?, reset_token_hash = NULL, reset_token_expiry = NULL WHERE id = ?',
            (generate_password_hash(form.password.data), user_id),
        )
        g.db.commit()
        audit_log('reset_password', target=username, details='Mot de passe réinitialisé via lien admin')
        flash("Mot de passe modifié. Vous pouvez vous connecter.", 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, username=username, settings=get_settings())


@app.route('/logout')
@login_required
def logout():
    audit_log('logout')
    logout_user()
    return redirect(url_for('login'))


# ── MFA verification (after password login) ──────────────────────────────────
def _get_mfa_user():
    uid = session.get('_mfa_user_id')
    if not uid:
        return None
    return _load_user_by('id', uid)


@app.route('/mfa', methods=['GET'])
def mfa_verify():
    user = _get_mfa_user()
    if not user:
        return redirect(url_for('login'))
    methods = session.get('_mfa_methods', [])
    return render_template('mfa.html', methods=methods, settings=get_settings(),
                           webauthn_available=WEBAUTHN_AVAILABLE)


@app.route('/mfa/totp', methods=['POST'])
@limiter.limit("10 per minute")
def mfa_totp_verify():
    user = _get_mfa_user()
    if not user:
        return redirect(url_for('login'))
    code = request.form.get('totp_code', '').strip()
    try:
        secret = _decrypt_secret(user.totp_secret)
    except Exception:
        app.logger.error("Impossible de déchiffrer le secret TOTP pour user %s", user.id)
        flash('Erreur interne MFA. Contactez l\'administrateur.', 'danger')
        return redirect(url_for('mfa_verify'))
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        session.clear()
        login_user(user)
        audit_log('login', details='via TOTP')
        return redirect(url_for('dashboard'))
    audit_log('mfa_failed', target=user.username, details='TOTP invalide')
    flash('Code TOTP invalide.', 'danger')
    return redirect(url_for('mfa_verify'))


@app.route('/mfa/webauthn/begin', methods=['POST'])
@limiter.limit("10 per minute")
def mfa_webauthn_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400
    user = _get_mfa_user()
    if not user or not user.webauthn_credential_id:
        return jsonify({'error': 'Non autorisé'}), 403

    cred_id = base64.b64decode(user.webauthn_credential_id)
    options = generate_authentication_options(
        rp_id=get_rp_id(),
        allow_credentials=[PublicKeyCredentialDescriptor(id=cred_id)],
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    session['_webauthn_auth_challenge'] = base64.b64encode(options.challenge).decode()
    return options_to_json(options), 200, {'Content-Type': 'application/json'}


@app.route('/mfa/webauthn/complete', methods=['POST'])
@limiter.limit("10 per minute")
def mfa_webauthn_complete():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400
    user = _get_mfa_user()
    if not user:
        return jsonify({'error': 'Non autorisé'}), 403

    challenge = base64.b64decode(session.pop('_webauthn_auth_challenge', ''))
    pub_key   = base64.b64decode(user.webauthn_public_key)

    try:
        from webauthn.helpers.structs import (
            AuthenticationCredential, AuthenticatorAssertionResponse)
        from webauthn.helpers import base64url_to_bytes as _b64
        raw = request.get_data()
        data = json.loads(raw)
        resp_data = data['response']
        credential = AuthenticationCredential(
            id=data['id'],
            raw_id=_b64(data['rawId']),
            response=AuthenticatorAssertionResponse(
                client_data_json=_b64(resp_data['clientDataJSON']),
                authenticator_data=_b64(resp_data['authenticatorData']),
                signature=_b64(resp_data['signature']),
                user_handle=_b64(resp_data['userHandle']) if resp_data.get('userHandle') else None,
            ),
        )

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_rp_origin(),
            credential_public_key=pub_key,
            credential_current_sign_count=user.webauthn_sign_count,
        )
        g.db.execute('UPDATE users SET webauthn_sign_count = ? WHERE id = ?',
                     (verification.new_sign_count, user.id))
        g.db.commit()
    except Exception as exc:
        app.logger.error("WebAuthn auth failed: %s", exc)
        audit_log('mfa_failed', target=user.username if user else None, details='WebAuthn invalide')
        return jsonify({'error': 'Échec de la vérification'}), 400

    session.clear()
    login_user(user)
    audit_log('login', details='via WebAuthn')
    return jsonify({'success': True, 'redirect': url_for('dashboard')})


# ── Profil utilisateur ────────────────────────────────────────────────────────
@app.route('/profile')
@login_required
def profile():
    form = ChangePasswordForm()
    backup_remaining = 0
    if current_user.has_totp:
        row = g.db.execute(
            'SELECT totp_backup_codes FROM users WHERE id = ?', (current_user.id,)
        ).fetchone()
        if row and row[0]:
            backup_remaining = len(json.loads(row[0]))
    return render_template('profile.html', form=form, settings=get_settings(),
                           avatar_colors=AVATAR_COLORS,
                           webauthn_available=WEBAUTHN_AVAILABLE,
                           backup_remaining=backup_remaining)


@app.route('/profile/password', methods=['POST'])
@login_required
def profile_change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if not check_password_hash(current_user.password, form.current.data):
            flash('Mot de passe actuel incorrect.', 'danger')
        else:
            g.db.execute('UPDATE users SET password = ? WHERE id = ?',
                         (generate_password_hash(form.password.data), current_user.id))
            g.db.commit()
            audit_log('password_change')
            flash('Mot de passe modifié.', 'success')
    else:
        for field, errors in form.errors.items():
            for err in errors:
                flash(f'{err}', 'danger')
    return redirect(url_for('profile'))


@app.route('/profile/theme', methods=['POST'])
@login_required
def profile_change_theme():
    theme = request.form.get('theme', 'light')
    if theme not in ('light', 'dark'):
        theme = 'light'
    g.db.execute('UPDATE users SET theme = ? WHERE id = ?', (theme, current_user.id))
    g.db.commit()
    return redirect(url_for('profile'))


@app.route('/profile/avatar-color', methods=['POST'])
@login_required
def profile_change_avatar_color():
    color = request.form.get('color', '#4361ee').strip()
    if color not in AVATAR_COLORS:
        color = '#4361ee'
    g.db.execute('UPDATE users SET avatar_color = ? WHERE id = ?', (color, current_user.id))
    g.db.commit()
    return redirect(url_for('profile'))


# ── Profil : TOTP ─────────────────────────────────────────────────────────────
@app.route('/profile/totp/setup', methods=['POST'])
@login_required
def profile_totp_setup():
    secret = pyotp.random_base32()
    session['_totp_setup_secret'] = secret
    settings = get_settings()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username,
        issuer_name=settings.get('app_name', 'FileShareApp'),
    )
    return jsonify({'secret': secret, 'uri': uri})


@app.route('/profile/totp/confirm', methods=['POST'])
@login_required
def profile_totp_confirm():
    secret = session.pop('_totp_setup_secret', None)
    code   = request.form.get('totp_code', '').strip()
    if not secret:
        flash('Session expirée, recommencez.', 'danger')
        return redirect(url_for('profile'))
    if pyotp.TOTP(secret).verify(code, valid_window=1):
        display_codes, hashes_json = _generate_backup_codes()
        g.db.execute(
            'UPDATE users SET totp_secret = ?, totp_backup_codes = ? WHERE id = ?',
            (_encrypt_secret(secret), hashes_json, current_user.id)
        )
        g.db.commit()
        audit_log('totp_enable')
        session['_backup_codes_display'] = display_codes
        return redirect(url_for('profile_totp_backup_show'))
    flash('Code invalide. Réessayez.', 'danger')
    return redirect(url_for('profile'))


@app.route('/profile/totp/disable', methods=['POST'])
@login_required
def profile_totp_disable():
    g.db.execute(
        'UPDATE users SET totp_secret = NULL, totp_backup_codes = NULL WHERE id = ?',
        (current_user.id,)
    )
    g.db.commit()
    audit_log('totp_disable')
    flash('TOTP désactivé.', 'success')
    return redirect(url_for('profile'))


# ── Profil : codes de récupération TOTP ──────────────────────────────────────
@app.route('/profile/totp/backup/show')
@login_required
def profile_totp_backup_show():
    codes = session.pop('_backup_codes_display', None)
    if not codes:
        flash('Aucun code de récupération à afficher.', 'warning')
        return redirect(url_for('profile'))
    return render_template('backup_codes.html', codes=codes, settings=get_settings())


@app.route('/profile/totp/backup/regenerate', methods=['POST'])
@login_required
def profile_totp_backup_regenerate():
    if not current_user.has_totp:
        flash('Activez d\'abord le TOTP pour générer des codes de récupération.', 'warning')
        return redirect(url_for('profile'))
    display_codes, hashes_json = _generate_backup_codes()
    g.db.execute(
        'UPDATE users SET totp_backup_codes = ? WHERE id = ?',
        (hashes_json, current_user.id)
    )
    g.db.commit()
    audit_log('totp_backup_regenerate')
    session['_backup_codes_display'] = display_codes
    return redirect(url_for('profile_totp_backup_show'))


@app.route('/mfa/backup', methods=['POST'])
@limiter.limit("5 per minute")
def mfa_backup_verify():
    user = _get_mfa_user()
    if not user:
        return redirect(url_for('login'))
    submitted = request.form.get('backup_code', '').strip()
    row = get_db().execute(
        'SELECT totp_backup_codes FROM users WHERE id = ?', (user.id,)
    ).fetchone()
    if row and row[0]:
        hashes = json.loads(row[0])
        submitted_hash = _hash_backup_code(submitted)
        for i, h in enumerate(hashes):
            if h == submitted_hash:
                hashes.pop(i)
                g.db.execute(
                    'UPDATE users SET totp_backup_codes = ? WHERE id = ?',
                    (json.dumps(hashes), user.id)
                )
                g.db.commit()
                session.clear()
                login_user(user)
                audit_log('login', details=f'via code de récupération ({len(hashes)} restants)')
                return redirect(url_for('dashboard'))
    audit_log('mfa_failed', target=user.username, details='Code de récupération invalide')
    flash('Code de récupération invalide.', 'danger')
    return redirect(url_for('mfa_verify'))


# ── Profil : WebAuthn ─────────────────────────────────────────────────────────
@app.route('/profile/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=RP_NAME,
        user_id=str(current_user.id).encode(),
        user_name=current_user.username,
        user_display_name=current_user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.DISCOURAGED,
        ),
    )
    session['_webauthn_reg_challenge'] = base64.b64encode(options.challenge).decode()
    return options_to_json(options), 200, {'Content-Type': 'application/json'}


@app.route('/profile/webauthn/register/complete', methods=['POST'])
@login_required
def webauthn_register_complete():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400

    challenge = base64.b64decode(session.pop('_webauthn_reg_challenge', ''))
    try:
        from webauthn.helpers.structs import (
            RegistrationCredential, AuthenticatorAttestationResponse, AuthenticatorTransport)
        from webauthn.helpers import base64url_to_bytes as _b64
        raw = request.get_data()
        data = json.loads(raw)
        resp_data = data['response']
        valid_transports = {e.value for e in AuthenticatorTransport}
        transports = [AuthenticatorTransport(t) for t in resp_data.get('transports', [])
                      if t in valid_transports]
        credential = RegistrationCredential(
            id=data['id'],
            raw_id=_b64(data['rawId']),
            response=AuthenticatorAttestationResponse(
                client_data_json=_b64(resp_data['clientDataJSON']),
                attestation_object=_b64(resp_data['attestationObject']),
                transports=transports or None,
            ),
        )

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=get_rp_id(),
            expected_origin=get_rp_origin(),
        )
    except Exception as exc:
        app.logger.error("WebAuthn registration failed: %s", exc)
        return jsonify({'error': 'Échec de l\'enregistrement'}), 400

    cred_id = base64.b64encode(verification.credential_id).decode()
    pub_key = base64.b64encode(verification.credential_public_key).decode()
    label = (request.json.get('label') or '').strip()[:64] or None
    g.db.execute(
        'UPDATE users SET webauthn_credential_id=?, webauthn_public_key=?, webauthn_sign_count=?, webauthn_label=? WHERE id=?',
        (cred_id, pub_key, verification.sign_count, label, current_user.id),
    )
    g.db.commit()
    audit_log('webauthn_register', details='Clé de sécurité enregistrée')
    return jsonify({'success': True})


@app.route('/profile/webauthn/delete', methods=['POST'])
@login_required
def webauthn_delete():
    g.db.execute(
        'UPDATE users SET webauthn_credential_id=NULL, webauthn_public_key=NULL, webauthn_sign_count=0, webauthn_label=NULL WHERE id=?',
        (current_user.id,),
    )
    g.db.commit()
    audit_log('webauthn_delete', details='Clé de sécurité supprimée')
    flash('Clé de sécurité supprimée.', 'success')
    return redirect(url_for('profile'))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    settings  = get_settings()
    cur = g.db.execute(
        'SELECT id, original_filename, expiry, views, max_downloads, deposited_by'
        ' FROM files WHERE owner_id = ? ORDER BY expiry DESC',
        (current_user.id,),
    )
    now   = datetime.now()
    files = []
    for fid, name, expiry, views, max_dl, dep_by in cur.fetchall():
        exp       = _parse_expiry(expiry)
        expired   = now > exp
        remaining = 'Illimité' if max_dl == 'unlimited' else max(0, int(max_dl) - views)
        files.append({
            'id': fid, 'name': name,
            'expiry': exp.strftime('%d/%m/%Y %H:%M'),
            'expired': expired, 'remaining': remaining,
            'exhausted': remaining == 0, 'deposited_by': dep_by,
            'views': views, 'max_downloads': max_dl,
        })

    # ── Quota stockage + fichiers ─────────────────────────────────────────────
    all_ids    = g.db.execute(
        'SELECT id FROM files WHERE owner_id = ?', (current_user.id,)
    ).fetchall()
    used_bytes = sum(storage_get_size(fid) for (fid,) in all_ids)
    max_storage_mb   = int(settings['max_storage_mb'])
    _s_unit          = settings.get('max_storage_unit', 'mo')
    max_files        = int(settings['max_files_per_user'])
    file_count       = len(all_ids)

    def _fmt_bytes(b):
        if b >= 1024 ** 3:
            return f"{b / 1024 ** 3:.1f} Go"
        if b >= 1024 ** 2:
            return f"{b / 1024 ** 2:.1f} Mo"
        return f"{b / 1024:.0f} Ko"

    if max_storage_mb > 0:
        _s_disp  = max_storage_mb // 1024 if _s_unit == 'go' else max_storage_mb
        _s_label = 'Go' if _s_unit == 'go' else 'Mo'
        _max_str = f"{_s_disp} {_s_label}"
    else:
        _max_str = None

    quota = {
        'used_str':       _fmt_bytes(used_bytes),
        'max_storage_mb': max_storage_mb,
        'max_storage_str': _max_str,
        'storage_pct':    min(100, round(used_bytes * 100 / (max_storage_mb * 1048576)))
                          if max_storage_mb > 0 else None,
        'file_count':     file_count,
        'max_files':      max_files,
        'file_pct':       min(100, round(file_count * 100 / max_files))
                          if max_files > 0 else None,
    }

    # ── Liens de dépôt temporaires ────────────────────────────────────────────
    rows = g.db.execute(
        'SELECT id, label, expiry, max_files, files_deposited '
        'FROM drop_tokens WHERE owner_id = ? ORDER BY created_at DESC',
        (current_user.id,)
    ).fetchall()
    now_dt = datetime.now()
    drop_tokens = []
    for tid, label, expiry_str, max_files, files_dep in rows:
        expiry_dt = _parse_expiry(expiry_str)
        is_expired   = now_dt > expiry_dt
        is_exhausted = (max_files > 0 and files_dep >= max_files)
        drop_tokens.append({
            'id':              tid,
            'label':           label or '(sans nom)',
            'expiry':          expiry_dt.strftime('%d/%m/%Y %H:%M'),
            'expired':         is_expired,
            'exhausted':       is_exhausted,
            'active':          not is_expired and not is_exhausted,
            'max_files':       max_files,
            'files_deposited': files_dep,
            'url':             url_for('drop_zone', drop_token=tid, _external=True),
        })

    return render_template('dashboard.html', files=files, drop_tokens=drop_tokens,
                           settings=settings, quota=quota)


@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    _require_uuid(file_id)
    cur = g.db.execute('SELECT owner_id, original_filename FROM files WHERE id = ?', (file_id,))
    row = cur.fetchone()
    if row and row[0] == current_user.id:
        _remove_file(file_id)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
        audit_log('delete_file', target=file_id, details=row[1])
    return redirect(url_for('dashboard'))


# ── RGPD : export des données personnelles (art. 20) ─────────────────────────
@app.route('/profile/export')
@login_required
def profile_export():
    """Retourne un JSON contenant toutes les données personnelles de l'utilisateur."""
    user_row = g.db.execute(
        'SELECT username, created_at, theme, avatar_color, is_admin, sso_user FROM users WHERE id = ?',
        (current_user.id,)
    ).fetchone()
    files = g.db.execute(
        'SELECT id, original_filename, expiry, views, max_downloads FROM files WHERE owner_id = ?',
        (current_user.id,)
    ).fetchall()
    logs = g.db.execute(
        'SELECT timestamp, action, target, details, ip_address FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC',
        (current_user.id,)
    ).fetchall()
    payload = {
        'export_date': datetime.now().isoformat(),
        'account': {
            'username':    user_row[0],
            'created_at':  user_row[1],
            'theme':       user_row[2],
            'avatar_color': user_row[3],
            'is_admin':    bool(user_row[4]),
            'sso_user':    bool(user_row[5]),
        },
        'files': [
            {'id': r[0], 'filename': r[1], 'expiry': r[2], 'views': r[3], 'max_downloads': r[4]}
            for r in files
        ],
        'audit_logs': [
            {'timestamp': r[0], 'action': r[1], 'target': r[2], 'details': r[3], 'ip_address': r[4]}
            for r in logs
        ],
    }
    audit_log('rgpd_export')
    response = app.response_class(
        response=json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename="mes-donnees-{current_user.username}.json"'}
    )
    return response


# ── RGPD : suppression de compte (art. 17 — droit à l'effacement) ────────────
@app.route('/profile/delete-account', methods=['POST'])
@login_required
def profile_delete_account():
    settings = get_settings()
    if settings.get('allow_account_deletion') != '1':
        abort(403)

    confirm = request.form.get('confirm_word', '').strip().lower()
    if confirm != 'supprimer':
        flash('Confirmation incorrecte. Tapez exactement « supprimer » pour valider.', 'danger')
        return redirect(url_for('profile'))

    uid = current_user.id

    # Suppression des fichiers dans le backend de stockage
    file_ids = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (uid,)).fetchall()
    for (fid,) in file_ids:
        storage_delete(fid)

    # Suppression en base (fichiers, drop_tokens, bundles, puis utilisateur)
    g.db.execute('DELETE FROM files WHERE owner_id = ?', (uid,))
    g.db.execute('DELETE FROM drop_tokens WHERE owner_id = ?', (uid,))
    g.db.execute('DELETE FROM bundles WHERE owner_id = ?', (uid,))
    g.db.execute('DELETE FROM users WHERE id = ?', (uid,))
    g.db.commit()

    audit_log('account_self_deleted', details=f'Compte {current_user.username} auto-supprimé')
    logout_user()
    flash('Votre compte et l\'ensemble de vos données ont été supprimés définitivement.', 'success')
    return redirect(url_for('login'))


# ── Liens de dépôt temporaires ────────────────────────────────────────────────
@app.route('/profile/drop-create', methods=['POST'])
@login_required
def drop_create():
    label     = request.form.get('label', '').strip()[:64]
    duration  = request.form.get('duration', '24h')
    max_files = request.form.get('max_files', '1')

    duration_map = {
        '1h':  timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d':  timedelta(days=7),
        '30d': timedelta(days=30),
    }
    delta  = duration_map.get(duration, timedelta(hours=24))
    expiry = datetime.now() + delta

    try:
        max_files_int = int(max_files)
        if max_files_int not in (1, 3, 5, 10, 0):
            max_files_int = 1
    except ValueError:
        max_files_int = 1

    token_id = str(uuid.uuid4())
    g.db.execute(
        'INSERT INTO drop_tokens (id, owner_id, label, expiry, max_files) VALUES (?, ?, ?, ?, ?)',
        (token_id, current_user.id, label, expiry.strftime('%Y-%m-%d %H:%M:%S'), max_files_int),
    )
    g.db.commit()
    audit_log('drop_create', target=token_id,
              details=f"label={label} expiry={expiry.strftime('%Y-%m-%d %H:%M')} max={max_files_int}")
    return redirect(url_for('dashboard'))


@app.route('/profile/drop-delete/<token_id>', methods=['POST'])
@login_required
def drop_delete(token_id):
    _require_uuid(token_id)
    g.db.execute('DELETE FROM drop_tokens WHERE id = ? AND owner_id = ?',
                 (token_id, current_user.id))
    g.db.commit()
    audit_log('drop_delete', target=token_id)
    return redirect(url_for('dashboard'))


# ── Zone de dépôt ─────────────────────────────────────────────────────────────
@app.route('/drop/<drop_token>', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def drop_zone(drop_token):
    now = datetime.now()
    cur = g.db.execute(
        'SELECT dt.id, dt.owner_id, dt.expiry, dt.max_files, dt.files_deposited, u.username '
        'FROM drop_tokens dt JOIN users u ON u.id = dt.owner_id '
        'WHERE dt.id = ?', (drop_token,)
    )
    row = cur.fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    token_id, recipient_id, expiry_str, max_files, files_deposited, recipient_name = row
    expiry    = _parse_expiry(expiry_str)
    settings  = get_settings()

    if now > expiry:
        return render_template('drop.html', recipient=recipient_name, drop_token=drop_token,
                               success=False, expired=True, exhausted=False,
                               remaining=None, settings=settings)

    if max_files > 0 and files_deposited >= max_files:
        return render_template('drop.html', recipient=recipient_name, drop_token=drop_token,
                               success=False, expired=False, exhausted=True,
                               remaining=0, settings=settings)

    remaining = (max_files - files_deposited) if max_files > 0 else None
    success   = False

    if request.method == 'POST':
        file        = request.files.get('file')
        sender_name = request.form.get('sender_name', '').strip()[:64] or 'Anonyme'
        sender_name = ''.join(c for c in sender_name if c.isprintable() and c not in '<>"&\'')

        if file and allowed_file(file.filename):
            raw_data = file.read()

            # Vérification quota stockage du destinataire
            max_storage_mb = int(settings['max_storage_mb'])
            if max_storage_mb > 0:
                all_ids    = g.db.execute('SELECT id FROM files WHERE owner_id = ?',
                                          (recipient_id,)).fetchall()
                used_bytes = sum(storage_get_size(fid) for (fid,) in all_ids)
                if used_bytes + len(raw_data) > max_storage_mb * 1048576:
                    flash("Le destinataire n'a plus d'espace de stockage disponible.", 'danger')
                    return render_template('drop.html', recipient=recipient_name,
                                           drop_token=drop_token, success=False,
                                           expired=False, exhausted=False,
                                           remaining=remaining, settings=settings)

            # Vérification quota fichiers du destinataire
            max_files_user = int(settings['max_files_per_user'])
            if max_files_user > 0:
                file_count = g.db.execute(
                    'SELECT COUNT(*) FROM files WHERE owner_id = ?', (recipient_id,)
                ).fetchone()[0]
                if file_count >= max_files_user:
                    flash("Le destinataire a atteint son quota de fichiers.", 'danger')
                    return render_template('drop.html', recipient=recipient_name,
                                           drop_token=drop_token, success=False,
                                           expired=False, exhausted=False,
                                           remaining=remaining, settings=settings)

            file_id     = str(uuid.uuid4())
            expiry_time = get_expiry_time(settings['default_expiry'])
            safe, threat = _clamav_scan(raw_data)
            if not safe:
                audit_log('drop_upload_blocked', details=f"{file.filename} - menace : {threat}")
                flash(f'Fichier refusé : menace détectée ({threat}).', 'danger')
                return render_template('drop.html', recipient=recipient_name,
                                       drop_token=drop_token, success=False,
                                       expired=False, exhausted=False,
                                       remaining=remaining, settings=settings)
            try:
                storage_write(file_id, _encrypt(raw_data))
            except Exception:
                flash("Erreur interne lors de l'enregistrement.", 'danger')
                return render_template('drop.html', recipient=recipient_name,
                                       drop_token=drop_token, success=False,
                                       expired=False, exhausted=False,
                                       remaining=remaining, settings=settings)

            g.db.execute(
                'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, owner_id, deposited_by)'
                ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                (file_id, file_id, secure_filename(file.filename), expiry_time,
                 'unlimited', recipient_id, sender_name),
            )
            g.db.execute(
                'UPDATE drop_tokens SET files_deposited = files_deposited + 1 WHERE id = ?',
                (token_id,)
            )
            g.db.commit()
            audit_log('drop_upload', target=file_id,
                      details=f"{file.filename} pour {recipient_name} par {sender_name}")
            success   = True
            remaining = max(0, remaining - 1) if remaining is not None else None
        else:
            flash('Type de fichier non autorisé.', 'danger')

    return render_template('drop.html', recipient=recipient_name, drop_token=drop_token,
                           success=success, expired=False, exhausted=False,
                           remaining=remaining, expiry=expiry.strftime('%d/%m/%Y à %H:%M'),
                           settings=settings)


# ── Statistiques admin ─────────────────────────────────────────────────────────
def _compute_admin_stats():
    from datetime import date as _d, timedelta as _td

    def _months_back(n):
        months, d = [], _d.today().replace(day=1)
        for _ in range(n):
            months.append(d.strftime('%Y-%m'))
            d = (d - _td(days=1)).replace(day=1)
        return list(reversed(months))

    with sqlite3.connect(DATABASE) as conn:
        conn.execute('PRAGMA journal_mode=WAL')

        # ── KPI ──────────────────────────────────────────────────────────────
        total_users    = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        active_files   = conn.execute(
            "SELECT COUNT(*) FROM files WHERE expiry > datetime('now')"
        ).fetchone()[0]
        total_uploads  = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action='upload'"
        ).fetchone()[0]
        total_downloads = conn.execute(
            "SELECT COUNT(*) FROM audit_logs WHERE action IN ('download','bundle_download')"
        ).fetchone()[0]

        # ── Stockage total ───────────────────────────────────────────────────
        storage_bytes = 0
        s_cfg = _get_s3_settings()
        if s_cfg.get('storage_backend') == 's3':
            # Sur S3 : on somme via head_object pour chaque fichier en base
            all_fids = conn.execute('SELECT id FROM files').fetchall()
            for (fid,) in all_fids:
                storage_bytes += storage_get_size(fid)
        else:
            try:
                for fname in os.listdir(UPLOAD_FOLDER):
                    p = os.path.join(UPLOAD_FOLDER, fname)
                    if os.path.isfile(p):
                        storage_bytes += os.path.getsize(p)
            except OSError:
                pass

        # ── Activité des 30 derniers jours ───────────────────────────────────
        today   = _d.today()
        days_30 = [(today - _td(days=i)).isoformat() for i in range(29, -1, -1)]
        rows = conn.execute(
            "SELECT DATE(timestamp), COUNT(*) FROM audit_logs"
            " WHERE action='upload' AND timestamp >= date('now','-29 days')"
            " GROUP BY DATE(timestamp)"
        ).fetchall()
        upl_day = {r[0]: r[1] for r in rows}
        rows = conn.execute(
            "SELECT DATE(timestamp), COUNT(*) FROM audit_logs"
            " WHERE action IN ('download','bundle_download')"
            " AND timestamp >= date('now','-29 days') GROUP BY DATE(timestamp)"
        ).fetchall()
        dl_day = {r[0]: r[1] for r in rows}

        # ── Activité mensuelle (12 mois) ─────────────────────────────────────
        months_12 = _months_back(12)
        rows = conn.execute(
            "SELECT strftime('%Y-%m',timestamp), action, COUNT(*) FROM audit_logs"
            " WHERE action IN ('upload','download','bundle_download')"
            " AND timestamp >= date('now','-365 days')"
            " GROUP BY strftime('%Y-%m',timestamp), action"
        ).fetchall()
        m_upl, m_dl = {}, {}
        for month, action, cnt in rows:
            if action == 'upload':
                m_upl[month] = m_upl.get(month, 0) + cnt
            else:
                m_dl[month]  = m_dl.get(month, 0) + cnt

        # ── Nouveaux comptes par mois (12 mois) ──────────────────────────────
        rows_users = conn.execute(
            "SELECT strftime('%Y-%m',created_at), COUNT(*) FROM users"
            " WHERE created_at >= date('now','-365 days')"
            " GROUP BY strftime('%Y-%m',created_at)"
        ).fetchall()
        m_users = {r[0]: r[1] for r in rows_users}

        # ── Répartition des actions (top 10) ─────────────────────────────────
        rows_actions = conn.execute(
            "SELECT action, COUNT(*) FROM audit_logs"
            " GROUP BY action ORDER BY COUNT(*) DESC LIMIT 10"
        ).fetchall()

    return {
        'kpi': {
            'total_users':     total_users,
            'active_files':    active_files,
            'total_uploads':   total_uploads,
            'total_downloads': total_downloads,
            'storage_bytes':   storage_bytes,
        },
        'daily': {
            'labels':    [d[5:] for d in days_30],
            'uploads':   [upl_day.get(d, 0) for d in days_30],
            'downloads': [dl_day.get(d, 0)  for d in days_30],
        },
        'monthly': {
            'labels':    months_12,
            'uploads':   [m_upl.get(m, 0)   for m in months_12],
            'downloads': [m_dl.get(m, 0)    for m in months_12],
            'users':     [m_users.get(m, 0) for m in months_12],
        },
        'actions': {
            'labels': [r[0] for r in rows_actions],
            'counts': [r[1] for r in rows_actions],
        },
    }


# ── Branding : logo et CSS dynamique ─────────────────────────────────────────
@app.route('/logo')
def logo():
    if not os.path.exists(LOGO_PATH):
        abort(404)
    ct = get_settings().get('logo_content_type', 'image/png')
    return send_file(LOGO_PATH, mimetype=ct)


@app.route('/branding.css')
def branding_css():
    accent = get_settings().get('accent_color', '#4361ee')
    if not re.match(r'^#[0-9a-fA-F]{6}$', accent):
        accent = '#4361ee'
    dark = _darken_hex(accent)
    h = accent.lstrip('#')
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    css = f"""\
:root {{
  --accent: {accent};
  --accent-dark: {dark};
  --accent-rgb: {r},{g},{b};
}}
.btn-primary {{
  background-color: var(--accent) !important;
  border-color: var(--accent) !important;
}}
.btn-primary:hover, .btn-primary:focus, .btn-primary:active {{
  background-color: var(--accent-dark) !important;
  border-color: var(--accent-dark) !important;
}}
.btn-outline-primary {{
  color: var(--accent) !important;
  border-color: var(--accent) !important;
}}
.btn-outline-primary:hover {{
  background-color: var(--accent) !important;
  border-color: var(--accent) !important;
  color: #fff !important;
}}
.text-primary {{ color: var(--accent) !important; }}
a:not(.btn):not(.nav-link):not(.navbar-brand):not(.dropdown-item):not([class*="text-"]):not(.user-avatar) {{
  color: var(--accent);
}}
.user-avatar {{ color: #fff !important; }}
.progress-bar, #upload-progress-bar {{ background-color: var(--accent) !important; }}
.badge.bg-primary {{ background-color: var(--accent) !important; }}
.nav-tabs .nav-link.active {{ color: var(--accent) !important; border-bottom-color: var(--accent) !important; }}
.form-check-input:checked {{
  background-color: var(--accent) !important;
  border-color: var(--accent) !important;
}}
.avatar-circle {{ background-color: var(--accent) !important; color: #fff !important; }}
"""
    resp = app.response_class(css, mimetype='text/css')
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return resp


# ── Pages légales ─────────────────────────────────────────────────────────────
_LEGAL_ALLOWED_TAGS = {
    'p', 'br', 'strong', 'em', 'u', 'b', 'i', 's',
    'h1', 'h2', 'h3', 'h4', 'ul', 'ol', 'li',
    'a', 'blockquote', 'hr', 'span', 'div',
}
_LEGAL_ALLOWED_ATTRS = {
    'a': {'href', 'title', 'target'},   # 'rel' géré par link_rel= de nh3
    'span': {'class'},
    'div': {'class'},
}

_md_parser = mistune.create_markdown()


def _sanitize_legal(md: str) -> str:
    """Convertit le Markdown en HTML, puis sanitise avec une whitelist stricte."""
    html = _md_parser(md)
    return nh3.clean(
        html,
        tags=_LEGAL_ALLOWED_TAGS,
        attributes=_LEGAL_ALLOWED_ATTRS,
        link_rel='noopener noreferrer',
    )


@app.route('/mentions-legales')
def mentions_legales():
    s = get_settings()
    content = s.get('legal_mentions') or _DEFAULT_LEGAL_MENTIONS
    content = content.replace('{contact_email}', s.get('contact_email', '')) \
                     .replace('{app_name}', s.get('app_name', ''))
    return render_template('legal.html', title='Mentions légales',
                           content=_sanitize_legal(content), settings=s)


@app.route('/cgu')
def cgu():
    from datetime import date as _date
    s = get_settings()
    content = s.get('terms_of_use') or _DEFAULT_TERMS_OF_USE
    content = content.replace('{contact_email}', s.get('contact_email', '')) \
                     .replace('{app_name}', s.get('app_name', '')) \
                     .replace('{date}', _date.today().strftime('%d/%m/%Y'))
    return render_template('legal.html', title='Conditions Générales d\'Utilisation',
                           content=_sanitize_legal(content), settings=s)


# ── Administration ────────────────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    rows = g.db.execute('''
        SELECT u.id, u.username, u.created_at, u.is_admin, u.sso_user, COUNT(f.id) AS file_count
        FROM users u LEFT JOIN files f ON f.owner_id = u.id
        GROUP BY u.id ORDER BY u.created_at
    ''').fetchall()

    users = []
    for uid, username, created_at, is_admin, sso_user, file_count in rows:
        file_ids = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (uid,)).fetchall()
        used = sum(storage_get_size(fid) for (fid,) in file_ids)
        users.append({
            'id': uid, 'username': username, 'created_at': created_at,
            'is_admin': bool(is_admin), 'sso_user': bool(sso_user),
            'file_count': file_count,
            'storage_mb': round(used / (1024 * 1024), 2),
        })

    log_rows = g.db.execute('''
        SELECT id, timestamp, username, action, target, details, ip_address
        FROM audit_logs ORDER BY id DESC LIMIT 300
    ''').fetchall()
    logs = [
        {'id': r[0], 'timestamp': r[1], 'username': r[2] or 'system',
         'action': r[3], 'target': r[4], 'details': r[5], 'ip': r[6]}
        for r in log_rows
    ]

    settings = get_settings()
    _unit = settings.get('max_file_size_unit', 'mo')
    _mb   = int(settings['max_file_size_mb'])
    _display_val = _mb // 1024 if _unit == 'go' else _mb
    _s_unit = settings.get('max_storage_unit', 'mo')
    _s_mb   = int(settings['max_storage_mb'])
    _s_display = _s_mb // 1024 if _s_unit == 'go' else _s_mb
    form = AdminSettingsForm(data={
        'app_name':                 settings['app_name'],
        'contact_email':            settings['contact_email'],
        'welcome_banner':           settings.get('welcome_banner', ''),
        'max_file_size_value':      _display_val,
        'max_file_size_unit':       _unit,
        'blocked_extensions':       settings['blocked_extensions'],
        'allow_registration':       settings['allow_registration'] == '1',
        'default_expiry':           settings['default_expiry'],
        'max_files_per_user':       int(settings['max_files_per_user']),
        'max_storage_value':        _s_display,
        'max_storage_unit':         _s_unit,
        'audit_log_retention_days': int(settings.get('audit_log_retention_days', '0')),
        'e2e_mode':                 settings.get('e2e_mode', 'optional'),
        'maintenance_mode':         settings.get('maintenance_mode') == '1',
        'maintenance_message':      settings.get('maintenance_message', ''),
        'mfa_required':             settings.get('mfa_required') == '1',
        'allow_account_deletion':   settings.get('allow_account_deletion') == '1',
        'accent_color':             settings.get('accent_color', '#4361ee'),
    })
    sso_form = SSOSettingsForm(data={
        'sso_enabled':       settings.get('sso_enabled') == '1',
        'sso_force':         settings.get('sso_force') == '1',
        'sso_provider_name': settings.get('sso_provider_name', 'SSO'),
        'sso_discovery_url': settings.get('sso_discovery_url', ''),
        'sso_client_id':     settings.get('sso_client_id', ''),
    })
    s3_form = S3SettingsForm(data={
        'storage_backend': settings.get('storage_backend', 'local'),
        's3_bucket':       settings.get('s3_bucket', ''),
        's3_region':       settings.get('s3_region', ''),
        's3_endpoint_url': settings.get('s3_endpoint_url', ''),
        's3_access_key':   settings.get('s3_access_key', ''),
        's3_prefix':       settings.get('s3_prefix', ''),
    })
    legal_form = LegalForm(data={
        'legal_mentions': settings.get('legal_mentions', _DEFAULT_LEGAL_MENTIONS),
        'terms_of_use':   settings.get('terms_of_use',   _DEFAULT_TERMS_OF_USE),
    })
    stats = _compute_admin_stats()
    return render_template('admin.html', users=users, form=form, sso_form=sso_form,
                           s3_form=s3_form, legal_form=legal_form, settings=settings,
                           logs=logs, stats=stats,
                           clamav_active=_clamav_available())


@app.route('/admin/settings', methods=['POST'])
@login_required
@admin_required
def admin_save_settings():
    form = AdminSettingsForm()
    if form.validate_on_submit():
        _unit  = form.max_file_size_unit.data
        _val   = form.max_file_size_value.data
        _mb    = _val * 1024 if _unit == 'go' else _val
        _s_unit = form.max_storage_unit.data
        _s_val  = form.max_storage_value.data
        _s_mb   = _s_val * 1024 if _s_unit == 'go' else _s_val
        values = {
            'app_name':                 form.app_name.data.strip(),
            'contact_email':            form.contact_email.data.strip(),
            'welcome_banner':           (form.welcome_banner.data or '').strip(),
            'max_file_size_mb':         str(_mb),
            'max_file_size_unit':       _unit,
            'blocked_extensions':       form.blocked_extensions.data.strip().lower(),
            'allow_registration':       '1' if form.allow_registration.data else '0',
            'default_expiry':           form.default_expiry.data,
            'max_files_per_user':       str(form.max_files_per_user.data),
            'max_storage_mb':           str(_s_mb),
            'max_storage_unit':         _s_unit,
            'audit_log_retention_days': str(form.audit_log_retention_days.data),
            'e2e_mode':                 form.e2e_mode.data,
            'maintenance_mode':         '1' if form.maintenance_mode.data else '0',
            'maintenance_message':      (form.maintenance_message.data or '').strip(),
            'mfa_required':             '1' if form.mfa_required.data else '0',
            'allow_account_deletion':   '1' if form.allow_account_deletion.data else '0',
        }
        # Accent color (validate hex)
        raw_accent = (form.accent_color.data or '').strip()
        if re.match(r'^#[0-9a-fA-F]{6}$', raw_accent):
            values['accent_color'] = raw_accent
        # Logo upload
        logo_file = request.files.get('logo')
        if logo_file and logo_file.filename:
            ct = logo_file.content_type or 'image/png'
            if ct in ('image/png', 'image/jpeg', 'image/jpg', 'image/svg+xml',
                      'image/webp', 'image/gif'):
                try:
                    os.makedirs(os.path.dirname(LOGO_PATH), exist_ok=True)
                    logo_file.save(LOGO_PATH)
                    values['logo_content_type'] = ct
                except OSError as e:
                    app.logger.error('Logo save error: %s', e)
        # Suppression logo
        if request.form.get('remove_logo') == '1' and os.path.exists(LOGO_PATH):
            try:
                os.remove(LOGO_PATH)
                values['logo_content_type'] = ''
            except OSError:
                pass
        for key, value in values.items():
            g.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        g.db.commit()
        purge_old_audit_logs()
        audit_log('admin_settings', details='Paramètres mis à jour')
        flash('Paramètres sauvegardés.', 'success')
    else:
        for field, errors in form.errors.items():
            for err in errors:
                flash(f'{field} : {err}', 'danger')
    return redirect(url_for('admin_panel') + '#settings')


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    if user_id == current_user.id:
        flash("Impossible de supprimer votre propre compte.", 'danger')
        return redirect(url_for('admin_panel'))
    row = g.db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not row:
        return redirect(url_for('admin_panel'))
    target_username = row[0]
    file_ids = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (user_id,)).fetchall()
    n = sum(1 for (fid,) in file_ids if _remove_file(fid))
    g.db.execute('DELETE FROM files WHERE owner_id = ?', (user_id,))
    g.db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    g.db.commit()
    audit_log('admin_delete_user', target=target_username, details=f"{n} fichier(s) supprimé(s)")
    flash(f"Utilisateur « {target_username} » supprimé.", 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    if user_id == current_user.id:
        flash("Impossible de modifier vos propres droits.", 'danger')
        return redirect(url_for('admin_panel'))
    row = g.db.execute('SELECT username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if row:
        new_val = 0 if row[1] else 1
        g.db.execute('UPDATE users SET is_admin = ? WHERE id = ?', (new_val, user_id))
        g.db.commit()
        audit_log('admin_toggle_admin', target=row[0],
                  details='Promu administrateur' if new_val else 'Droits admin retirés')
    return redirect(url_for('admin_panel'))


@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    row = g.db.execute('SELECT username, sso_user FROM users WHERE id = ?', (user_id,)).fetchone()
    if not row:
        flash("Utilisateur introuvable.", 'danger')
        return redirect(url_for('admin_panel'))
    username, is_sso = row[0], bool(row[1])
    if is_sso:
        flash("Impossible de réinitialiser le mot de passe d'un compte SSO.", 'danger')
        return redirect(url_for('admin_panel'))
    token       = secrets.token_urlsafe(32)
    token_hash  = hashlib.sha256(token.encode()).hexdigest()
    expiry      = (datetime.utcnow() + timedelta(hours=1)).isoformat()
    g.db.execute(
        'UPDATE users SET reset_token_hash = ?, reset_token_expiry = ? WHERE id = ?',
        (token_hash, expiry, user_id),
    )
    g.db.commit()
    audit_log('admin_reset_password', target=username, details='Lien de réinitialisation généré')
    reset_url = url_for('reset_password', token=token, _external=True)
    flash(
        f"Lien de réinitialisation pour « {username} » (valide 1 h) : {reset_url}",
        'warning',
    )
    return redirect(url_for('admin_panel'))


# ── SSO / OIDC ────────────────────────────────────────────────────────────────
@app.route('/auth/sso')
def sso_login():
    settings = get_settings()
    if settings.get('sso_enabled') != '1' or not settings.get('sso_discovery_url'):
        abort(404)
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    try:
        discovery = requests.get(settings['sso_discovery_url'], timeout=5).json()
    except Exception:
        flash("Impossible de contacter le fournisseur SSO.", 'danger')
        return redirect(url_for('login'))
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    session['_sso_state']            = state
    session['_sso_nonce']            = nonce
    session['_sso_token_endpoint']   = discovery['token_endpoint']
    session['_sso_userinfo_endpoint'] = discovery.get('userinfo_endpoint', '')
    params = urlencode({
        'response_type': 'code',
        'client_id':     settings['sso_client_id'],
        'redirect_uri':  url_for('sso_callback', _external=True),
        'scope':         'openid email profile',
        'state':         state,
        'nonce':         nonce,
    })
    return redirect(f"{discovery['authorization_endpoint']}?{params}")


@app.route('/auth/sso/callback')
def sso_callback():
    settings = get_settings()
    if settings.get('sso_enabled') != '1':
        abort(404)

    def _sso_fail(msg):
        """Redirige vers /login. En mode SSO forcé, ajoute ?sso_error=1
        pour éviter une boucle infinie login → sso_login → callback → login."""
        flash(msg, 'danger')
        if settings.get('sso_force') == '1':
            return redirect(url_for('login', sso_error=1))
        return redirect(url_for('login'))

    if request.args.get('state') != session.pop('_sso_state', None):
        return _sso_fail("Erreur de sécurité SSO (state invalide).")
    code = request.args.get('code')
    if not code:
        return _sso_fail("Connexion SSO échouée.")
    token_endpoint    = session.pop('_sso_token_endpoint', '')
    userinfo_endpoint = session.pop('_sso_userinfo_endpoint', '')
    session.pop('_sso_nonce', None)
    try:
        token_resp = requests.post(token_endpoint, data={
            'grant_type':   'authorization_code',
            'code':         code,
            'redirect_uri': url_for('sso_callback', _external=True),
            'client_id':    settings['sso_client_id'],
            'client_secret': _decrypt_secret(settings['sso_client_secret']),
        }, timeout=10)
        token_data = token_resp.json()
    except Exception:
        return _sso_fail("Impossible d'échanger le code SSO.")
    access_token = token_data.get('access_token')
    if not access_token:
        return _sso_fail("Connexion SSO échouée (pas de token).")
    try:
        ui = requests.get(
            userinfo_endpoint,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        ).json()
    except Exception:
        return _sso_fail("Impossible de récupérer les informations SSO.")
    raw_username = ui.get('preferred_username') or ui.get('email') or ui.get('sub', '')
    username = ''.join(c for c in raw_username.split('@')[0] if c.isalnum() or c in '-_.')[:64]
    if not username:
        return _sso_fail("Le fournisseur SSO n'a pas fourni d'identifiant utilisable.")
    user = _load_user_by('username', username)
    if user is None:
        drop_token   = str(uuid.uuid4())
        avatar_color = AVATAR_COLORS[hash(username) % len(AVATAR_COLORS)]
        random_pw    = generate_password_hash(secrets.token_hex(32))
        # En mode SSO forcé : premier compte SSO créé obtient admin si aucun
        # admin SSO n'existe encore (couvre la transition depuis un admin local).
        # En mode normal   : premier compte tout court est admin.
        if settings.get('sso_force') == '1':
            no_sso_admin = g.db.execute(
                'SELECT COUNT(*) FROM users WHERE is_admin=1 AND sso_user=1'
            ).fetchone()[0] == 0
            grant_admin = 1 if no_sso_admin else 0
        else:
            grant_admin = 1 if g.db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0 else 0
        g.db.execute(
            'INSERT INTO users (username, password, drop_token, is_admin, avatar_color, sso_user) '
            'VALUES (?, ?, ?, ?, ?, 1)',
            (username, random_pw, drop_token, grant_admin, avatar_color),
        )
        g.db.commit()
        user = _load_user_by('username', username)
        audit_log('sso_register', target=username,
                  details=f'Compte créé via SSO{"  (admin)" if grant_admin else ""}')
    session.clear()
    login_user(user)
    audit_log('sso_login')
    return redirect(url_for('dashboard'))


@app.route('/admin/sso', methods=['POST'])
@login_required
@admin_required
def admin_save_sso():
    form = SSOSettingsForm()
    if form.validate_on_submit():
        existing = get_settings()
        new_secret = form.sso_client_secret.data.strip()
        # sso_force ne peut être activé que si sso_enabled l'est aussi
        sso_enabled = form.sso_enabled.data
        sso_force   = form.sso_force.data and sso_enabled
        values = {
            'sso_enabled':       '1' if sso_enabled else '0',
            'sso_force':         '1' if sso_force else '0',
            'sso_provider_name': form.sso_provider_name.data.strip() or 'SSO',
            'sso_discovery_url': form.sso_discovery_url.data.strip(),
            'sso_client_id':     form.sso_client_id.data.strip(),
            'sso_client_secret': _encrypt_secret(new_secret) if new_secret else existing.get('sso_client_secret', ''),
        }
        for key, value in values.items():
            g.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        g.db.commit()
        audit_log('admin_settings', details='Paramètres SSO mis à jour')
        flash('Configuration SSO sauvegardée.', 'success')
    else:
        for field, errors in form.errors.items():
            for err in errors:
                flash(f'{field} : {err}', 'danger')
    return redirect(url_for('admin_panel') + '#sso')


@app.route('/admin/s3', methods=['POST'])
@login_required
@admin_required
def admin_save_s3():
    form = S3SettingsForm()
    if form.validate_on_submit():
        existing = get_settings()
        new_secret = form.s3_secret_key.data.strip()
        values = {
            'storage_backend': form.storage_backend.data,
            's3_bucket':       form.s3_bucket.data.strip(),
            's3_region':       form.s3_region.data.strip(),
            's3_endpoint_url': form.s3_endpoint_url.data.strip(),
            's3_access_key':   form.s3_access_key.data.strip(),
            's3_secret_key':   _encrypt_secret(new_secret) if new_secret else existing.get('s3_secret_key', ''),
            's3_prefix':       form.s3_prefix.data.strip().strip('/'),
        }
        for key, value in values.items():
            g.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        g.db.commit()
        audit_log('admin_settings', details='Paramètres stockage S3 mis à jour')
        flash('Configuration du stockage sauvegardée.', 'success')
    else:
        for field, errors in form.errors.items():
            for err in errors:
                flash(f'{field} : {err}', 'danger')
    return redirect(url_for('admin_panel') + '#s3')


@app.route('/admin/s3/test', methods=['POST'])
@login_required
@admin_required
def admin_test_s3():
    """Test la connexion S3 avec les paramètres envoyés depuis le formulaire (avant sauvegarde)."""
    if not _BOTO3_AVAILABLE:
        return jsonify({'ok': False, 'message': 'boto3 non installé sur ce serveur.'})

    data = request.get_json(silent=True) or {}

    bucket       = (data.get('s3_bucket') or '').strip()
    region       = (data.get('s3_region') or '').strip() or None
    endpoint_url = (data.get('s3_endpoint_url') or '').strip() or None
    access_key   = (data.get('s3_access_key') or '').strip() or None
    secret_raw   = (data.get('s3_secret_key') or '').strip()

    if not bucket:
        return jsonify({'ok': False, 'message': 'Nom du bucket manquant.'})

    # Si le secret est vide, on utilise le secret déjà sauvegardé
    if secret_raw:
        secret_key = secret_raw
    else:
        existing = get_settings()
        secret_key = _decrypt_secret(existing.get('s3_secret_key', '')) or None

    try:
        kwargs = {
            'aws_access_key_id':     access_key,
            'aws_secret_access_key': secret_key,
            'region_name':           region,
        }
        if endpoint_url:
            kwargs['endpoint_url'] = endpoint_url
        client = boto3.client('s3', **kwargs)
        client.head_bucket(Bucket=bucket)
        return jsonify({'ok': True, 'message': f'Connexion réussie au bucket « {bucket} ».'})
    except Exception as exc:
        msg = str(exc)
        # Extraire le message lisible depuis les erreurs boto3
        if hasattr(exc, 'response'):
            code = exc.response.get('Error', {}).get('Code', '')
            msg  = exc.response.get('Error', {}).get('Message', msg)
            if code:
                msg = f'[{code}] {msg}'
        return jsonify({'ok': False, 'message': msg})


@app.route('/admin/legal', methods=['POST'])
@login_required
@admin_required
def admin_save_legal():
    form = LegalForm()
    if form.validate_on_submit():
        for key, value in {'legal_mentions': form.legal_mentions.data,
                           'terms_of_use':   form.terms_of_use.data}.items():
            g.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                         (key, value or ''))
        g.db.commit()
        audit_log('admin_legal', details='Mentions légales / CGU mis à jour')
        flash('Mentions légales et CGU sauvegardées.', 'success')
    else:
        for field, errors in form.errors.items():
            for err in errors:
                flash(f'{field} : {err}', 'danger')
    return redirect(url_for('admin_panel') + '#legal')


# ── Pages d'erreur ────────────────────────────────────────────────────────────
@app.route('/file_not_found')
def file_not_found():
    return render_template('file_not_found.html', settings=get_settings())


@app.route('/file_expired')
def file_expired():
    return render_template('file_expired.html', settings=get_settings())


# ── Gestionnaires d'erreurs HTTP ─────────────────────────────────────────────
def _error_theme():
    return current_user.theme if current_user.is_authenticated else 'light'


@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'success': False, 'message': 'Fichier trop grand (limite serveur dépassée).'}), 413


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', settings=get_settings(), user_theme=_error_theme()), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html', settings=get_settings(), user_theme=_error_theme()), 403


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html', settings=get_settings(), user_theme=_error_theme()), 500


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
