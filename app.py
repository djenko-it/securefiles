import base64
import io
import json
import logging
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlencode

import requests

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
from redis import Redis
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import (BooleanField, FileField, IntegerField, PasswordField,
                     SelectField, StringField, SubmitField)
from wtforms.validators import DataRequired, EqualTo, Length, NumberRange, Optional

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
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)

redis_client = Redis(host='redis', port=6379)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='redis://redis:6379',
    default_limits=["200 per day", "50 per hour"],
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
login_manager.login_message_category = 'warning'

DATABASE      = '/app/messages.db'
UPLOAD_FOLDER = '/app/data'
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar',
    'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv',
    'mp3', 'mp4', 'avi', 'mov', 'ogg', 'webm', 'svg',
}

SETTINGS_DEFAULTS = {
    'app_name':           'FileShareApp',
    'contact_email':      'djenko-it@protonmail.com',
    'max_file_size_mb':   '16',
    'blocked_extensions': 'exe,bat,cmd,sh,msi,dll,com,scr,vbs,ps1',
    'allow_registration': '1',
    'default_expiry':     '1d',
    'max_files_per_user': '0',
    'max_storage_mb':     '0',
    # SSO / OIDC
    'sso_enabled':        '0',
    'sso_provider_name':  'SSO',
    'sso_discovery_url':  '',
    'sso_client_id':      '',
    'sso_client_secret':  '',
}

AVATAR_COLORS = [
    '#4361ee', '#e63946', '#2a9d8f', '#e9c46a', '#f4a261',
    '#264653', '#6c5ce7', '#00b894', '#fd79a8', '#636e72',
    '#0984e3', '#d63031', '#6ab04c', '#f9ca24', '#eb4d4b',
]

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ── WebAuthn config ───────────────────────────────────────────────────────────
RP_ID     = os.environ.get('WEBAUTHN_RP_ID', 'localhost')
RP_ORIGIN = os.environ.get('WEBAUTHN_RP_ORIGIN', 'http://localhost:5000')
RP_NAME   = 'FileShareApp'

# ── Chiffrement Fernet ────────────────────────────────────────────────────────
_raw_key = os.environ.get('ENCRYPTION_KEY', '').strip().strip('"').strip("'")
_raw_key = _raw_key.split('#')[0].strip()
if _raw_key:
    try:
        fernet = Fernet(_raw_key.encode())
    except Exception:
        fernet = None
else:
    fernet = None


def _encrypt(data: bytes) -> bytes:
    return fernet.encrypt(data) if fernet else data


def _decrypt(data: bytes) -> bytes:
    if not fernet:
        return data
    try:
        return fernet.decrypt(data)
    except InvalidToken:
        return data


def _encrypt_secret(secret: str) -> str:
    if fernet and secret:
        return fernet.encrypt(secret.encode()).decode()
    return secret


def _decrypt_secret(encrypted: str) -> str:
    if not fernet or not encrypted:
        return encrypted or ''
    try:
        return fernet.decrypt(encrypted.encode()).decode()
    except (InvalidToken, Exception):
        return encrypted


# ── Modèle utilisateur ────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, username, password, drop_token, is_admin=False,
                 totp_secret=None, webauthn_credential_id=None,
                 webauthn_public_key=None, webauthn_sign_count=0,
                 theme='light', avatar_color='#4361ee'):
        self.id                     = id
        self.username               = username
        self.password               = password
        self.drop_token             = drop_token
        self.is_admin               = bool(is_admin)
        self.totp_secret            = totp_secret
        self.webauthn_credential_id = webauthn_credential_id
        self.webauthn_public_key    = webauthn_public_key
        self.webauthn_sign_count    = webauthn_sign_count or 0
        self.theme                  = theme or 'light'
        self.avatar_color           = avatar_color or '#4361ee'

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
              'webauthn_sign_count, theme, avatar_color')


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
        }
    return {'user_theme': 'light', 'user_avatar_color': '#4361ee', 'user_avatar_letter': '?'}


# ── Formulaires WTForms ───────────────────────────────────────────────────────
class PasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit   = SubmitField('Soumettre')


class FileUploadForm(FlaskForm):
    file          = FileField('Choisissez un fichier', validators=[DataRequired()])
    expiry        = SelectField('Durée de validité', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois'),
    ])
    max_downloads = SelectField('Nombre maximal de téléchargements', choices=[
        ('1', '1'), ('5', '5'), ('10', '10'), ('unlimited', 'Illimité'),
    ], validators=[DataRequired()])
    password      = PasswordField('Mot de passe (optionnel)')
    submit        = SubmitField('Téléverser')


class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=10)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.'),
    ])
    submit   = SubmitField('Créer un compte')


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe',     validators=[DataRequired()])
    submit   = SubmitField('Se connecter')


class ChangePasswordForm(FlaskForm):
    current  = PasswordField('Mot de passe actuel', validators=[DataRequired()])
    password = PasswordField('Nouveau mot de passe', validators=[DataRequired(), Length(min=10)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.'),
    ])
    submit   = SubmitField('Modifier')


class AdminSettingsForm(FlaskForm):
    app_name           = StringField('Nom de l\'application',
                                     validators=[DataRequired(), Length(max=64)])
    contact_email      = StringField('E-mail de contact',
                                     validators=[DataRequired(), Length(max=128)])
    max_file_size_mb   = IntegerField('Taille max des fichiers (Mo)',
                                      validators=[DataRequired(), NumberRange(min=1, max=2048)])
    blocked_extensions = StringField('Extensions bloquées (virgules)',
                                     validators=[Optional(), Length(max=256)])
    allow_registration = BooleanField('Autoriser les inscriptions')
    default_expiry     = SelectField('Expiration par défaut', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois'),
    ])
    max_files_per_user = IntegerField('Quota fichiers / utilisateur (0 = illimité)',
                                      validators=[NumberRange(min=0)])
    max_storage_mb     = IntegerField('Quota stockage / utilisateur en Mo (0 = illimité)',
                                      validators=[NumberRange(min=0)])
    submit             = SubmitField('Sauvegarder')


class SSOSettingsForm(FlaskForm):
    sso_enabled       = BooleanField('Activer le SSO (OIDC)')
    sso_provider_name = StringField('Nom du fournisseur',
                                    validators=[Optional(), Length(max=64)])
    sso_discovery_url = StringField('Discovery URL',
                                    validators=[Optional(), Length(max=512)])
    sso_client_id     = StringField('Client ID',
                                    validators=[Optional(), Length(max=256)])
    sso_client_secret = PasswordField('Client Secret (laisser vide pour ne pas changer)',
                                      validators=[Optional(), Length(max=512)])
    submit            = SubmitField('Sauvegarder SSO')


# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
        g.db.execute('PRAGMA journal_mode=WAL')
    return g.db


def init_db():
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
            ('theme',                  "TEXT DEFAULT 'light'"),
            ('avatar_color',           "TEXT DEFAULT '#4361ee'"),
        ]:
            if col not in existing_users:
                conn.execute(f'ALTER TABLE users ADD COLUMN {col} {ddl}')


@app.before_request
def before_request():
    g.db = get_db()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


# ── Journal d'audit ───────────────────────────────────────────────────────────
def audit_log(action: str, target: str = None, details: str = None):
    uid   = current_user.id       if current_user.is_authenticated else None
    uname = current_user.username if current_user.is_authenticated else None
    ip    = request.remote_addr
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
                path = os.path.join(UPLOAD_FOLDER, fid)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        deleted += 1
                except OSError:
                    errors += 1
            conn.execute('DELETE FROM files WHERE expiry < ?', (now,))
    except Exception:
        return
    if deleted or errors:
        detail = f"{deleted} fichier(s) supprimé(s)"
        if errors:
            detail += f", {errors} erreur(s)"
        _system_audit_log('cleanup', detail)


_scheduler = BackgroundScheduler(daemon=True)
_scheduler.add_job(cleanup_expired_files, 'interval', hours=1, id='cleanup',
                   next_run_time=datetime.now() + timedelta(minutes=1))
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
    return ext not in s.get('blocked_ext_set', set()) and ext in ALLOWED_EXTENSIONS


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


def _remove_file(file_id: str) -> bool:
    path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    try:
        if os.path.exists(path):
            os.remove(path)
            return True
    except OSError as exc:
        app.logger.error("Erreur suppression fichier %s : %s", file_id, exc)
    return False


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
        used = 0
        for (fid,) in file_ids:
            p = os.path.join(app.config['UPLOAD_FOLDER'], fid)
            try:
                used += os.path.getsize(p) if os.path.exists(p) else 0
            except OSError:
                pass
        if used + size_bytes > max_storage * 1024 * 1024:
            return {'success': False,
                    'message': f"Quota de stockage dépassé ({max_storage} Mo maximum)."}

    file_id         = str(uuid.uuid4())
    expiry_time     = get_expiry_time(request.form.get('expiry', settings['default_expiry']))
    max_downloads   = request.form.get('max_downloads', 'unlimited')
    password        = request.form.get('password', '')
    hashed_password = generate_password_hash(password) if password else None

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    dest = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    try:
        raw_data = file.read()
        with open(dest, 'wb') as fh:
            fh.write(_encrypt(raw_data))
    except OSError as exc:
        app.logger.error("Erreur écriture fichier %s : %s", file_id, exc)
        return {'success': False, 'message': 'Erreur interne lors de l\'enregistrement.'}

    g.db.execute(
        'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password, owner_id)'
        ' VALUES (?, ?, ?, ?, ?, ?, ?)',
        (file_id, file_id, file.filename, expiry_time, max_downloads, hashed_password, current_user.id),
    )
    g.db.commit()

    size_kb = round(size_bytes / 1024, 1)
    audit_log('upload', target=file_id,
              details=f"{file.filename} ({size_kb} Ko)")

    return {'success': True, 'link': url_for('download_file', file_id=file_id, _external=True)}


@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
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
    cur = g.db.execute(
        'SELECT original_filename, expiry, views, max_downloads, password FROM files WHERE id = ?',
        (file_id,),
    )
    row = cur.fetchone()
    if not row:
        return redirect(url_for('file_not_found'))

    original_filename, expiry, views, max_downloads, hashed_password = row
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

    path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
    try:
        with open(path, 'rb') as fh:
            raw = fh.read()
    except OSError:
        return redirect(url_for('file_not_found'))

    data = _decrypt(raw)
    return send_file(io.BytesIO(data), as_attachment=True, download_name=original_filename)


# ── Authentification ──────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    settings = get_settings()
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
    form = LoginForm()
    if form.validate_on_submit():
        uname = form.username.data.strip()
        user  = _load_user_by('username', uname)
        if user and check_password_hash(user.password, form.password.data):
            # MFA check
            if user.has_mfa:
                session['_mfa_user_id'] = user.id
                session['_mfa_methods'] = []
                if user.has_totp:
                    session['_mfa_methods'].append('totp')
                if user.has_webauthn:
                    session['_mfa_methods'].append('webauthn')
                return redirect(url_for('mfa_verify'))
            login_user(user)
            audit_log('login')
            return redirect(request.args.get('next') or url_for('dashboard'))
        audit_log('login_failed', target=uname)
        flash('Identifiants incorrects.', 'danger')
    return render_template('login.html', form=form, settings=get_settings())


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
    secret = _decrypt_secret(user.totp_secret)
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        session.pop('_mfa_user_id', None)
        session.pop('_mfa_methods', None)
        login_user(user)
        audit_log('login', details='via TOTP')
        return redirect(url_for('dashboard'))
    flash('Code TOTP invalide.', 'danger')
    return redirect(url_for('mfa_verify'))


@app.route('/mfa/webauthn/begin', methods=['POST'])
def mfa_webauthn_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400
    user = _get_mfa_user()
    if not user or not user.webauthn_credential_id:
        return jsonify({'error': 'Non autorisé'}), 403

    cred_id = base64.b64decode(user.webauthn_credential_id)
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[PublicKeyCredentialDescriptor(id=cred_id)],
        user_verification=UserVerificationRequirement.DISCOURAGED,
    )
    session['_webauthn_auth_challenge'] = base64.b64encode(options.challenge).decode()
    return options_to_json(options), 200, {'Content-Type': 'application/json'}


@app.route('/mfa/webauthn/complete', methods=['POST'])
def mfa_webauthn_complete():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400
    user = _get_mfa_user()
    if not user:
        return jsonify({'error': 'Non autorisé'}), 403

    challenge = base64.b64decode(session.pop('_webauthn_auth_challenge', ''))
    pub_key   = base64.b64decode(user.webauthn_public_key)

    try:
        from webauthn.helpers.structs import AuthenticationCredential
        raw = request.get_data()
        try:
            credential = AuthenticationCredential.model_validate_json(raw)
        except AttributeError:
            credential = AuthenticationCredential.parse_raw(raw)

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
            credential_public_key=pub_key,
            credential_current_sign_count=user.webauthn_sign_count,
        )
        g.db.execute('UPDATE users SET webauthn_sign_count = ? WHERE id = ?',
                     (verification.new_sign_count, user.id))
        g.db.commit()
    except Exception as exc:
        app.logger.error("WebAuthn auth failed: %s", exc)
        return jsonify({'error': 'Échec de la vérification'}), 400

    session.pop('_mfa_user_id', None)
    session.pop('_mfa_methods', None)
    login_user(user)
    audit_log('login', details='via WebAuthn')
    return jsonify({'success': True, 'redirect': url_for('dashboard')})


# ── Profil utilisateur ────────────────────────────────────────────────────────
@app.route('/profile')
@login_required
def profile():
    form = ChangePasswordForm()
    return render_template('profile.html', form=form, settings=get_settings(),
                           avatar_colors=AVATAR_COLORS,
                           webauthn_available=WEBAUTHN_AVAILABLE)


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
    return redirect(request.referrer or url_for('profile'))


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
        g.db.execute('UPDATE users SET totp_secret = ? WHERE id = ?',
                     (_encrypt_secret(secret), current_user.id))
        g.db.commit()
        audit_log('totp_enable')
        flash('TOTP activé avec succès.', 'success')
    else:
        flash('Code invalide. Réessayez.', 'danger')
    return redirect(url_for('profile'))


@app.route('/profile/totp/disable', methods=['POST'])
@login_required
def profile_totp_disable():
    g.db.execute('UPDATE users SET totp_secret = NULL WHERE id = ?', (current_user.id,))
    g.db.commit()
    audit_log('totp_disable')
    flash('TOTP désactivé.', 'success')
    return redirect(url_for('profile'))


# ── Profil : WebAuthn ─────────────────────────────────────────────────────────
@app.route('/profile/webauthn/register/begin', methods=['POST'])
@login_required
def webauthn_register_begin():
    if not WEBAUTHN_AVAILABLE:
        return jsonify({'error': 'WebAuthn non disponible'}), 400

    options = generate_registration_options(
        rp_id=RP_ID,
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
        from webauthn.helpers.structs import RegistrationCredential
        raw = request.get_data()
        try:
            credential = RegistrationCredential.model_validate_json(raw)
        except AttributeError:
            credential = RegistrationCredential.parse_raw(raw)

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=RP_ORIGIN,
        )
    except Exception as exc:
        app.logger.error("WebAuthn registration failed: %s", exc)
        return jsonify({'error': 'Échec de l\'enregistrement'}), 400

    cred_id = base64.b64encode(verification.credential_id).decode()
    pub_key = base64.b64encode(verification.credential_public_key).decode()
    g.db.execute(
        'UPDATE users SET webauthn_credential_id=?, webauthn_public_key=?, webauthn_sign_count=? WHERE id=?',
        (cred_id, pub_key, verification.sign_count, current_user.id),
    )
    g.db.commit()
    audit_log('webauthn_register', details='Clé de sécurité enregistrée')
    return jsonify({'success': True})


@app.route('/profile/webauthn/delete', methods=['POST'])
@login_required
def webauthn_delete():
    g.db.execute(
        'UPDATE users SET webauthn_credential_id=NULL, webauthn_public_key=NULL, webauthn_sign_count=0 WHERE id=?',
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
        })
    drop_url = url_for('drop_zone', drop_token=current_user.drop_token, _external=True)
    return render_template('dashboard.html', files=files, drop_url=drop_url, settings=get_settings())


@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    cur = g.db.execute('SELECT owner_id, original_filename FROM files WHERE id = ?', (file_id,))
    row = cur.fetchone()
    if row and row[0] == current_user.id:
        _remove_file(file_id)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
        audit_log('delete_file', target=file_id, details=row[1])
    return redirect(url_for('dashboard'))


# ── Zone de dépôt ─────────────────────────────────────────────────────────────
@app.route('/drop/<drop_token>', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def drop_zone(drop_token):
    cur      = g.db.execute('SELECT id, username FROM users WHERE drop_token = ?', (drop_token,))
    user_row = cur.fetchone()
    if not user_row:
        return redirect(url_for('file_not_found'))
    recipient_id, recipient_name = user_row

    success = False
    if request.method == 'POST':
        file        = request.files.get('file')
        sender_name = request.form.get('sender_name', '').strip() or 'Anonyme'
        if file and allowed_file(file.filename):
            file_id     = str(uuid.uuid4())
            settings    = get_settings()
            expiry_time = get_expiry_time(settings['default_expiry'])
            dest        = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            try:
                raw_data = file.read()
                with open(dest, 'wb') as fh:
                    fh.write(_encrypt(raw_data))
            except OSError:
                flash("Erreur interne lors de l'enregistrement.", 'danger')
                return render_template('drop.html', recipient=recipient_name,
                                       drop_token=drop_token, success=False,
                                       settings=get_settings())
            g.db.execute(
                'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, owner_id, deposited_by)'
                ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                (file_id, file_id, file.filename, expiry_time, 'unlimited', recipient_id, sender_name),
            )
            g.db.commit()
            audit_log('drop_upload', target=file_id,
                      details=f"{file.filename} pour {recipient_name} par {sender_name}")
            success = True
        else:
            flash('Type de fichier non autorisé.', 'danger')

    return render_template('drop.html', recipient=recipient_name,
                           drop_token=drop_token, success=success, settings=get_settings())


# ── Administration ────────────────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    rows = g.db.execute('''
        SELECT u.id, u.username, u.created_at, u.is_admin, COUNT(f.id) AS file_count
        FROM users u LEFT JOIN files f ON f.owner_id = u.id
        GROUP BY u.id ORDER BY u.created_at
    ''').fetchall()

    users = []
    for uid, username, created_at, is_admin, file_count in rows:
        file_ids = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (uid,)).fetchall()
        used = 0
        for (fid,) in file_ids:
            p = os.path.join(app.config['UPLOAD_FOLDER'], fid)
            try:
                used += os.path.getsize(p) if os.path.exists(p) else 0
            except OSError:
                pass
        users.append({
            'id': uid, 'username': username, 'created_at': created_at,
            'is_admin': bool(is_admin), 'file_count': file_count,
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
    form = AdminSettingsForm(data={
        'app_name': settings['app_name'], 'contact_email': settings['contact_email'],
        'max_file_size_mb': int(settings['max_file_size_mb']),
        'blocked_extensions': settings['blocked_extensions'],
        'allow_registration': settings['allow_registration'] == '1',
        'default_expiry': settings['default_expiry'],
        'max_files_per_user': int(settings['max_files_per_user']),
        'max_storage_mb': int(settings['max_storage_mb']),
    })
    sso_form = SSOSettingsForm(data={
        'sso_enabled':       settings.get('sso_enabled') == '1',
        'sso_provider_name': settings.get('sso_provider_name', 'SSO'),
        'sso_discovery_url': settings.get('sso_discovery_url', ''),
        'sso_client_id':     settings.get('sso_client_id', ''),
    })
    return render_template('admin.html', users=users, form=form, sso_form=sso_form,
                           settings=settings, logs=logs)


@app.route('/admin/settings', methods=['POST'])
@login_required
@admin_required
def admin_save_settings():
    form = AdminSettingsForm()
    if form.validate_on_submit():
        values = {
            'app_name': form.app_name.data.strip(),
            'contact_email': form.contact_email.data.strip(),
            'max_file_size_mb': str(form.max_file_size_mb.data),
            'blocked_extensions': form.blocked_extensions.data.strip().lower(),
            'allow_registration': '1' if form.allow_registration.data else '0',
            'default_expiry': form.default_expiry.data,
            'max_files_per_user': str(form.max_files_per_user.data),
            'max_storage_mb': str(form.max_storage_mb.data),
        }
        for key, value in values.items():
            g.db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        g.db.commit()
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
    if request.args.get('state') != session.pop('_sso_state', None):
        flash("Erreur de sécurité SSO (state invalide).", 'danger')
        return redirect(url_for('login'))
    code = request.args.get('code')
    if not code:
        flash("Connexion SSO échouée.", 'danger')
        return redirect(url_for('login'))
    token_endpoint    = session.pop('_sso_token_endpoint', '')
    userinfo_endpoint = session.pop('_sso_userinfo_endpoint', '')
    session.pop('_sso_nonce', None)
    try:
        token_resp = requests.post(token_endpoint, data={
            'grant_type':   'authorization_code',
            'code':         code,
            'redirect_uri': url_for('sso_callback', _external=True),
            'client_id':    settings['sso_client_id'],
            'client_secret': settings['sso_client_secret'],
        }, timeout=10)
        token_data = token_resp.json()
    except Exception:
        flash("Impossible d'échanger le code SSO.", 'danger')
        return redirect(url_for('login'))
    access_token = token_data.get('access_token')
    if not access_token:
        flash("Connexion SSO échouée (pas de token).", 'danger')
        return redirect(url_for('login'))
    try:
        ui = requests.get(
            userinfo_endpoint,
            headers={'Authorization': f'Bearer {access_token}'},
            timeout=5,
        ).json()
    except Exception:
        flash("Impossible de récupérer les informations SSO.", 'danger')
        return redirect(url_for('login'))
    raw_username = ui.get('preferred_username') or ui.get('email') or ui.get('sub', '')
    username = ''.join(c for c in raw_username.split('@')[0] if c.isalnum() or c in '-_.')[:64]
    if not username:
        flash("Le fournisseur SSO n'a pas fourni d'identifiant utilisable.", 'danger')
        return redirect(url_for('login'))
    user = _load_user_by('username', username)
    if user is None:
        drop_token   = str(uuid.uuid4())
        avatar_color = AVATAR_COLORS[hash(username) % len(AVATAR_COLORS)]
        random_pw    = generate_password_hash(secrets.token_hex(32))
        is_first     = g.db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0
        g.db.execute(
            'INSERT INTO users (username, password, drop_token, is_admin, avatar_color) '
            'VALUES (?, ?, ?, ?, ?)',
            (username, random_pw, drop_token, 1 if is_first else 0, avatar_color),
        )
        g.db.commit()
        user = _load_user_by('username', username)
        audit_log('sso_register', target=username, details='Compte créé via SSO')
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
        values = {
            'sso_enabled':       '1' if form.sso_enabled.data else '0',
            'sso_provider_name': form.sso_provider_name.data.strip() or 'SSO',
            'sso_discovery_url': form.sso_discovery_url.data.strip(),
            'sso_client_id':     form.sso_client_id.data.strip(),
            'sso_client_secret': new_secret if new_secret else existing.get('sso_client_secret', ''),
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


# ── Pages d'erreur ────────────────────────────────────────────────────────────
@app.route('/file_not_found')
def file_not_found():
    return render_template('file_not_found.html', settings=get_settings())


@app.route('/file_expired')
def file_expired():
    return render_template('file_expired.html', settings=get_settings())


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
