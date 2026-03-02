import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, render_template, url_for, flash, send_from_directory, g, session, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, PasswordField, SubmitField, StringField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, NumberRange
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

# ── Configuration ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
csrf = CSRFProtect(app)

redis_client = Redis(host='redis', port=6379)

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='redis://redis:6379',
    default_limits=["200 per day", "50 per hour"]
)

# ── Flask-Login ───────────────────────────────────────────────────────────────
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
}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class User(UserMixin):
    def __init__(self, id, username, password, drop_token, is_admin=False):
        self.id         = id
        self.username   = username
        self.password   = password
        self.drop_token = drop_token
        self.is_admin   = bool(is_admin)


@login_manager.user_loader
def load_user(user_id):
    cur = get_db().execute(
        'SELECT id, username, password, drop_token, is_admin FROM users WHERE id = ?',
        (user_id,)
    )
    row = cur.fetchone()
    return User(*row) if row else None


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated


# ── Forms ─────────────────────────────────────────────────────────────────────
class PasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit   = SubmitField('Soumettre')


class FileUploadForm(FlaskForm):
    file          = FileField('Choisissez un fichier', validators=[DataRequired()])
    expiry        = SelectField('Durée de validité', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois')
    ])
    max_downloads = SelectField('Nombre maximal de téléchargements', choices=[
        ('1', '1'), ('5', '5'), ('10', '10'), ('unlimited', 'Illimité')
    ], validators=[DataRequired()])
    password      = PasswordField('Mot de passe (optionnel)')
    submit        = SubmitField('Téléverser')


class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.')
    ])
    submit   = SubmitField('Créer un compte')


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit   = SubmitField('Se connecter')


class AdminSettingsForm(FlaskForm):
    app_name           = StringField('Nom de l\'application',
                                     validators=[DataRequired(), Length(max=64)])
    contact_email      = StringField('E-mail de contact administrateur',
                                     validators=[DataRequired(), Length(max=128)])
    max_file_size_mb   = IntegerField('Taille max des fichiers (Mo)',
                                      validators=[DataRequired(), NumberRange(min=1, max=2048)])
    blocked_extensions = StringField('Extensions bloquées (séparées par des virgules)',
                                     validators=[Optional(), Length(max=256)])
    allow_registration = BooleanField('Autoriser les inscriptions')
    default_expiry     = SelectField('Expiration par défaut', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois')
    ])
    max_files_per_user = IntegerField('Quota fichiers par utilisateur (0 = illimité)',
                                      validators=[NumberRange(min=0)])
    max_storage_mb     = IntegerField('Quota stockage par utilisateur en Mo (0 = illimité)',
                                      validators=[NumberRange(min=0)])
    submit             = SubmitField('Sauvegarder')


# ── Base de données ───────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
    return g.db


def init_db():
    with sqlite3.connect(DATABASE) as conn:
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
        # Migrations sans casser les données existantes
        existing_files = {row[1] for row in conn.execute('PRAGMA table_info(files)')}
        if 'owner_id' not in existing_files:
            conn.execute('ALTER TABLE files ADD COLUMN owner_id INTEGER REFERENCES users(id)')
        if 'deposited_by' not in existing_files:
            conn.execute('ALTER TABLE files ADD COLUMN deposited_by TEXT')
        existing_users = {row[1] for row in conn.execute('PRAGMA table_info(users)')}
        if 'is_admin' not in existing_users:
            conn.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')


@app.before_request
def before_request():
    g.db = get_db()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


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
    if ext in s.get('blocked_ext_set', set()):
        return False
    return ext in ALLOWED_EXTENSIONS


def get_expiry_time(expiry_option):
    if expiry_option == '3h':
        return datetime.now() + timedelta(hours=3)
    elif expiry_option == '1d':
        return datetime.now() + timedelta(days=1)
    elif expiry_option == '1w':
        return datetime.now() + timedelta(weeks=1)
    elif expiry_option == '1m':
        return datetime.now() + timedelta(days=30)
    return None


def _parse_expiry(expiry_str):
    try:
        return datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        return datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')


# ── Routes principales ────────────────────────────────────────────────────────
@app.route('/')
@login_required
def index():
    form = FileUploadForm()
    return render_template('index.html', form=form, settings=get_settings())


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    if not file or not allowed_file(file.filename):
        return {"success": False, "message": "Fichier absent ou type non autorisé"}

    settings = get_settings()

    # Vérifier la taille du fichier
    file.seek(0, 2)
    size_bytes = file.tell()
    file.seek(0)
    max_bytes = int(settings['max_file_size_mb']) * 1024 * 1024
    if size_bytes > max_bytes:
        return {"success": False,
                "message": f"Fichier trop grand (max {settings['max_file_size_mb']} Mo)"}

    # Vérifier le quota fichiers par utilisateur
    max_files = int(settings['max_files_per_user'])
    if max_files > 0:
        count = g.db.execute(
            'SELECT COUNT(*) FROM files WHERE owner_id = ?', (current_user.id,)
        ).fetchone()[0]
        if count >= max_files:
            return {"success": False,
                    "message": f"Quota atteint ({max_files} fichiers maximum)"}

    # Vérifier le quota stockage par utilisateur
    max_storage = int(settings['max_storage_mb'])
    if max_storage > 0:
        rows = g.db.execute(
            'SELECT id FROM files WHERE owner_id = ?', (current_user.id,)
        ).fetchall()
        used = sum(
            os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], r[0]))
            for r in rows
            if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], r[0]))
        )
        if used + size_bytes > max_storage * 1024 * 1024:
            return {"success": False,
                    "message": f"Quota de stockage dépassé ({max_storage} Mo maximum)"}

    file_id         = str(uuid.uuid4())
    expiry_time     = get_expiry_time(request.form.get('expiry', settings['default_expiry']))
    max_downloads   = request.form.get('max_downloads', 'unlimited')
    password        = request.form.get('password', '')
    hashed_password = generate_password_hash(password) if password else None

    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_id))

    with g.db:
        g.db.execute(
            'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password, owner_id)'
            ' VALUES (?, ?, ?, ?, ?, ?, ?)',
            (file_id, file_id, file.filename, expiry_time, max_downloads, hashed_password, current_user.id)
        )
        g.db.commit()

    return {"success": True, "link": url_for('download_file', file_id=file_id, _external=True)}


@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    form = PasswordForm()
    with g.db:
        cur = g.db.execute(
            'SELECT filename, original_filename, expiry, views, max_downloads, password FROM files WHERE id = ?',
            (file_id,)
        )
        row = cur.fetchone()

        if not row:
            flash("Le fichier n'a pas été trouvé.")
            return redirect(url_for('file_not_found'))

        filename, original_filename, expiry, views, max_downloads, hashed_password = row
        expiry_time = _parse_expiry(expiry)

        if datetime.now() > expiry_time:
            g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            return redirect(url_for('file_expired'))

        if max_downloads != 'unlimited':
            remaining_downloads = int(max_downloads) - views
            if remaining_downloads <= 0:
                g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                return redirect(url_for('file_not_found'))
        else:
            remaining_downloads = 'Illimité'

        if form.validate_on_submit():
            if hashed_password and not check_password_hash(hashed_password, form.password.data):
                flash("Mot de passe incorrect.")
                return render_template('password_required.html', file_id=file_id, form=form,
                                       settings=get_settings())
            if hashed_password:
                session[f'auth_{file_id}'] = True

        if hashed_password and request.method == 'GET':
            return render_template('password_required.html', file_id=file_id, form=form,
                                   settings=get_settings())

        return render_template('download.html',
                               file_id=file_id,
                               original_filename=original_filename,
                               expiry_time=expiry_time.strftime('%Y-%m-%d %H:%M:%S'),
                               remaining_downloads=remaining_downloads,
                               settings=get_settings())


@app.route('/download_direct/<file_id>', methods=['GET'])
def download_direct(file_id):
    with g.db:
        cur = g.db.execute(
            'SELECT original_filename, expiry, views, max_downloads, password FROM files WHERE id = ?',
            (file_id,)
        )
        row = cur.fetchone()
        if not row:
            return redirect(url_for('file_not_found'))

        original_filename, expiry, views, max_downloads, hashed_password = row
        expiry_time = _parse_expiry(expiry)

        if datetime.now() > expiry_time:
            g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            return redirect(url_for('file_expired'))

        if max_downloads != 'unlimited' and int(max_downloads) - views <= 0:
            g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
            return redirect(url_for('file_not_found'))

        if hashed_password and not session.get(f'auth_{file_id}'):
            return redirect(url_for('download_file', file_id=file_id))

        g.db.execute('UPDATE files SET views = views + 1 WHERE id = ?', (file_id,))
        g.db.commit()
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            file_id,
            as_attachment=True,
            download_name=original_filename
        )


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
            # Le premier compte créé devient administrateur
            user_count = g.db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            is_admin   = 1 if user_count == 0 else 0
            g.db.execute(
                'INSERT INTO users (username, password, drop_token, is_admin) VALUES (?, ?, ?, ?)',
                (form.username.data.strip(), generate_password_hash(form.password.data),
                 str(uuid.uuid4()), is_admin)
            )
            g.db.commit()
            flash('Compte créé ! Vous pouvez vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur est déjà pris.", 'danger')
    return render_template('register.html', form=form, settings=settings)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        cur = g.db.execute(
            'SELECT id, username, password, drop_token, is_admin FROM users WHERE username = ?',
            (form.username.data.strip(),)
        )
        row = cur.fetchone()
        if row and check_password_hash(row[2], form.password.data):
            login_user(User(*row))
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Identifiants incorrects.', 'danger')
    return render_template('login.html', form=form, settings=get_settings())


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    cur = g.db.execute(
        'SELECT id, original_filename, expiry, views, max_downloads, deposited_by'
        ' FROM files WHERE owner_id = ? ORDER BY expiry DESC',
        (current_user.id,)
    )
    now   = datetime.now()
    files = []
    for fid, name, expiry, views, max_dl, dep_by in cur.fetchall():
        exp      = _parse_expiry(expiry)
        expired  = now > exp
        remaining = 'Illimité' if max_dl == 'unlimited' else max(0, int(max_dl) - views)
        files.append({
            'id':           fid,
            'name':         name,
            'expiry':       exp.strftime('%d/%m/%Y %H:%M'),
            'expired':      expired,
            'remaining':    remaining,
            'exhausted':    remaining == 0,
            'deposited_by': dep_by,
        })

    drop_url = url_for('drop_zone', drop_token=current_user.drop_token, _external=True)
    return render_template('dashboard.html', files=files, drop_url=drop_url, settings=get_settings())


@app.route('/delete/<file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    cur = g.db.execute('SELECT owner_id FROM files WHERE id = ?', (file_id,))
    row = cur.fetchone()
    if row and row[0] == current_user.id:
        path = os.path.join(app.config['UPLOAD_FOLDER'], file_id)
        if os.path.exists(path):
            os.remove(path)
        g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
        g.db.commit()
    return redirect(url_for('dashboard'))


# ── Zone de dépôt ─────────────────────────────────────────────────────────────
@app.route('/drop/<drop_token>', methods=['GET', 'POST'])
def drop_zone(drop_token):
    cur = g.db.execute('SELECT id, username FROM users WHERE drop_token = ?', (drop_token,))
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
            expiry_time = datetime.now() + timedelta(days=30)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_id))
            g.db.execute(
                'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, owner_id, deposited_by)'
                ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                (file_id, file_id, file.filename, expiry_time, 'unlimited', recipient_id, sender_name)
            )
            g.db.commit()
            success = True
        else:
            flash('Type de fichier non autorisé.', 'danger')

    return render_template('drop.html',
                           recipient=recipient_name,
                           drop_token=drop_token,
                           success=success,
                           settings=get_settings())


# ── Administration ────────────────────────────────────────────────────────────
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    rows = g.db.execute('''
        SELECT u.id, u.username, u.created_at, u.is_admin, COUNT(f.id) AS file_count
        FROM users u
        LEFT JOIN files f ON f.owner_id = u.id
        GROUP BY u.id
        ORDER BY u.created_at
    ''').fetchall()

    users = []
    for uid, username, created_at, is_admin, file_count in rows:
        file_ids   = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (uid,)).fetchall()
        used_bytes = sum(
            os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], r[0]))
            for r in file_ids
            if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], r[0]))
        )
        users.append({
            'id':         uid,
            'username':   username,
            'created_at': created_at,
            'is_admin':   bool(is_admin),
            'file_count': file_count,
            'storage_mb': round(used_bytes / (1024 * 1024), 2),
        })

    settings = get_settings()
    form = AdminSettingsForm(data={
        'app_name':           settings['app_name'],
        'contact_email':      settings['contact_email'],
        'max_file_size_mb':   int(settings['max_file_size_mb']),
        'blocked_extensions': settings['blocked_extensions'],
        'allow_registration': settings['allow_registration'] == '1',
        'default_expiry':     settings['default_expiry'],
        'max_files_per_user': int(settings['max_files_per_user']),
        'max_storage_mb':     int(settings['max_storage_mb']),
    })
    return render_template('admin.html', users=users, form=form, settings=settings)


@app.route('/admin/settings', methods=['POST'])
@login_required
@admin_required
def admin_save_settings():
    form = AdminSettingsForm()
    if form.validate_on_submit():
        values = {
            'app_name':           form.app_name.data.strip(),
            'contact_email':      form.contact_email.data.strip(),
            'max_file_size_mb':   str(form.max_file_size_mb.data),
            'blocked_extensions': form.blocked_extensions.data.strip().lower(),
            'allow_registration': '1' if form.allow_registration.data else '0',
            'default_expiry':     form.default_expiry.data,
            'max_files_per_user': str(form.max_files_per_user.data),
            'max_storage_mb':     str(form.max_storage_mb.data),
        }
        for key, value in values.items():
            g.db.execute(
                'INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value)
            )
        g.db.commit()
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
    file_ids = g.db.execute('SELECT id FROM files WHERE owner_id = ?', (user_id,)).fetchall()
    for (fid,) in file_ids:
        path = os.path.join(app.config['UPLOAD_FOLDER'], fid)
        if os.path.exists(path):
            os.remove(path)
    g.db.execute('DELETE FROM files WHERE owner_id = ?', (user_id,))
    g.db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    g.db.commit()
    flash('Utilisateur supprimé.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/users/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def admin_toggle_admin(user_id):
    if user_id == current_user.id:
        flash("Impossible de modifier vos propres droits.", 'danger')
        return redirect(url_for('admin_panel'))
    row = g.db.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    if row:
        g.db.execute('UPDATE users SET is_admin = ? WHERE id = ?',
                     (0 if row[0] else 1, user_id))
        g.db.commit()
    return redirect(url_for('admin_panel'))


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
