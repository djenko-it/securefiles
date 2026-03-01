import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, redirect, render_template, url_for, flash, send_from_directory, g, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, Length, EqualTo
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

DATABASE = '/app/messages.db'
UPLOAD_FOLDER = '/app/data'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class User(UserMixin):
    def __init__(self, id, username, password, drop_token):
        self.id = id
        self.username = username
        self.password = password
        self.drop_token = drop_token


@login_manager.user_loader
def load_user(user_id):
    cur = get_db().execute(
        'SELECT id, username, password, drop_token FROM users WHERE id = ?', (user_id,)
    )
    row = cur.fetchone()
    return User(*row) if row else None


# ── Forms ─────────────────────────────────────────────────────────────────────
class PasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Soumettre')


class FileUploadForm(FlaskForm):
    file = FileField('Choisissez un fichier', validators=[DataRequired()])
    expiry = SelectField('Durée de validité', choices=[
        ('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois')
    ])
    max_downloads = SelectField('Nombre maximal de téléchargements', choices=[
        ('1', '1'), ('5', '5'), ('10', '10'), ('unlimited', 'Illimité')
    ], validators=[DataRequired()])
    password = PasswordField('Mot de passe (optionnel)')
    submit = SubmitField('Téléverser')


class RegisterForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired(), Length(min=3, max=32)])
    password = PasswordField('Mot de passe', validators=[DataRequired(), Length(min=6)])
    confirm  = PasswordField('Confirmer', validators=[
        DataRequired(), EqualTo('password', message='Les mots de passe ne correspondent pas.')
    ])
    submit = SubmitField('Créer un compte')


class LoginForm(FlaskForm):
    username = StringField('Nom d\'utilisateur', validators=[DataRequired()])
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Se connecter')


# ── Base de données ───────────────────────────────────────────────────────────
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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
        # Migration sans casser les données existantes
        existing = {row[1] for row in conn.execute('PRAGMA table_info(files)')}
        if 'owner_id' not in existing:
            conn.execute('ALTER TABLE files ADD COLUMN owner_id INTEGER REFERENCES users(id)')
        if 'deposited_by' not in existing:
            conn.execute('ALTER TABLE files ADD COLUMN deposited_by TEXT')


@app.before_request
def before_request():
    g.db = get_db()


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()


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


def get_settings():
    return {
        'software_name':       os.environ.get('SOFTWARE_NAME',       'FileShareApp'),
        'contact_email':       os.environ.get('CONTACT_EMAIL',       'djenko-it@protonmail.com'),
        'title_upload_file':   os.environ.get('TITLE_UPLOAD_FILE',   'Téléverser un Fichier'),
        'title_download_file': os.environ.get('TITLE_DOWNLOAD_FILE', 'Télécharger un Fichier'),
        'max_file_size':       os.environ.get('MAX_FILE_SIZE',       '10'),
    }


def _parse_expiry(expiry_str):
    try:
        return datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        return datetime.strptime(expiry_str, '%Y-%m-%d %H:%M:%S')


# ── Routes principales ────────────────────────────────────────────────────────
@app.route('/')
def index():
    form = FileUploadForm()
    return render_template('index.html', form=form, settings=get_settings())


@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        file_id         = str(uuid.uuid4())
        expiry_time     = get_expiry_time(request.form.get('expiry', '1d'))
        max_downloads   = request.form.get('max_downloads', 'unlimited')
        password        = request.form.get('password', '')
        hashed_password = generate_password_hash(password) if password else None
        owner_id        = current_user.id if current_user.is_authenticated else None

        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_id))

        with g.db:
            g.db.execute(
                'INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password, owner_id)'
                ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                (file_id, file_id, file.filename, expiry_time, max_downloads, hashed_password, owner_id)
            )
            g.db.commit()

        return {"success": True, "link": url_for('download_file', file_id=file_id, _external=True)}

    return {"success": False, "message": "No file selected or file type is not allowed"}


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
                return render_template('password_required.html', file_id=file_id, form=form, settings=get_settings())
            if hashed_password:
                session[f'auth_{file_id}'] = True

        if hashed_password and request.method == 'GET':
            return render_template('password_required.html', file_id=file_id, form=form, settings=get_settings())

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
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            g.db.execute('INSERT INTO users (username, password, drop_token) VALUES (?, ?, ?)',
                         (form.username.data.strip(),
                          generate_password_hash(form.password.data),
                          str(uuid.uuid4())))
            g.db.commit()
            flash('Compte créé ! Vous pouvez vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Ce nom d'utilisateur est déjà pris.", 'danger')
    return render_template('register.html', form=form, settings=get_settings())


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        cur = g.db.execute(
            'SELECT id, username, password, drop_token FROM users WHERE username = ?',
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
    return redirect(url_for('index'))


# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route('/dashboard')
@login_required
def dashboard():
    cur = g.db.execute(
        'SELECT id, original_filename, expiry, views, max_downloads, deposited_by'
        ' FROM files WHERE owner_id = ? ORDER BY expiry DESC',
        (current_user.id,)
    )
    now = datetime.now()
    files = []
    for fid, name, expiry, views, max_dl, dep_by in cur.fetchall():
        exp = _parse_expiry(expiry)
        expired = now > exp
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
        file = request.files.get('file')
        sender_name = request.form.get('sender_name', '').strip() or 'Anonyme'
        if file and allowed_file(file.filename):
            file_id = str(uuid.uuid4())
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
