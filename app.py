import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, redirect, render_template, url_for, flash, send_from_directory, g
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import FileField, SelectField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

# Configuration de l'application
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')
csrf = CSRFProtect(app)

# Configuration de Redis
redis_client = Redis(host='redis', port=6379)

# Limiter les tentatives de connexion pour éviter les attaques par force brute
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri='redis://redis:6379',
    default_limits=["200 per day", "50 per hour"]
)

DATABASE = '/app/messages.db'
UPLOAD_FOLDER = '/app/data'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'rar'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

class PasswordForm(FlaskForm):
    password = PasswordField('Mot de passe', validators=[DataRequired()])
    submit = SubmitField('Soumettre')

# Définition du formulaire WTForms
class FileUploadForm(FlaskForm):
    file = FileField('Choisissez un fichier', validators=[DataRequired()])
    expiry = SelectField('Durée de validité', choices=[('3h', '3 heures'), ('1d', '1 jour'), ('1w', '1 semaine'), ('1m', '1 mois')])
    max_downloads = SelectField('Nombre maximal de téléchargements', choices=[('1', '1'), ('5', '5'), ('10', '10'), ('unlimited', 'Illimité')], validators=[DataRequired()])
    submit = SubmitField('Téléverser')

# Fonctions de base de données
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
    return g.db

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('DROP TABLE IF EXISTS files')
        conn.execute('''
            CREATE TABLE files (
                id TEXT PRIMARY KEY,
                filename TEXT,
                original_filename TEXT,
                expiry TIMESTAMP,
                views INTEGER DEFAULT 0,
                max_downloads INTEGER,
                password TEXT
            )
        ''')

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
        'software_name': os.environ.get('SOFTWARE_NAME', 'FileShareApp'),
        'contact_email': os.environ.get('CONTACT_EMAIL', 'djenko-it@protonmail.com'),
        'title_upload_file': os.environ.get('TITLE_UPLOAD_FILE', 'Téléverser un Fichier'),
        'title_download_file': os.environ.get('TITLE_DOWNLOAD_FILE', 'Télécharger un Fichier'),
        'max_file_size': os.environ.get('MAX_FILE_SIZE', '10')  # Taille maximale en Mo
    }

# Routes
@app.route('/')
def index():
    form = FileUploadForm()
    return render_template('index.html', form=form, settings=get_settings())

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file:
        file_id = str(uuid.uuid4())
        original_filename = file.filename
        expiry_option = request.form['expiry']
        max_downloads = request.form['max_downloads']
        password = request.form['password']

        expiry_time = get_expiry_time(expiry_option)
        hashed_password = generate_password_hash(password) if password else None

        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_id))

        with g.db:
            g.db.execute('INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password) VALUES (?, ?, ?, ?, ?, ?)',
                         (file_id, file.filename, original_filename, expiry_time, max_downloads, hashed_password))
            g.db.commit()

        link = url_for('download_file', file_id=file_id, _external=True)
        flash(f'File uploaded successfully. Download link: {link}')
        return redirect(url_for('index'))
    else:
        flash('No file selected')
        return redirect(url_for('index'))


@app.route('/download/<file_id>', methods=['GET', 'POST'])
def download_file(file_id):
    form = PasswordForm()
    with g.db:
        cur = g.db.execute('SELECT filename, original_filename, expiry, views, max_downloads, password FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()

        if row:
            filename, original_filename, expiry, views, max_downloads, hashed_password = row
            expiry_time = datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')

            if datetime.now() > expiry_time:
                g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                flash("Le fichier a expiré.")
                return redirect(url_for('file_expired'))

            remaining_downloads = 'Illimité'
            if max_downloads is not None:
                remaining_downloads = max_downloads - views
                if remaining_downloads <= 0:
                    g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                    flash("Le fichier a atteint le nombre maximal de téléchargements.")
                    return redirect(url_for('file_not_found'))

            if form.validate_on_submit():
                password = form.password.data
                if hashed_password and not check_password_hash(hashed_password, password):
                    flash("Mot de passe incorrect.")
                    return render_template('password_required.html', file_id=file_id, form=form, settings=get_settings())

            if hashed_password and request.method == 'GET':
                return render_template('password_required.html', file_id=file_id, form=form, settings=get_settings())

            return render_template('download.html', 
                                   file_id=file_id, 
                                   original_filename=original_filename, 
                                   expiry_time=expiry_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                   remaining_downloads=remaining_downloads, 
                                   settings=get_settings())
        else:
            flash("Le fichier n'a pas été trouvé.")
            return redirect(url_for('file_not_found'))



@app.route('/download_direct/<file_id>', methods=['GET'])
def download_direct(file_id):
    with g.db:
        cur = g.db.execute('SELECT original_filename FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()
        if row:
            original_filename = row[0]
            g.db.execute('UPDATE files SET views = views + 1 WHERE id = ?', (file_id,))
            return send_from_directory(app.config['UPLOAD_FOLDER'], file_id, as_attachment=True, attachment_filename=original_filename)
        else:
            flash("Le fichier n'a pas été trouvé.")
            return redirect(url_for('file_not_found'))


@app.route('/file_not_found')
def file_not_found():
    return render_template('file_not_found.html', settings=get_settings())

@app.route('/file_expired')
def file_expired():
    return render_template('file_expired.html', settings=get_settings())

# Démarrage de l'application
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
