import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, redirect, render_template, url_for, flash, g
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from redis import Redis

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
                views INTEGER DEFAULT 0
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

@app.route('/')
def index():
    return render_template('index.html', settings=get_settings())

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = str(uuid.uuid4())
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
            
            expiry_option = request.form.get('expiry')
            expiry_time = get_expiry_time(expiry_option)
            
            with g.db:
                g.db.execute('INSERT INTO files (id, filename, original_filename, expiry) VALUES (?, ?, ?, ?)', 
                             (unique_filename, filename, file.filename, expiry_time))
            
            link = url_for('download_file', file_id=unique_filename, _external=True)
            flash(f'File uploaded successfully. Download link: {link}')
            return redirect(url_for('index'))
    return render_template('upload.html', settings=get_settings())

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    with g.db:
        cur = g.db.execute('SELECT filename, original_filename, expiry, views FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()

        if row:
            filename, original_filename, expiry, views = row
            expiry_time = datetime.strptime(expiry, '%Y-%m-%d %H:%M:%S.%f')
            
            if datetime.now() > expiry_time:
                g.db.execute('DELETE FROM files WHERE id = ?', (file_id,))
                flash("Le fichier a expiré.")
                return redirect(url_for('file_expired'))
            
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
        'contact_email': os.environ.get('CONTACT_EMAIL', 'newcontact@example.com'),
        'title_upload_file': os.environ.get('TITLE_UPLOAD_FILE', 'Téléverser un Fichier'),
        'title_download_file': os.environ.get('TITLE_DOWNLOAD_FILE', 'Télécharger un Fichier')
    }

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
