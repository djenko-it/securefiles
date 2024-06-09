import os
import uuid
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, redirect, render_template, url_for, flash, g, send_file, safe_join, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask, request, redirect, render_template, url_for, flash, g, send_file, safe_join, current_app
from forms import UploadForm  # Assurez-vous d'importer le formulaire

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey')  # Nécessaire pour les messages flash et CSRF
csrf = CSRFProtect(app)

# Limiter les tentatives de connexion pour éviter les attaques par force brute
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration de la base de données
DATABASE = '/app/messages.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
    return db

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
        conn.execute('DROP TABLE IF EXISTS settings')
        conn.execute('''
            CREATE TABLE settings (
                id INTEGER PRIMARY KEY,
                software_name TEXT,
                delete_on_read_default BOOLEAN,
                password_protect_default BOOLEAN,
                show_delete_on_read BOOLEAN,
                show_password_protect BOOLEAN,
                contact_email TEXT,
                title_send_message TEXT,
                title_read_message TEXT,
                title_upload_file TEXT,
                title_download_file TEXT,
                max_file_size INTEGER
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admin (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                must_change_password BOOLEAN
            )
        ''')
        # Insert default settings
        conn.execute('''
            INSERT INTO settings (software_name, delete_on_read_default, password_protect_default, show_delete_on_read, show_password_protect, contact_email, title_send_message, title_read_message, title_upload_file, title_download_file, max_file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            os.environ.get('SOFTWARE_NAME', 'SecureMsg'),
            os.environ.get('DELETE_ON_READ_DEFAULT', 'false').lower() == 'true',
            os.environ.get('PASSWORD_PROTECT_DEFAULT', 'false').lower() == 'true',
            os.environ.get('SHOW_DELETE_ON_READ', 'true').lower() == 'true',
            os.environ.get('SHOW_PASSWORD_PROTECT', 'true').lower() == 'true',
            os.environ.get('CONTACT_EMAIL', 'djenko-it@protonmail.com'),
            os.environ.get('TITLE_SEND_MESSAGE', 'Envoyer un Message Sécurisé'),
            os.environ.get('TITLE_READ_MESSAGE', 'Lire le Message'),
            os.environ.get('TITLE_UPLOAD_FILE', 'Téléverser un fichier'),
            os.environ.get('TITLE_DOWNLOAD_FILE', 'Télécharger un fichier'),
            int(os.environ.get('MAX_FILE_SIZE', '50'))  # Default max file size to 50 MB
        ))

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def get_settings():
    db = get_db()
    cur = db.execute('SELECT software_name, delete_on_read_default, password_protect_default, show_delete_on_read, show_password_protect, contact_email, title_send_message, title_read_message, title_upload_file, title_download_file, max_file_size FROM settings WHERE id = 1')
    settings = cur.fetchone()
    return {
        'software_name': settings[0],
        'delete_on_read_default': settings[1],
        'password_protect_default': settings[2],
        'show_delete_on_read': settings[3],
        'show_password_protect': settings[4],
        'contact_email': settings[5],
        'title_send_message': settings[6],
        'title_read_message': settings[7],
        'title_upload_file': settings[8],
        'title_download_file': settings[9],
        'max_file_size': settings[10]
    }

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

@app.route('/')
def index():
    form = UploadForm()  # Créez une instance du formulaire
    settings = get_settings()
    return render_template('index.html', form=form, settings=settings)  #

@app.route('/about')
def about():
    settings = get_settings()
    return render_template('about.html', settings=settings)

@app.route('/contact')
def contact():
    settings = get_settings()
    return render_template('contact.html', settings=settings)

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

        upload_folder = current_app.config['UPLOAD_FOLDER']
        os.makedirs(upload_folder, exist_ok=True)
        file_path = safe_join(upload_folder, file_id)
        file.save(file_path)

        with g.db:
            g.db.execute('INSERT INTO files (id, filename, original_filename, expiry, max_downloads, password) VALUES (?, ?, ?, ?, ?, ?)',
                         (file_id, file_id, original_filename, expiry_time, max_downloads, hashed_password))
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

            # Mettre à jour le nombre de vues
            g.db.execute('UPDATE files SET views = views + 1 WHERE id = ?', (file_id,))
            g.db.commit()

            # Préparer la durée restante
            time_remaining = expiry_time - datetime.now()
            days, seconds = time_remaining.days, time_remaining.seconds
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            seconds = seconds % 60
            time_remaining_str = f"{days} jours, {hours} heures, {minutes} minutes et {seconds} secondes"

            return render_template('download.html', 
                                   file_id=file_id, 
                                   original_filename=original_filename, 
                                   expiry_time=expiry_time.strftime('%Y-%m-%d %H:%M:%S'), 
                                   remaining_downloads=remaining_downloads, 
                                   time_remaining_str=time_remaining_str,
                                   settings=get_settings())
        else:
            flash("Le fichier n'a pas été trouvé.")
            return redirect(url_for('file_not_found'))

@app.route('/download_direct/<file_id>')
def download_direct(file_id):
    with g.db:
        cur = g.db.execute('SELECT filename, original_filename FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()

        if row:
            filename, original_filename = row
            file_path = safe_join(current_app.config['UPLOAD_FOLDER'], filename)
            return send_file(file_path, as_attachment=True, attachment_filename=original_filename)
        else:
            flash("Fichier non trouvé.")
            return redirect(url_for('file_not_found'))

@app.route('/preview/<file_id>')
def preview_file(file_id):
    with g.db:
        cur = g.db.execute('SELECT filename FROM files WHERE id = ?', (file_id,))
        row = cur.fetchone()

        if row:
            filename = row[0]
            file_path = safe_join(current_app.config['UPLOAD_FOLDER'], filename)
            
            # Log the file path
            current_app.logger.info(f"Previewing file at path: {file_path}")
            
            if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                return send_file(file_path, mimetype='image/jpeg')
            elif filename.lower().endswith('.pdf'):
                return send_file(file_path, mimetype='application/pdf')
            else:
                flash("Aperçu non disponible pour ce type de fichier.")
                return redirect(url_for('download_file', file_id=file_id))
        else:
            flash("Fichier non trouvé.")
            return redirect(url_for('file_not_found'))

@app.route('/file_not_found')
def file_not_found():
    settings = get_settings()
    return render_template('file_not_found.html', settings=settings)

@app.route('/file_expired')
def file_expired():
    settings = get_settings()
    return render_template('file_expired.html', settings=settings)

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
