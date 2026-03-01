"""
Tests de l'application SecureFiles.

Couverture :
- Routes de base (index, pages d'erreur)
- Upload de fichiers (valide, invalide)
- Download (fichier valide, expiré, limite atteinte)
- Protection par mot de passe
- download_direct : sécurité (bypass impossible), téléchargement réel
- Régression : strptime sans microsecondes
- Authentification : inscription, connexion, déconnexion
- Dashboard : liste des partages, suppression
- Zone de dépôt (drop zone)
"""
import io
import os
import sqlite3
from datetime import datetime, timedelta

import pytest

import app as flask_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_app(tmp_path):
    db_path     = str(tmp_path / 'test.db')
    upload_path = str(tmp_path / 'uploads')
    os.makedirs(upload_path)

    flask_app.DATABASE = db_path
    flask_app.app.config['UPLOAD_FOLDER']     = upload_path
    flask_app.app.config['TESTING']           = True
    flask_app.app.config['WTF_CSRF_ENABLED']  = False
    flask_app.app.config['SECRET_KEY']        = 'test-secret-key'

    flask_app.init_db()
    yield


@pytest.fixture
def client():
    with flask_app.app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def do_upload(client, filename='test.txt', content=b'contenu test',
              expiry='1d', max_downloads='5', password=''):
    data = {
        'file': (io.BytesIO(content), filename),
        'expiry': expiry,
        'max_downloads': max_downloads,
        'password': password,
    }
    return client.post('/upload', data=data, content_type='multipart/form-data')


def file_id_from(response):
    data = response.get_json()
    assert data['success'] is True, f"Upload failed: {data}"
    return data['link'].split('/download/')[-1]


def set_expiry_in_db(file_id, delta):
    ts = (datetime.now() + delta).strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(flask_app.DATABASE)
    conn.execute('UPDATE files SET expiry = ? WHERE id = ?', (ts, file_id))
    conn.commit()
    conn.close()


def set_views_in_db(file_id, views):
    conn = sqlite3.connect(flask_app.DATABASE)
    conn.execute('UPDATE files SET views = ? WHERE id = ?', (views, file_id))
    conn.commit()
    conn.close()


def create_user_in_db(username='alice', password='motdepasse'):
    import uuid
    from werkzeug.security import generate_password_hash
    drop_token = str(uuid.uuid4())
    conn = sqlite3.connect(flask_app.DATABASE)
    conn.execute('INSERT INTO users (username, password, drop_token) VALUES (?, ?, ?)',
                 (username, generate_password_hash(password), drop_token))
    conn.commit()
    row = conn.execute('SELECT id, drop_token FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return row[0], row[1]   # user_id, drop_token


def login_user_client(client, username='alice', password='motdepasse'):
    return client.post('/login', data={'username': username, 'password': password})


# ---------------------------------------------------------------------------
# Routes de base
# ---------------------------------------------------------------------------

class TestIndex:
    def test_returns_200(self, client):
        assert client.get('/').status_code == 200

    def test_contains_dropzone(self, client):
        assert b'dropzone' in client.get('/').data


class TestErrorPages:
    def test_file_not_found_page(self, client):
        assert client.get('/file_not_found').status_code == 200

    def test_file_expired_page(self, client):
        assert client.get('/file_expired').status_code == 200


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

class TestUpload:
    def test_upload_fichier_valide(self, client):
        r = do_upload(client)
        data = r.get_json()
        assert data['success'] is True
        assert '/download/' in data['link']

    def test_upload_extension_invalide(self, client):
        assert do_upload(client, filename='virus.exe').get_json()['success'] is False

    def test_upload_pdf(self, client):
        assert do_upload(client, filename='doc.pdf', content=b'%PDF').get_json()['success'] is True

    def test_upload_cree_entree_bdd(self, client):
        do_upload(client)
        conn = sqlite3.connect(flask_app.DATABASE)
        count = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
        conn.close()
        assert count == 1

    def test_upload_sans_fichier(self, client):
        assert do_upload(client, filename='', content=b'').get_json()['success'] is False

    def test_upload_associe_utilisateur_connecte(self, client):
        create_user_in_db()
        login_user_client(client)
        fid = file_id_from(do_upload(client))
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute('SELECT owner_id FROM files WHERE id = ?', (fid,)).fetchone()
        conn.close()
        assert row[0] is not None

    def test_upload_sans_compte_owner_null(self, client):
        fid = file_id_from(do_upload(client))
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute('SELECT owner_id FROM files WHERE id = ?', (fid,)).fetchone()
        conn.close()
        assert row[0] is None


# ---------------------------------------------------------------------------
# Download (page d'info)
# ---------------------------------------------------------------------------

class TestDownload:
    def test_fichier_valide(self, client):
        fid = file_id_from(do_upload(client))
        r = client.get(f'/download/{fid}')
        assert r.status_code == 200
        assert b'test.txt' in r.data

    def test_fichier_introuvable(self, client):
        r = client.get('/download/uuid-inexistant')
        assert r.status_code == 302
        assert 'file_not_found' in r.headers['Location']

    def test_fichier_expire(self, client):
        fid = file_id_from(do_upload(client))
        set_expiry_in_db(fid, timedelta(hours=-1))
        r = client.get(f'/download/{fid}')
        assert r.status_code == 302
        assert 'file_expired' in r.headers['Location']

    def test_regression_strptime_sans_microsecondes(self, client):
        fid = file_id_from(do_upload(client))
        set_expiry_in_db(fid, timedelta(hours=1))
        assert client.get(f'/download/{fid}').status_code == 200

    def test_limite_telechargements_atteinte(self, client):
        fid = file_id_from(do_upload(client, max_downloads='1'))
        set_views_in_db(fid, 1)
        r = client.get(f'/download/{fid}')
        assert r.status_code == 302
        assert 'file_not_found' in r.headers['Location']

    def test_illimite_ne_bloque_pas(self, client):
        fid = file_id_from(do_upload(client, max_downloads='unlimited'))
        set_views_in_db(fid, 9999)
        assert client.get(f'/download/{fid}').status_code == 200


# ---------------------------------------------------------------------------
# Protection par mot de passe
# ---------------------------------------------------------------------------

class TestMotDePasse:
    def test_get_affiche_formulaire(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        r = client.get(f'/download/{fid}')
        assert r.status_code == 200
        assert b'password' in r.data.lower()

    def test_mauvais_mot_de_passe(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        r = client.post(f'/download/{fid}', data={'password': 'mauvais'})
        assert r.status_code == 200
        assert 'incorrect' in r.data.decode().lower()

    def test_bon_mot_de_passe(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        r = client.post(f'/download/{fid}', data={'password': 'secret'})
        assert r.status_code == 200
        assert b'test.txt' in r.data

    def test_bon_mot_de_passe_cree_session(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        client.post(f'/download/{fid}', data={'password': 'secret'})
        with client.session_transaction() as sess:
            assert sess.get(f'auth_{fid}') is True


# ---------------------------------------------------------------------------
# download_direct
# ---------------------------------------------------------------------------

class TestDownloadDirect:
    def test_telechargement_valide(self, client):
        fid = file_id_from(do_upload(client))
        assert client.get(f'/download_direct/{fid}').status_code == 200

    def test_incremente_vues(self, client):
        fid = file_id_from(do_upload(client))
        client.get(f'/download_direct/{fid}')
        conn = sqlite3.connect(flask_app.DATABASE)
        views = conn.execute('SELECT views FROM files WHERE id = ?', (fid,)).fetchone()[0]
        conn.close()
        assert views == 1

    def test_fichier_introuvable(self, client):
        assert client.get('/download_direct/uuid-inexistant').status_code == 302

    def test_bypass_mdp_impossible_sans_session(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 302
        assert f'/download/{fid}' in r.headers['Location']

    def test_telechargement_avec_session_auth(self, client):
        fid = file_id_from(do_upload(client, password='secret'))
        with client.session_transaction() as sess:
            sess[f'auth_{fid}'] = True
        assert client.get(f'/download_direct/{fid}').status_code == 200

    def test_expire_redirige(self, client):
        fid = file_id_from(do_upload(client))
        set_expiry_in_db(fid, timedelta(hours=-1))
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 302
        assert 'file_expired' in r.headers['Location']

    def test_limite_atteinte_redirige(self, client):
        fid = file_id_from(do_upload(client, max_downloads='1'))
        set_views_in_db(fid, 1)
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 302
        assert 'file_not_found' in r.headers['Location']


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------

class TestAuth:
    def test_register_page(self, client):
        assert client.get('/register').status_code == 200

    def test_login_page(self, client):
        assert client.get('/login').status_code == 200

    def test_register_cree_compte(self, client):
        client.post('/register', data={
            'username': 'alice', 'password': 'motdepasse', 'confirm': 'motdepasse'
        })
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()
        conn.close()
        assert row is not None

    def test_register_doublon_echoue(self, client):
        create_user_in_db()
        r = client.post('/register', data={
            'username': 'alice', 'password': 'motdepasse', 'confirm': 'motdepasse'
        })
        assert 'déjà pris' in r.data.decode()

    def test_login_valide_redirige_dashboard(self, client):
        create_user_in_db()
        r = login_user_client(client)
        assert r.status_code == 302
        assert 'dashboard' in r.headers['Location']

    def test_login_mauvais_mdp(self, client):
        create_user_in_db()
        r = login_user_client(client, password='mauvais')
        assert r.status_code == 200
        assert 'incorrects' in r.data.decode().lower()

    def test_logout_redirige_accueil(self, client):
        create_user_in_db()
        login_user_client(client)
        r = client.get('/logout')
        assert r.status_code == 302

    def test_dashboard_sans_login_redirige_login(self, client):
        r = client.get('/dashboard')
        assert r.status_code == 302
        assert 'login' in r.headers['Location']


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class TestDashboard:
    def test_dashboard_connecte(self, client):
        create_user_in_db()
        login_user_client(client)
        r = client.get('/dashboard')
        assert r.status_code == 200

    def test_dashboard_affiche_fichier_utilisateur(self, client):
        create_user_in_db()
        login_user_client(client)
        do_upload(client)
        r = client.get('/dashboard')
        assert b'test.txt' in r.data

    def test_delete_file_owner(self, client):
        create_user_in_db()
        login_user_client(client)
        fid = file_id_from(do_upload(client))
        client.post(f'/delete/{fid}')
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute('SELECT id FROM files WHERE id = ?', (fid,)).fetchone()
        conn.close()
        assert row is None

    def test_delete_file_non_owner_ignore(self, client):
        create_user_in_db('alice')
        login_user_client(client, 'alice')
        fid = file_id_from(do_upload(client))
        # Bob tente la suppression
        client.get('/logout')
        create_user_in_db('bob', 'mdp')
        login_user_client(client, 'bob', 'mdp')
        client.post(f'/delete/{fid}')
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute('SELECT id FROM files WHERE id = ?', (fid,)).fetchone()
        conn.close()
        assert row is not None


# ---------------------------------------------------------------------------
# Zone de dépôt (drop zone)
# ---------------------------------------------------------------------------

class TestDropZone:
    def test_drop_page_valide(self, client):
        _, token = create_user_in_db()
        r = client.get(f'/drop/{token}')
        assert r.status_code == 200
        assert b'alice' in r.data

    def test_drop_token_invalide(self, client):
        r = client.get('/drop/token-inexistant')
        assert r.status_code == 302
        assert 'file_not_found' in r.headers['Location']

    def test_drop_upload_fichier(self, client):
        uid, token = create_user_in_db()
        r = client.post(f'/drop/{token}', data={
            'file': (io.BytesIO(b'contenu'), 'rapport.txt'),
            'sender_name': 'Bob',
        }, content_type='multipart/form-data')
        assert r.status_code == 200
        assert b'envoy' in r.data.lower()

    def test_drop_fichier_dans_bdd(self, client):
        uid, token = create_user_in_db()
        client.post(f'/drop/{token}', data={
            'file': (io.BytesIO(b'contenu'), 'rapport.txt'),
            'sender_name': 'Bob',
        }, content_type='multipart/form-data')
        conn = sqlite3.connect(flask_app.DATABASE)
        row = conn.execute('SELECT deposited_by FROM files WHERE owner_id = ?', (uid,)).fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 'Bob'

    def test_drop_extension_invalide(self, client):
        _, token = create_user_in_db()
        r = client.post(f'/drop/{token}', data={
            'file': (io.BytesIO(b'exe'), 'virus.exe'),
        }, content_type='multipart/form-data')
        assert r.status_code == 200
        # On error, the success card is NOT shown; an error flash is shown instead
        assert 'fichier envoyé' not in r.data.decode('utf-8').lower()
        assert 'non aut' in r.data.decode('utf-8').lower()
