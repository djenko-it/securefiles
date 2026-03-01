"""
Tests de l'application SecureFiles.

Couverture :
- Routes de base (index, pages d'erreur)
- Upload de fichiers (valide, invalide)
- Download (fichier valide, expiré, limite atteinte)
- Protection par mot de passe
- download_direct : sécurité (bypass impossible), téléchargement réel
- Régression : strptime sans microsecondes
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
    """Configure l'app avec une base et un dossier temporaires pour chaque test."""
    db_path = str(tmp_path / 'test.db')
    upload_path = str(tmp_path / 'uploads')
    os.makedirs(upload_path)

    flask_app.DATABASE = db_path
    flask_app.app.config['UPLOAD_FOLDER'] = upload_path
    flask_app.app.config['TESTING'] = True
    flask_app.app.config['WTF_CSRF_ENABLED'] = False
    flask_app.app.config['SECRET_KEY'] = 'test-secret-key'

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
    """Poste un fichier et retourne la réponse."""
    data = {
        'file': (io.BytesIO(content), filename),
        'expiry': expiry,
        'max_downloads': max_downloads,
        'password': password,
    }
    return client.post('/upload', data=data, content_type='multipart/form-data')


def file_id_from(response):
    """Extrait le file_id du JSON retourné par /upload."""
    data = response.get_json()
    assert data['success'] is True, f"Upload failed: {data}"
    return data['link'].split('/download/')[-1]


def set_expiry_in_db(file_id, delta):
    """Met à jour l'expiration d'un fichier dans la base."""
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
        r = do_upload(client, filename='virus.exe')
        assert r.get_json()['success'] is False

    def test_upload_pdf(self, client):
        r = do_upload(client, filename='doc.pdf', content=b'%PDF-1.4')
        assert r.get_json()['success'] is True

    def test_upload_cree_entree_bdd(self, client):
        do_upload(client)
        conn = sqlite3.connect(flask_app.DATABASE)
        count = conn.execute('SELECT COUNT(*) FROM files').fetchone()[0]
        conn.close()
        assert count == 1

    def test_upload_sans_fichier(self, client):
        # Fichier avec un nom vide → allowed_file('') retourne False
        r = do_upload(client, filename='', content=b'')
        assert r.get_json()['success'] is False


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
        set_expiry_in_db(fid, timedelta(hours=-1))  # expiration dans le passé

        r = client.get(f'/download/{fid}')
        assert r.status_code == 302
        assert 'file_expired' in r.headers['Location']

    def test_regression_strptime_sans_microsecondes(self, client):
        """Bug #2 : une date sans microsecondes ne doit pas crasher."""
        fid = file_id_from(do_upload(client))
        set_expiry_in_db(fid, timedelta(hours=1))  # format sans .%f

        r = client.get(f'/download/{fid}')
        assert r.status_code == 200  # ne doit pas lever ValueError

    def test_limite_telechargements_atteinte(self, client):
        fid = file_id_from(do_upload(client, max_downloads='1'))
        set_views_in_db(fid, 1)  # déjà téléchargé 1 fois

        r = client.get(f'/download/{fid}')
        assert r.status_code == 302
        assert 'file_not_found' in r.headers['Location']

    def test_illimite_ne_bloque_pas(self, client):
        fid = file_id_from(do_upload(client, max_downloads='unlimited'))
        set_views_in_db(fid, 9999)

        r = client.get(f'/download/{fid}')
        assert r.status_code == 200


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
# download_direct — téléchargement réel
# ---------------------------------------------------------------------------

class TestDownloadDirect:
    def test_telechargement_valide(self, client):
        fid = file_id_from(do_upload(client))
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 200

    def test_incremente_vues(self, client):
        fid = file_id_from(do_upload(client))
        client.get(f'/download_direct/{fid}')
        conn = sqlite3.connect(flask_app.DATABASE)
        views = conn.execute('SELECT views FROM files WHERE id = ?', (fid,)).fetchone()[0]
        conn.close()
        assert views == 1

    def test_fichier_introuvable(self, client):
        r = client.get('/download_direct/uuid-inexistant')
        assert r.status_code == 302

    def test_bypass_mdp_impossible_sans_session(self, client):
        """Bug #3 corrigé : download_direct doit rejeter sans authentification."""
        fid = file_id_from(do_upload(client, password='secret'))
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 302
        assert f'/download/{fid}' in r.headers['Location']

    def test_telechargement_avec_session_auth(self, client):
        """Après authentification via download_file, download_direct doit fonctionner."""
        fid = file_id_from(do_upload(client, password='secret'))
        with client.session_transaction() as sess:
            sess[f'auth_{fid}'] = True
        r = client.get(f'/download_direct/{fid}')
        assert r.status_code == 200

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
