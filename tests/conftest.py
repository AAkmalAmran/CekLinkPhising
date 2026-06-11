import pytest
from unittest.mock import patch
from app import create_app
from app.database import db as _db

TEST_CONFIG = {
    'TESTING': True,
    'SQLALCHEMY_DATABASE_URI': 'sqlite:///:memory:',
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    # Override engine options: ssl_context hanya untuk pg8000/PostgreSQL, bukan SQLite
    'SQLALCHEMY_ENGINE_OPTIONS': {},
    'PHISHTANK_API_KEY': None,
    'GOOGLE_SAFE_BROWSING_API_KEY': 'fake-key-for-testing',
    'PROPAGATE_EXCEPTIONS': False,
}


@pytest.fixture(scope='session')
def app():
    """Membuat instance Flask app khusus untuk testing dengan SQLite in-memory.
    
    Config override diteruskan langsung ke create_app() agar SQLite URI
    diterapkan sebelum engine database dibuat — mencegah koneksi ke PostgreSQL.
    """
    app = create_app(test_config=TEST_CONFIG)

    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    """Membuat test client Flask."""
    return app.test_client()


@pytest.fixture(scope='function', autouse=True)
def clean_db(app):
    """Bersihkan data antar setiap test agar test terisolasi."""
    yield
    with app.app_context():
        for table in reversed(_db.metadata.sorted_tables):
            _db.session.execute(table.delete())
        _db.session.commit()
