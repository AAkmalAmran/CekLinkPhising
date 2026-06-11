import json
import pytest
from unittest.mock import patch
from app.models import ScannedURL
from app.database import db

# Path mock yang benar: merujuk ke fungsi di dalam modul routes/scan.py
MOCK_TARGET = 'app.routes.scan.check_url_with_google_safe_browsing'


class TestScanEndpoint:
    """Test suite untuk endpoint POST /api/v1/scan"""

    # --- Validasi Input ---

    def test_scan_missing_body_returns_400(self, client):
        """Request JSON tanpa key 'url' harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={})
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    def test_scan_missing_url_key_returns_400(self, client):
        """Request tanpa key 'url' harus mengembalikan 400."""
        response = client.post(
            '/api/v1/scan',
            json={'bukan_url': 'http://test.com'}
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    def test_scan_empty_url_returns_400(self, client):
        """Request dengan URL kosong/whitespace harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={'url': '   '})
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    def test_scan_empty_string_url_returns_400(self, client):
        """Request dengan string kosong harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={'url': ''})
        assert response.status_code == 400
        data = response.get_json()
        assert data['success'] is False

    # --- Caching: Data sudah ada di database ---

    def test_scan_returns_cached_result(self, client, app):
        """URL yang sudah ada di DB harus dikembalikan dari cache, bukan dari API."""
        with app.app_context():
            cached = ScannedURL(url='http://cached-phish.com', status='Phishing')
            db.session.add(cached)
            db.session.commit()

        with patch(MOCK_TARGET) as mock_api:
            response = client.post('/api/v1/scan', json={'url': 'http://cached-phish.com'})
            # Pastikan Google Safe Browsing API TIDAK dipanggil
            mock_api.assert_not_called()

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Phishing'
        assert data['data']['source'] == 'Local Database'

    def test_scan_cached_result_has_correct_structure(self, client, app):
        """Respons cache harus memiliki field: url, status, source, checked_at."""
        with app.app_context():
            cached = ScannedURL(url='http://cached-safe.com', status='Aman')
            db.session.add(cached)
            db.session.commit()

        with patch(MOCK_TARGET):
            response = client.post('/api/v1/scan', json={'url': 'http://cached-safe.com'})

        data = response.get_json()
        assert 'url' in data['data']
        assert 'status' in data['data']
        assert 'source' in data['data']
        assert 'checked_at' in data['data']

    # --- External API: Data belum ada di database ---

    def test_scan_calls_gsb_when_not_cached(self, client):
        """URL baru harus memanggil Google Safe Browsing API."""
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'status': 'Aman'}
            response = client.post('/api/v1/scan', json={'url': 'http://url-baru.com'})
            mock_api.assert_called_once_with('http://url-baru.com')

        assert response.status_code == 200

    def test_scan_saves_result_to_db_after_api_call(self, client, app):
        """Hasil dari Google Safe Browsing API harus disimpan ke database."""
        url = 'http://save-to-db-test.com'
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'status': 'Phishing'}
            client.post('/api/v1/scan', json={'url': url})

        with app.app_context():
            saved = ScannedURL.query.filter_by(url=url).first()
            assert saved is not None
            assert saved.status == 'Phishing'

    def test_scan_phishing_url_via_api(self, client):
        """URL phishing dari GSB harus mengembalikan status 'Phishing'."""
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'status': 'Phishing'}
            response = client.post('/api/v1/scan', json={'url': 'http://phishing-baru.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Phishing'
        assert data['data']['source'] == 'Google Safe Browsing API'

    def test_scan_safe_url_via_api(self, client):
        """URL aman dari GSB harus mengembalikan status 'Aman'."""
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'status': 'Aman'}
            response = client.post('/api/v1/scan', json={'url': 'http://aman-baru.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Aman'

    def test_scan_api_error_returns_502(self, client):
        """Jika Google Safe Browsing API error, harus mengembalikan 502."""
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'error': 'Koneksi ke GSB gagal'}
            response = client.post('/api/v1/scan', json={'url': 'http://error-url.com'})

        assert response.status_code == 502
        data = response.get_json()
        assert data['success'] is False

    def test_scan_response_has_checked_at_field(self, client):
        """Respons dari API harus memiliki field 'checked_at'."""
        with patch(MOCK_TARGET) as mock_api:
            mock_api.return_value = {'status': 'Aman'}
            response = client.post('/api/v1/scan', json={'url': 'http://cek-waktu.com'})

        data = response.get_json()
        assert 'checked_at' in data['data']


class TestStatsEndpoint:
    """Test suite untuk endpoint GET /api/v1/stats"""

    def test_stats_returns_200(self, client):
        """Stats endpoint harus mengembalikan 200."""
        response = client.get('/api/v1/stats')
        assert response.status_code == 200

    def test_stats_response_structure(self, client):
        """Respons stats harus memiliki field 'total_scanned_urls' dan 'total_phishing_detected'."""
        response = client.get('/api/v1/stats')
        data = response.get_json()
        assert data['success'] is True
        assert 'total_scanned_urls' in data['data']
        assert 'total_phishing_detected' in data['data']

    def test_stats_counts_correctly(self, client, app):
        """Statistik harus menghitung data di database dengan benar."""
        with app.app_context():
            db.session.add(ScannedURL(url='http://url1.com', status='Phishing'))
            db.session.add(ScannedURL(url='http://url2.com', status='Aman'))
            db.session.add(ScannedURL(url='http://url3.com', status='Phishing'))
            db.session.commit()

        response = client.get('/api/v1/stats')
        data = response.get_json()
        assert data['data']['total_scanned_urls'] == 3
        assert data['data']['total_phishing_detected'] == 2
