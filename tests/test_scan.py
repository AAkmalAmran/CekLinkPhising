import json
import pytest
from unittest.mock import patch
from app.models import ScannedURL
from app.database import db

# Mock path untuk kedua API
MOCK_VT  = 'app.routes.scan.check_url_with_virustotal'
MOCK_GSB = 'app.routes.scan.check_url_with_google_safe_browsing'


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
        """URL yang sudah ada di DB harus dikembalikan dari cache, kedua API tidak dipanggil."""
        with app.app_context():
            cached = ScannedURL(url='http://cached-phish.com', status='Phishing')
            db.session.add(cached)
            db.session.commit()

        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            response = client.post('/api/v1/scan', json={'url': 'http://cached-phish.com'})
            mock_vt.assert_not_called()
            mock_gsb.assert_not_called()

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

        with patch(MOCK_VT), patch(MOCK_GSB):
            response = client.post('/api/v1/scan', json={'url': 'http://cached-safe.com'})

        data = response.get_json()
        assert 'url' in data['data']
        assert 'status' in data['data']
        assert 'source' in data['data']
        assert 'checked_at' in data['data']

    # --- VirusTotal API: Tahap Pertama ---

    def test_scan_calls_virustotal_first(self, client):
        """URL baru harus memanggil VirusTotal terlebih dahulu."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            mock_vt.return_value = {'status': 'Aman', 'source': 'VirusTotal API'}
            response = client.post('/api/v1/scan', json={'url': 'http://url-baru-vt.com'})
            mock_vt.assert_called_once_with('http://url-baru-vt.com')
            mock_gsb.assert_not_called()  # GSB tidak perlu dipanggil jika VT berhasil

        assert response.status_code == 200

    def test_scan_phishing_detected_by_virustotal(self, client):
        """URL phishing yang terdeteksi VirusTotal harus mengembalikan status 'Phishing'."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB):
            mock_vt.return_value = {'status': 'Phishing', 'source': 'VirusTotal API'}
            response = client.post('/api/v1/scan', json={'url': 'http://phishing-vt.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Phishing'
        assert data['data']['source'] == 'VirusTotal API'

    def test_scan_safe_url_via_virustotal(self, client):
        """URL aman yang dikonfirmasi VirusTotal harus mengembalikan status 'Aman'."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB):
            mock_vt.return_value = {'status': 'Aman', 'source': 'VirusTotal API'}
            response = client.post('/api/v1/scan', json={'url': 'http://aman-vt.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Aman'
        assert data['data']['source'] == 'VirusTotal API'

    def test_scan_saves_result_after_virustotal(self, client, app):
        """Hasil dari VirusTotal harus disimpan ke database."""
        url = 'http://save-vt-to-db.com'
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB):
            mock_vt.return_value = {'status': 'Phishing', 'source': 'VirusTotal API'}
            client.post('/api/v1/scan', json={'url': url})

        with app.app_context():
            saved = ScannedURL.query.filter_by(url=url).first()
            assert saved is not None
            assert saved.status == 'Phishing'

    # --- Fallback ke Google Safe Browsing ---

    def test_scan_falls_back_to_gsb_when_vt_errors(self, client):
        """Jika VirusTotal error (rate-limit, timeout, dll), harus fallback ke GSB."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            mock_vt.return_value  = {'error': 'VirusTotal rate limit tercapai, coba lagi nanti'}
            mock_gsb.return_value = {'status': 'Aman'}
            response = client.post('/api/v1/scan', json={'url': 'http://fallback-gsb.com'})
            mock_gsb.assert_called_once_with('http://fallback-gsb.com')

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['source'] == 'Google Safe Browsing API'

    def test_scan_phishing_detected_by_gsb_fallback(self, client):
        """URL phishing yang terdeteksi GSB (setelah VT gagal) harus mengembalikan 'Phishing'."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            mock_vt.return_value  = {'error': 'URL belum pernah dianalisis oleh VirusTotal'}
            mock_gsb.return_value = {'status': 'Phishing'}
            response = client.post('/api/v1/scan', json={'url': 'http://phishing-gsb-fallback.com'})

        assert response.status_code == 200
        data = response.get_json()
        assert data['success'] is True
        assert data['data']['status'] == 'Phishing'
        assert data['data']['source'] == 'Google Safe Browsing API'

    def test_scan_saves_result_after_gsb_fallback(self, client, app):
        """Hasil dari GSB (fallback) harus disimpan ke database."""
        url = 'http://save-gsb-fallback-to-db.com'
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            mock_vt.return_value  = {'error': 'VirusTotal rate limit tercapai, coba lagi nanti'}
            mock_gsb.return_value = {'status': 'Aman'}
            client.post('/api/v1/scan', json={'url': url})

        with app.app_context():
            saved = ScannedURL.query.filter_by(url=url).first()
            assert saved is not None
            assert saved.status == 'Aman'

    # --- Semua API Gagal ---

    def test_scan_returns_502_when_both_apis_fail(self, client):
        """Jika kedua API error, harus mengembalikan 502."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB) as mock_gsb:
            mock_vt.return_value  = {'error': 'VirusTotal timeout'}
            mock_gsb.return_value = {'error': 'GSB timeout'}
            response = client.post('/api/v1/scan', json={'url': 'http://both-api-fail.com'})

        assert response.status_code == 502
        data = response.get_json()
        assert data['success'] is False

    # --- Struktur Respons ---

    def test_scan_response_has_checked_at_field(self, client):
        """Respons dari API harus memiliki field 'checked_at'."""
        with patch(MOCK_VT) as mock_vt, patch(MOCK_GSB):
            mock_vt.return_value = {'status': 'Aman', 'source': 'VirusTotal API'}
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
