import pytest
from unittest.mock import patch
from app.models import ScannedURL
from app.database import db

# Mock path ketiga API di dalam modul routes/scan.py
MOCK_VT      = 'app.routes.scan.check_url_with_virustotal'
MOCK_GSB     = 'app.routes.scan.check_url_with_google_safe_browsing'
MOCK_URLSCAN = 'app.routes.scan.check_url_with_urlscan'

# Helper: mock default semua API mengembalikan "Aman"
ALL_SAFE = {
    MOCK_VT:      {'status': 'Aman',    'source': 'VirusTotal API'},
    MOCK_GSB:     {'status': 'Aman'},
    MOCK_URLSCAN: {'status': 'Aman',    'source': 'URLScan.io'},
}


def patch_all_apis(overrides=None):
    """
    Context manager helper: patch ketiga API sekaligus.
    `overrides` adalah dict {MOCK_PATH: return_value} untuk menimpa nilai default.
    """
    values = {**ALL_SAFE, **(overrides or {})}
    return (
        patch(MOCK_VT,      return_value=values[MOCK_VT]),
        patch(MOCK_GSB,     return_value=values[MOCK_GSB]),
        patch(MOCK_URLSCAN, return_value=values[MOCK_URLSCAN]),
    )


class TestScanEndpoint:
    """Test suite untuk endpoint POST /api/v1/scan"""

    # ── Validasi Input ────────────────────────────────────────────────────────

    def test_scan_missing_body_returns_400(self, client):
        """Request JSON tanpa key 'url' harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={})
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_scan_missing_url_key_returns_400(self, client):
        """Request tanpa key 'url' harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={'bukan_url': 'http://test.com'})
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_scan_empty_url_returns_400(self, client):
        """URL whitespace harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={'url': '   '})
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    def test_scan_empty_string_url_returns_400(self, client):
        """URL string kosong harus mengembalikan 400."""
        response = client.post('/api/v1/scan', json={'url': ''})
        assert response.status_code == 400
        assert response.get_json()['success'] is False

    # ── Caching ───────────────────────────────────────────────────────────────

    def test_scan_returns_cached_result(self, client, app):
        """URL yang sudah ada di DB dikembalikan dari cache; ketiga API tidak dipanggil."""
        with app.app_context():
            db.session.add(ScannedURL(url='http://cached-phish.com', status='Phishing'))
            db.session.commit()

        with patch(MOCK_VT) as mvt, patch(MOCK_GSB) as mgsb, patch(MOCK_URLSCAN) as mus:
            response = client.post('/api/v1/scan', json={'url': 'http://cached-phish.com'})
            mvt.assert_not_called()
            mgsb.assert_not_called()
            mus.assert_not_called()

        data = response.get_json()
        assert response.status_code == 200
        assert data['success'] is True
        assert data['data']['status'] == 'Phishing'
        assert data['data']['source'] == 'Local Database'

    def test_scan_cached_result_has_correct_structure(self, client, app):
        """Respons cache harus punya field: url, status, source, checked_at."""
        with app.app_context():
            db.session.add(ScannedURL(url='http://cached-safe.com', status='Aman'))
            db.session.commit()

        with patch(MOCK_VT), patch(MOCK_GSB), patch(MOCK_URLSCAN):
            response = client.post('/api/v1/scan', json={'url': 'http://cached-safe.com'})

        data = response.get_json()['data']
        for field in ('url', 'status', 'source', 'checked_at'):
            assert field in data

    # ── Semua API dipanggil secara paralel ───────────────────────────────────

    def test_scan_calls_all_three_apis(self, client):
        """Ketiga API harus dipanggil untuk setiap URL baru."""
        url = 'http://all-three-apis.com'
        patches = patch_all_apis()
        with patches[0] as mvt, patches[1] as mgsb, patches[2] as mus:
            client.post('/api/v1/scan', json={'url': url})
            mvt.assert_called_once_with(url)
            mgsb.assert_called_once_with(url)
            mus.assert_called_once_with(url)

    # ── Logika: 1 positif = Phishing ─────────────────────────────────────────

    def test_phishing_if_only_virustotal_detects(self, client):
        """Jika hanya VirusTotal yang mendeteksi Phishing, hasil = Phishing."""
        patches = patch_all_apis({
            MOCK_VT: {'status': 'Phishing', 'source': 'VirusTotal API'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://phish-vt-only.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'
        assert 'VirusTotal API' in data['data']['source']

    def test_phishing_if_only_gsb_detects(self, client):
        """Jika hanya Google Safe Browsing yang mendeteksi Phishing, hasil = Phishing."""
        patches = patch_all_apis({
            MOCK_GSB: {'status': 'Phishing'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://phish-gsb-only.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'

    def test_phishing_if_only_urlscan_detects(self, client):
        """Jika hanya URLScan.io yang mendeteksi Phishing, hasil = Phishing."""
        patches = patch_all_apis({
            MOCK_URLSCAN: {'status': 'Phishing', 'source': 'URLScan.io'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://phish-urlscan-only.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'
        assert 'URLScan.io' in data['data']['source']

    def test_phishing_if_all_three_detect(self, client):
        """Jika ketiga API mendeteksi Phishing, hasil = Phishing."""
        patches = patch_all_apis({
            MOCK_VT:      {'status': 'Phishing', 'source': 'VirusTotal API'},
            MOCK_GSB:     {'status': 'Phishing'},
            MOCK_URLSCAN: {'status': 'Phishing', 'source': 'URLScan.io'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://phish-all.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'

    def test_safe_if_all_apis_say_aman(self, client):
        """Jika ketiga API menyatakan Aman, hasil = Aman."""
        patches = patch_all_apis()  # default: semua Aman
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://semua-aman.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Aman'

    # ── Skenario no_data (URLScan belum punya data) ───────────────────────────

    def test_safe_when_urlscan_has_no_data(self, client):
        """URLScan no_data diabaikan; keputusan diambil dari VT & GSB."""
        patches = patch_all_apis({
            MOCK_URLSCAN: {'status': 'no_data', 'source': 'URLScan.io'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://urlscan-nodata.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Aman'

    def test_phishing_when_vt_detects_and_urlscan_has_no_data(self, client):
        """VT mendeteksi Phishing meskipun URLScan tidak punya data."""
        patches = patch_all_apis({
            MOCK_VT:      {'status': 'Phishing', 'source': 'VirusTotal API'},
            MOCK_URLSCAN: {'status': 'no_data',  'source': 'URLScan.io'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://vt-phish-nodata.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'

    # ── Error API & 502 ───────────────────────────────────────────────────────

    def test_returns_502_when_all_apis_fail(self, client):
        """Jika ketiga API error, harus mengembalikan 502."""
        patches = patch_all_apis({
            MOCK_VT:      {'error': 'VT timeout'},
            MOCK_GSB:     {'error': 'GSB timeout'},
            MOCK_URLSCAN: {'error': 'URLScan timeout'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://all-fail.com'})

        data = response.get_json()
        assert response.status_code == 502
        assert data['success'] is False

    def test_safe_when_one_api_errors_rest_aman(self, client):
        """Jika 1 API error tapi 2 lainnya Aman, hasil = Aman (bukan 502)."""
        patches = patch_all_apis({
            MOCK_VT: {'error': 'VT rate limit'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://one-error.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Aman'

    def test_phishing_when_one_api_errors_one_detects(self, client):
        """Jika 1 API error dan 1 mendeteksi Phishing, hasil tetap = Phishing."""
        patches = patch_all_apis({
            MOCK_VT:  {'error': 'VT rate limit'},
            MOCK_GSB: {'status': 'Phishing'},
        })
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://one-error-one-phish.com'})

        data = response.get_json()
        assert response.status_code == 200
        assert data['data']['status'] == 'Phishing'

    # ── Simpan ke Database ────────────────────────────────────────────────────

    def test_saves_phishing_result_to_db(self, client, app):
        """Hasil Phishing harus tersimpan ke database."""
        url = 'http://save-phish.com'
        patches = patch_all_apis({
            MOCK_VT: {'status': 'Phishing', 'source': 'VirusTotal API'},
        })
        with patches[0], patches[1], patches[2]:
            client.post('/api/v1/scan', json={'url': url})

        with app.app_context():
            saved = ScannedURL.query.filter_by(url=url).first()
            assert saved is not None
            assert saved.status == 'Phishing'

    def test_saves_aman_result_to_db(self, client, app):
        """Hasil Aman harus tersimpan ke database."""
        url = 'http://save-aman.com'
        patches = patch_all_apis()
        with patches[0], patches[1], patches[2]:
            client.post('/api/v1/scan', json={'url': url})

        with app.app_context():
            saved = ScannedURL.query.filter_by(url=url).first()
            assert saved is not None
            assert saved.status == 'Aman'

    # ── Struktur Respons ──────────────────────────────────────────────────────

    def test_response_has_checked_at_field(self, client):
        """Respons harus memiliki field 'checked_at'."""
        patches = patch_all_apis()
        with patches[0], patches[1], patches[2]:
            response = client.post('/api/v1/scan', json={'url': 'http://cek-waktu.com'})

        assert 'checked_at' in response.get_json()['data']


class TestStatsEndpoint:
    """Test suite untuk endpoint GET /api/v1/stats"""

    def test_stats_returns_200(self, client):
        """Stats endpoint harus mengembalikan 200."""
        response = client.get('/api/v1/stats')
        assert response.status_code == 200

    def test_stats_response_structure(self, client):
        """Respons stats harus memiliki field yang benar."""
        data = client.get('/api/v1/stats').get_json()
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

        data = client.get('/api/v1/stats').get_json()
        assert data['data']['total_scanned_urls'] == 3
        assert data['data']['total_phishing_detected'] == 2
