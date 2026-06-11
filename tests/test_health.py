import json


class TestHealthEndpoint:
    """Test suite untuk endpoint GET /api/health"""

    def test_health_returns_200(self, client):
        """Health endpoint harus mengembalikan status 200."""
        response = client.get('/api/health')
        assert response.status_code == 200

    def test_health_returns_json(self, client):
        """Health endpoint harus mengembalikan JSON."""
        response = client.get('/api/health')
        assert response.content_type == 'application/json'

    def test_health_response_structure(self, client):
        """Response harus memiliki field 'status' dan 'database'."""
        response = client.get('/api/health')
        data = response.get_json()
        assert 'status' in data
        assert 'database' in data

    def test_health_status_ok(self, client):
        """Field 'status' harus bernilai 'OK'."""
        response = client.get('/api/health')
        data = response.get_json()
        assert data['status'] == 'OK'

    def test_health_db_connected(self, client):
        """Database harus terkoneksi (SQLite in-memory)."""
        response = client.get('/api/health')
        data = response.get_json()
        assert data['database'] == 'Connected'

    def test_404_on_unknown_route(self, client):
        """Route yang tidak ada harus mengembalikan 404."""
        response = client.get('/api/tidak_ada')
        assert response.status_code == 404
        data = response.get_json()
        assert data['success'] is False
