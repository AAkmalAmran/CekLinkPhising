from flask import Flask, jsonify
from flask_cors import CORS
from app.config import Config
from app.database import db

def create_app(test_config: dict = None):
    app = Flask(__name__)
    
    # Memuat konfigurasi default
    app.config.from_object(Config)
    
    # Jika ada config khusus (misal untuk testing), terapkan sekarang
    # sebelum db.init_app() agar engine dibuat dengan URI yang benar
    if test_config is not None:
        app.config.update(test_config)
    
    CORS(app)
    
    # Menghubungkan database dengan aplikasi Flask
    db.init_app(app)

    # Import dan daftarkan blueprint (routes)
    from app.routes.health import health_bp
    from app.routes.scan import scan_bp

    app.register_blueprint(health_bp, url_prefix='/api')
    app.register_blueprint(scan_bp, url_prefix='/api/v1')

    # Global Error Handler
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'success': False, 'message': 'Endpoint tidak ditemukan'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'success': False, 'message': 'Terjadi kesalahan internal server'}), 500

    return app