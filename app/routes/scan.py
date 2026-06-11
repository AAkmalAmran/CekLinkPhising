from flask import Blueprint, request, jsonify
from app.database import db
from app.models import ScannedURL
from app.services.phishtank_api import check_url_with_phishtank
from datetime import datetime, timezone

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    
    # 1. Validasi Input
    if not data or 'url' not in data or not data['url'].strip():
        return jsonify({"success": False, "message": "URL wajib diisi"}), 400
        
    target_url = data['url'].strip()
    
    try:
        # 2. Cek Database Lokal Terlebih Dahulu (Caching)
        cached_result = ScannedURL.query.filter_by(url=target_url).first()
        
        if cached_result:
            return jsonify({
                "success": True,
                "data": {
                    "url": cached_result.url,
                    "status": cached_result.status,
                    "source": "Local Database",
                    "checked_at": cached_result.created_at.isoformat() if cached_result.created_at else None
                }
            }), 200

        # 3. Jika tidak ada di lokal, tembak API Eksternal
        api_result = check_url_with_phishtank(target_url)
        
        if "error" in api_result:
            return jsonify({"success": False, "message": api_result["error"]}), 502
            
        status = api_result["status"]
        
        # 4. Simpan hasil dari API ke Database Lokal
        new_scan = ScannedURL(url=target_url, status=status)
        db.session.add(new_scan)
        db.session.commit()
        
        return jsonify({
            "success": True,
            "data": {
                "url": target_url,
                "status": status,
                "source": "PhishTank API",
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500

@scan_bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        total_scanned = ScannedURL.query.count()
        total_phishing = ScannedURL.query.filter_by(status='Phishing').count()
        
        return jsonify({
            "success": True,
            "data": {
                "total_scanned_urls": total_scanned,
                "total_phishing_detected": total_phishing
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": "Gagal mengambil statistik"}), 500