from flask import Blueprint, request, jsonify, current_app
from app.database import db
from app.models import ScannedURL
from app.services.virustotal_api import check_url_with_virustotal
from app.services.google_safe_browsing_api import check_url_with_google_safe_browsing
from app.services.urlscan_api import check_url_with_urlscan
from datetime import datetime, timezone
import concurrent.futures

scan_bp = Blueprint('scan', __name__)


def _run_with_context(app, func, *args, **kwargs):
    """Membungkus eksekusi fungsi agar tetap memiliki Flask Application Context di dalam thread."""
    with app.app_context():
        return func(*args, **kwargs)


def _run_all_checks(target_url: str) -> dict:
    """
    Menjalankan ketiga API secara paralel menggunakan ThreadPoolExecutor.
    Mengembalikan dictionary berisi hasil dari masing-masing API.
    """
    # Ambil objek aplikasi sebenarnya sebelum masuk ke thread
    app = current_app._get_current_object()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_vt      = executor.submit(_run_with_context, app, check_url_with_virustotal, target_url)
        future_gsb     = executor.submit(_run_with_context, app, check_url_with_google_safe_browsing, target_url)
        future_urlscan = executor.submit(_run_with_context, app, check_url_with_urlscan, target_url)

        return {
            "virustotal": future_vt.result(),
            "gsb":        future_gsb.result(),
            "urlscan":    future_urlscan.result(),
        }


@scan_bp.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()

    # 1. Validasi Input
    if not data or 'url' not in data or not data['url'].strip():
        return jsonify({"success": False, "message": "URL wajib diisi"}), 400

    target_url = data['url'].strip()

    try:
        # 2. Cek Database Lokal Terlebih Dahulu (Caching Strategy)
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

        # 3. Jalankan semua API secara paralel
        api_results = _run_all_checks(target_url)

        # 4. Evaluasi hasil: jika ADA SATU API yang menyatakan Phishing → langsung berbahaya
        detected_by  = []   # daftar API yang mendeteksi ancaman
        has_any_data = False  # minimal 1 API berhasil memberi keputusan

        for api_name, result in api_results.items():
            # Skip hasil error dan no_data (URLScan belum punya data URL ini)
            if "error" in result or result.get("status") == "no_data":
                continue

            has_any_data = True  # ada API yang berhasil memberi data

            if result.get("status") == "Phishing":
                detected_by.append(result.get("source", api_name))

        # 5. Jika semua API gagal (error) → 502
        if not has_any_data:
            errors = [r.get("error", "unknown error") for r in api_results.values()
                      if "error" in r]
            return jsonify({
                "success": False,
                "message": f"Semua API gagal merespons: {'; '.join(errors)}"
            }), 502

        # 6. Tentukan status akhir
        final_status = "Phishing" if detected_by else "Aman"
        source_label = (
            f"Terdeteksi oleh: {', '.join(detected_by)}"
            if detected_by
            else "Google Safe Browsing API, VirusTotal API, URLScan.io"
        )

        # 7. Simpan ke Database Lokal
        new_scan = ScannedURL(url=target_url, status=final_status)
        db.session.add(new_scan)
        db.session.commit()

        return jsonify({
            "success": True,
            "data": {
                "url": target_url,
                "status": final_status,
                "source": source_label,
                "checked_at": datetime.now(timezone.utc).isoformat()
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": f"Terjadi kesalahan: {str(e)}"}), 500


@scan_bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        total_scanned  = ScannedURL.query.count()
        total_phishing = ScannedURL.query.filter_by(status='Phishing').count()

        return jsonify({
            "success": True,
            "data": {
                "total_scanned_urls":    total_scanned,
                "total_phishing_detected": total_phishing
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": "Gagal mengambil statistik"}), 500