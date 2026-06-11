import requests
import base64
from flask import current_app


def check_url_with_virustotal(target_url: str) -> dict:
    """
    Memeriksa apakah sebuah URL termasuk phishing atau malware
    menggunakan VirusTotal API v3.

    Dokumentasi: https://developers.virustotal.com/reference/url-info

    Cara kerja:
    - URL di-encode dengan Base64URL (tanpa padding) lalu dijadikan ID.
    - Hasil dari 70+ vendor keamanan diambil dari field 'last_analysis_stats'.
    - Jika ada vendor yang menandai 'malicious' atau 'suspicious', URL dianggap berbahaya.

    Returns:
        {"status": "Phishing", "source": "VirusTotal API"} jika URL berbahaya
        {"status": "Aman",     "source": "VirusTotal API"} jika URL aman
        {"error": "..."}                                    jika terjadi error
    """
    api_key = current_app.config.get('VIRUSTOTAL_API_KEY')

    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY tidak ditemukan di konfigurasi server"}

    # Encode URL ke format Base64URL (tanpa padding '=') sesuai standar VirusTotal
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().rstrip("=")

    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(api_endpoint, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            malicious_count  = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            if malicious_count > 0 or suspicious_count > 0:
                return {
                    "status": "Phishing",
                    "source": "VirusTotal API",
                    "detail": f"{malicious_count} vendor mendeteksi malicious, {suspicious_count} suspicious"
                }
            else:
                return {"status": "Aman", "source": "VirusTotal API"}

        # 404 = URL belum pernah dianalisis VirusTotal → tidak bisa memberi keputusan
        if response.status_code == 404:
            return {"error": "URL belum pernah dianalisis oleh VirusTotal"}

        # 429 = Rate limit (akun gratis: 4 req/menit)
        if response.status_code == 429:
            return {"error": "VirusTotal rate limit tercapai, coba lagi nanti"}

        # Error lainnya dari VirusTotal API
        return {"error": f"VirusTotal API Error: HTTP {response.status_code} - {response.text}"}

    except requests.exceptions.Timeout:
        return {"error": "Koneksi ke VirusTotal API timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Koneksi ke VirusTotal API gagal: {str(e)}"}
