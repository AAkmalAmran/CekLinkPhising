import requests
from flask import current_app


def check_url_with_urlscan(target_url: str) -> dict:
    """
    Memeriksa apakah sebuah URL termasuk phishing/malware
    menggunakan URLScan.io Search API.

    Strategi:
    - Gunakan endpoint Search untuk mencari scan terbaru dari URL tersebut.
      Ini lebih cepat karena tidak perlu menunggu proses scan baru selesai.
    - Jika URLScan.io belum pernah menganalisis URL tersebut, kembalikan
      status 'no_data' (bukan error) agar logika utama tetap bisa lanjut.
    - Jika ada data, periksa field `verdicts.overall.malicious` dan `score`.

    Returns:
        {"status": "Phishing", "source": "URLScan.io"}  jika URL terdeteksi berbahaya
        {"status": "Aman",     "source": "URLScan.io"}  jika URL terdeteksi aman
        {"status": "no_data",  "source": "URLScan.io"}  jika tidak ada data scan
        {"error": "..."}                                  jika terjadi error koneksi
    """
    api_key = current_app.config.get('URLSCAN_API_KEY')

    search_endpoint = "https://urlscan.io/api/v1/search/"
    headers = {}
    if api_key:
        headers["API-Key"] = api_key

    params = {
        # Cari scan berdasarkan URL persis, ambil hasil terbaru
        "q": f'page.url:"{target_url}"',
        "size": 1,
        "sort": "date:desc"
    }

    try:
        response = requests.get(
            search_endpoint,
            headers=headers,
            params=params,
            timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            results = data.get("results", [])

            # Tidak ada hasil scan → URLScan.io belum pernah menganalisis URL ini
            if not results:
                return {"status": "no_data", "source": "URLScan.io"}

            # Ambil scan terbaru
            latest_scan = results[0]
            verdicts = latest_scan.get("verdicts", {})
            overall  = verdicts.get("overall", {})

            is_malicious = overall.get("malicious", False)
            # Score: 0-100, umumnya >= 50 dianggap mencurigakan
            score = overall.get("score", 0)

            if is_malicious or score >= 50:
                return {"status": "Phishing", "source": "URLScan.io"}
            else:
                return {"status": "Aman", "source": "URLScan.io"}

        if response.status_code == 429:
            return {"error": "URLScan.io rate limit tercapai"}

        return {"error": f"URLScan.io API Error: HTTP {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "Koneksi ke URLScan.io timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Koneksi ke URLScan.io gagal: {str(e)}"}
