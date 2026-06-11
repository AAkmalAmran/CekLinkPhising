import requests
from flask import current_app


def check_url_with_google_safe_browsing(target_url: str) -> dict:
    """
    Memeriksa apakah sebuah URL termasuk phishing atau malware
    menggunakan Google Safe Browsing API v4.
    
    Dokumentasi: https://developers.google.com/safe-browsing/v4/lookup-api
    
    Returns:
        {"status": "Phishing"} jika URL berbahaya
        {"status": "Aman"}     jika URL aman
        {"error": "..."}       jika terjadi error
    """
    api_key = current_app.config.get('GOOGLE_SAFE_BROWSING_API_KEY')
    
    if not api_key:
        return {"error": "GOOGLE_SAFE_BROWSING_API_KEY tidak ditemukan di konfigurasi server"}
    
    api_endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId":      "PhishGuard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes":      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": target_url}
            ]
        }
    }

    try:
        response = requests.post(api_endpoint, json=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Jika ada 'matches', URL tersebut terdeteksi sebagai ancaman
            if data.get('matches'):
                return {"status": "Phishing"}
            else:
                # Respons kosong {} berarti URL aman
                return {"status": "Aman"}
        
        # Handle error dari API Google (misal: 400 bad request, 403 invalid key)
        return {"error": f"API Error: HTTP {response.status_code} - {response.text}"}
    
    except requests.exceptions.Timeout:
        return {"error": "Koneksi ke Google Safe Browsing API timeout"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Koneksi ke Google Safe Browsing API gagal: {str(e)}"}
