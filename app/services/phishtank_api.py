import requests
from flask import current_app

def check_url_with_phishtank(target_url: str) -> dict:
    api_endpoint = "http://checkurl.phishtank.com/checkurl/"
    
    # Mengambil API key dari konfigurasi app
    api_key = current_app.config.get('PHISHTANK_API_KEY')
    
    payload = {
        "url": target_url,
        "format": "json"
    }
    
    if api_key:
        payload["app_key"] = api_key
        
    headers = {
        "User-Agent": "PhishGuard-App/1.0"
    }

    try:
        response = requests.post(api_endpoint, data=payload, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Logika pembacaan respons PhishTank
            # Cek apakah URL ada di database mereka
            if data.get('results', {}).get('in_database'):
                # Jika ada, cek apakah valid sebagai phishing
                is_phish = data['results'].get('valid', False)
                return {"status": "Phishing" if is_phish else "Aman"}
            else:
                return {"status": "Aman"}
                
        return {"error": f"API Error: HTTP {response.status_code}"}
        
    except requests.exceptions.RequestException as e:
        return {"error": f"Koneksi ke PhishTank gagal: {str(e)}"}