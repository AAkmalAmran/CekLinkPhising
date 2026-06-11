import os
from dotenv import load_dotenv

# Memuat variabel dari file .env
load_dotenv()

class Config:
    # URL koneksi Supabase (Session Pooler, mendukung IPv4)
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    
    # Engine option untuk pg8000: aktifkan SSL agar Supabase mengizinkan koneksi
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {
            "ssl_context": True
        }
    }
    
    # Mematikan fitur pelacakan modifikasi bawaan SQLAlchemy agar memori lebih hemat
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Key Google Safe Browsing
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')
    
    # API Key VirusTotal
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')

    # API Key URLScan.io
    URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY')