import os
from dotenv import load_dotenv

# Memuat variabel dari file .env
load_dotenv()

class Config:
    # URL koneksi Supabase
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL')
    # Mematikan fitur pelacakan modifikasi bawaan SQLAlchemy agar memori lebih hemat
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Key PhishTank (jika ada)
    PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY')