from flask import Blueprint, jsonify
from app.database import db
from sqlalchemy import text

health_bp = Blueprint('health', __name__)

@health_bp.route('/health', methods=['GET'])
def health_check():
    # Menguji koneksi database dengan query sederhana
    try:
        db.session.execute(text('SELECT 1'))
        db_status = "Connected"
    except Exception as e:
        db_status = "Disconnected"

    return jsonify({
        "status": "OK",
        "database": db_status
    }), 200