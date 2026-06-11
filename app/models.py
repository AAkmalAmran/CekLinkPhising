from app.database import db
from datetime import datetime, timezone
import uuid

class ScannedURL(db.Model):
    __tablename__ = 'scanned_urls'

    # Menggunakan SQLAlchemy Uuid agar kompatibel dengan SQLite (testing) dan PostgreSQL (produksi)
    id = db.Column(db.Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = db.Column(db.Text, nullable=False, index=True)
    status = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": str(self.id),
            "url": self.url,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }