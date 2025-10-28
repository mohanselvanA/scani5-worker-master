from sqlalchemy.orm import Session
from app.models.models_worker import Organization

def seed_initial_data(session: Session):
    if not session.query(Organization).filter_by(org_hash="samplehashvalue1234567890abcdef").first():
        org = Organization(
            org_name="Test Organization",
            org_hash="samplehashvalue1234567890abcdef"
        )
        session.add(org)
        session.commit()