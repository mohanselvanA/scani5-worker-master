from app.core.database import SessionWorker
from app.core.seed_data import seed_initial_data

if __name__ == "__main__":
    db = SessionWorker()
    try:
        seed_initial_data(db)
    finally:
        db.close()