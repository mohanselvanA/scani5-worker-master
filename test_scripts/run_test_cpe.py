# scripts/resolve_missing_cpe.py
from sqlalchemy.orm import Session
from app.core.database import SessionWorker
from app.models.models_worker import SoftwareInventory
from app.tasks.cve_tasks import resolve_cve_task
from app.core.database import SessionWorker, SessionNVD
from app.services.find_best_cpe import find_best_cpe_match  # <- this is the embedding-enhanced one

def resolve_missing_cpes():
    db: Session = SessionWorker()
    try:
        # Step 1: Get software records with no CPE
        records = db.query(SoftwareInventory).filter(SoftwareInventory.cpe_name == None).all()
        print(f"[INFO] Found {len(records)} inventory entries missing CPE", flush=True)

        for entry in records:
            print(f"\n[PROCESSING] ID={entry.id} App='{entry.name}' Version='{entry.version}' Vendor='{entry.vendor}'")
            db_nvd = SessionNVD()
            cpe = find_best_cpe_match(
                db=db_nvd,
                app_name=entry.name,
                app_version=entry.version,
                vendor=entry.vendor
            )

            if not cpe:
                print(f"[SKIP] No CPE match found for {entry.name} ({entry.vendor})", flush=True)
                continue

            # Step 2: Update record
            entry.cpe_name = cpe
            db.add(entry)
            db.commit()
            print(f"[UPDATED] Set CPE='{cpe}' for inventory ID={entry.id}", flush=True)

            # Step 3: Call CVE enrichment task
            resolve_cve_task.delay(entry.id, cpe, entry.version)
            print(f"[TASK SENT] resolve_cve_task({entry.id}, {cpe}, {entry.version})", flush=True)

    finally:
        db.close()

if __name__ == "__main__":
    resolve_missing_cpes()