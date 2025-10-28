from datetime import datetime
from app.core.database import AsyncNVDSessionLocal, AsyncWorkerSessionLocal
from app.models import models_nvd, models_worker
from app.services.cve_matcher import get_matching_cves
from app.tasks.vuln_tasks import resolve_vuln_task
from app.utils.group_cves import group_cves
import asyncio
from app.celery_app import celery_app
from sqlalchemy import select
from app.utils.logging import logger




@celery_app.task(name="app.tasks.cve_tasks.resolve_cve_task", bind=True)
def resolve_cve_task(self, inventory_id: int, cpe_name: str, version: str):
    try:
        asyncio.run(async_resolve_cve_task(
            self, inventory_id, cpe_name, version))
    except Exception as e:
        logger.info(f"[ERROR] CPE task failed: {e}")
        raise self.retry(exc=e, countdown=10, max_retries=3)


async def async_resolve_cve_task(self, inventory_id: int, cpe_name: str, version: str):
    async with AsyncNVDSessionLocal() as db_nvd, AsyncWorkerSessionLocal() as db:
        try:
            print(
                f"[CVE LOOKUP] inventory_id={inventory_id}, cpe={cpe_name}", flush=True)

        # Run the version-aware CVE matching
            matched_cves = await get_matching_cves(cpe_name, version, db_nvd)
            print(f"[CVE MATCHES] Found {len(matched_cves)} CVEs", flush=True)

            for cve in matched_cves:
                assoc = models_worker.InventoryCVE(
                    software_inventory_id=inventory_id,
                    cve_id=cve.cve_id,
                    created_at=datetime.utcnow()
                )
                try:
                    db.add(assoc)
                    await db.commit()

                except Exception as e:
                    await db.rollback()  # e.g., UniqueConstraint violation
                    print(
                        f"[CVE SKIP] {cve.cve_id} already linked or failed: {e}", flush=True)
            stmt = select(models_worker.SoftwareInventory).filter_by(id=inventory_id)
            result = await db.execute(stmt)
            inventory = result.scalar_one_or_none()
            if not inventory:
                raise Exception("Inventory not found")
            organization_id = inventory.org_id
            grouped = await group_cves(db, db_nvd, inventory_id, organization_id)

            for group in grouped:
                cwe_id = group["cwes"][0] if group["cwes"] else "UNKNOWN"
                cve_jsons = group["cves"]
                software_name = group["software_name"]
                software_version = group["software_version"]
                software_vendor = group["software_vendor"]
                group_id = group["group_id"]
                # Send to LLM vuln summary generator
                resolve_vuln_task.delay(
                    cwe_id, software_name, software_version, software_vendor, cve_jsons, inventory_id, group_id)

        except Exception as e:
            print(f"[ERROR] CVE task failed: {e}", flush=True)
            await db.rollback()
            raise self.retry(exc=e, countdown=10, max_retries=3)
