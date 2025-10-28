from app.celery_app import celery_app
from app.core.database import AsyncNVDSessionLocal, AsyncWorkerSessionLocal
from app.models import models_nvd, models_worker
from app.services.cpe_matcher import find_best_cpe_match
import asyncio
from app.tasks.cve_tasks import resolve_cve_task
from app.utils.logging import logger


@celery_app.task(name="app.tasks.cpe_tasks.resolve_cpe_task", bind=True)
def resolve_cpe_task(self, app_name: str, app_version: str, vendor: str, inventory_id: int):
    try:
        asyncio.run(async_resolve_cpe_task(
            app_name, app_version, vendor, inventory_id))
    except Exception as e:
        logger.info(f"[ERROR] CPE task failed: {e}")
        raise self.retry(exc=e, countdown=10, max_retries=3)


async def async_resolve_cpe_task(app_name: str, app_version: str, vendor: str, inventory_id: int):
    async with AsyncNVDSessionLocal() as db_nvd, AsyncWorkerSessionLocal() as db:
        try:
            cpe = await find_best_cpe_match(db_nvd, app_name, app_version, vendor)

            if cpe:
                await db.execute(
                    models_worker.SoftwareInventory.__table__.update()
                    .where(models_worker.SoftwareInventory.id == inventory_id)
                    .values(cpe=cpe)
                )
                await db.commit()
                resolve_cve_task.delay(inventory_id, cpe, app_version)
        except Exception as e:
            await db.rollback()
            raise