import os
import re
from sqlalchemy import or_
from app.models import models_nvd, models_worker
from app.schemas.agent import AgentPayload, CollectPayload, SoftwareInfo, PatchInfo
from datetime import datetime
from app.services.cpe_matcher import find_best_cpe_match
from fastapi import HTTPException
from app.tasks.cpe_tasks import resolve_cpe_task
from app.utils.software_filters import NoiseFilter
import traceback

noise_filter = NoiseFilter()
from app.core.database import AsyncWorkerDBSession
from sqlalchemy import select, update

from app.utils.logging import logger


async def register_agent(payload: AgentPayload, db: AsyncWorkerDBSession):
    try:
        logger.info(f"Looking for org:, {payload.org_hash}")
        stmt = select(models_worker.Organization).filter_by(org_hash=payload.org_hash)
        org_result = await db.execute(stmt)
        org = org_result.scalar_one_or_none()

        if not org:
            logger.info("Organization not found")
            return {"error": "Invalid organization"}

        logger.info("Organization found:", {org.org_name})
        secret = os.urandom(24).hex()

        agent_stmt = select(models_worker.Agent).filter_by(agent_id=payload.agent_id)
        agent_result = await db.execute(agent_stmt)
        agent = agent_result.scalar_one_or_none()

        if agent:
            logger.info("Agent exists, updating secret")
            agent.secret = secret
        else:
            logger.info("New agent, creating entry")
            agent = models_worker.Agent(
                agent_id=payload.agent_id,
                org_id=org.id,
                secret=secret,
                hostname=payload.hostname,
                ip_address=payload.ip_address,
                os_info=payload.os_info,
                agent_check_in=datetime.utcnow(),
                key_rotated_at=datetime.utcnow(),
                inventory_updated_at=None
            )
            db.add(agent)

        await db.commit()
        return {"secret": secret}

    except Exception as e:
        traceback.print_exc()
        return {"error": "Internal server error", "details": str(e)}


async def ping_agent(payload: AgentPayload, db: AsyncWorkerDBSession):
    try:
       
        stmt = select(models_worker.Agent).filter_by(agent_id=payload.agent_id)
        result = await db.execute(stmt)
        agent = result.scalar_one_or_none()
        if not agent:
            return {"error": "Agent not found"}

        agent.agent_check_in = datetime.utcnow()
        await db.commit()
        return {"status": "pong"}

    except Exception as e:
        print("[EXCEPTION] ping_agent encountered error:", flush=True)
        traceback.print_exc()
        return {"error": "Internal server error", "details": str(e)}


async def collect_data(payload: CollectPayload, db: AsyncWorkerDBSession):
    try:
        result = await db.execute(select(models_worker.Agent).filter_by(agent_id=payload.agent_id))
        agent = result.scalar_one_or_none()

        if not agent:
            raise HTTPException(status_code=403, detail="Agent not found")

        for app in payload.SoftwareInventory:
            if noise_filter.is_noise(app.name, app.vendor):
                # print(f"[FILTERED] Skipping noise: {app.name}", flush=True)
                continue

            sw_kwargs = {
                "org_id": agent.org_id,
                "name": app.name,
                "version": app.version,
                "vendor": app.vendor,
            }

            result = await db.execute(select(models_worker.SoftwareInventory).filter_by(**sw_kwargs))
            software = result.scalar_one_or_none()


            if app.action in ["add", "upgraded_to", "downgraded_to"]:
                if not software:
                    software = models_worker.SoftwareInventory(**sw_kwargs, cpe=None)
                    db.add(software)
                    await db.flush()
                    resolve_cpe_task.delay(app.name, app.version, app.vendor, software.id)

                result = await db.execute(select(models_worker.AgentSoftwareInventory).filter_by(
                    agent_id=agent.id,
                    software_inventory_id=software.id
                ))
                existing_link = result.scalar_one_or_none()

                if not existing_link:
                    link = models_worker.AgentSoftwareInventory(
                        agent_id=agent.id,
                        software_inventory_id=software.id,
                        action=app.action,
                        status="installed"
                    )
                    db.add(link)

            elif app.action in ["remove", "upgraded", "downgraded"]:
                if software:
                    await db.execute(update(models_worker.AgentSoftwareInventory).filter_by(
                        agent_id=agent.id,
                        software_inventory_id=software.id
                    ).values(action=app.action, status="removed"))

        for patch in payload.Patches:
            patch_kwargs = {
                "org_id": agent.org_id,
                "hotfix_id": patch.hotfix_id,
                "description": patch.description,
                "type": patch.type
            }

            result = await db.execute(select(models_worker.OSUpdatesInventory).filter_by(**patch_kwargs))
            os_update = result.scalar_one_or_none()

            if patch.action in ["add", "upgraded_to", "downgraded_to"]:
                if not os_update:
                    os_update = models_worker.OSUpdatesInventory(**patch_kwargs)
                    db.add(os_update)
                    await db.flush()

                result = await db.execute(select(models_worker.AgentOSUpdateInventory).filter_by(
                    agent_id=agent.id,
                    os_update_id=os_update.id
                ))
                existing_link = result.scalar_one_or_none()

                if not existing_link:
                    link = models_worker.AgentOSUpdateInventory(
                        agent_id=agent.id,
                        os_update_id=os_update.id,
                        action=patch.action,
                        status="installed",
                        installed_on=patch.installed_on
                    )
                    db.add(link)

            elif patch.action in ["remove", "upgraded", "downgraded"]:
                if os_update:
                    await db.execute(update(models_worker.AgentOSUpdateInventory).filter_by(
                        agent_id=agent.id,
                        os_update_id=os_update.id
                    ).values(action=patch.action, status="removed", installed_on=patch.installed_on))

        await db.execute(update(models_worker.Agent).filter_by(agent_id=payload.agent_id).values(
            inventory_updated_at=datetime.utcnow()
        ))

        try:
            await db.commit()
            print("[INFO] DB commit successful")
        except Exception as e:
            print(f"[ERROR] DB commit failed: {e}")
            await db.rollback()
        return {"status": "collected"}

    except Exception as e:
        traceback.print_exc()
        await db.rollback()
        return {"error": "Internal server error", "details": str(e)}

async def renew_secret(payload: AgentPayload, db: AsyncWorkerDBSession):
    new_secret = os.urandom(24).hex()
    await db.execute(update(models_worker.Agent).filter_by(agent_id=payload.agent_id).values(
        secret=new_secret,
        key_rotated_at=datetime.utcnow()
    ))
    await db.commit()
    return {"new_secret": new_secret}
