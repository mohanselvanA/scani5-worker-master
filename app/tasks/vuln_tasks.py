from app.services.llm_vulgen_client import get_vul_summary
from app.models import models_nvd, models_worker
from app.core.database import AsyncNVDSessionLocal, AsyncWorkerSessionLocal
from datetime import datetime
from dateutil import parser
import random
import asyncio
from app.celery_app import celery_app
from sqlalchemy import select
from app.utils.logging import logger


def get_max_cvss_scores(cve_jsons: list[dict]) -> dict:
    def extract_float(cve, key):
        try:
            val = cve.get(key)
            return float(val) if val is not None else None
        except (ValueError, TypeError):
            return None

    # Extract all scores
    cvssv2_vals = [extract_float(cve, "cvssv2") for cve in cve_jsons]
    cvssv3_vals = [extract_float(cve, "cvssv3") for cve in cve_jsons]
    exploitscorev2_vals = [extract_float(cve, "exploitscorev2") for cve in cve_jsons]
    exploitscorev3_vals = [extract_float(cve, "exploitscorev3") for cve in cve_jsons]
    impactscorev2_vals = [extract_float(cve, "impactscorev2") for cve in cve_jsons]
    impactscorev3_vals = [extract_float(cve, "impactscorev3") for cve in cve_jsons]

    # Calculate max scores with fallbacks
    cvssv2 = max(cvssv2_vals, key=lambda x: x or 0, default=0.0)
    cvssv3 = max(cvssv3_vals, key=lambda x: x or 0, default=0.0)
    exploitscorev2 = max(exploitscorev2_vals, key=lambda x: x or 0, default=0.0)
    exploitscorev3 = max(exploitscorev3_vals, key=lambda x: x or 0, default=0.0)
    impactscorev2 = max(impactscorev2_vals, key=lambda x: x or 0, default=0.0)
    impactscorev3 = max(impactscorev3_vals, key=lambda x: x or 0, default=0.0)

    # Prioritize v3 values; fallback to v2
    cvss = cvssv3 if cvssv3 else cvssv2
    exploitscore = exploitscorev3 if exploitscorev3 else exploitscorev2
    impactscore = impactscorev3 if impactscorev3 else impactscorev2

    return {
        "cvss": cvss,
        "exploitscore": exploitscore,
        "impactscore": impactscore,
        "cvssv2": cvssv2,
        "exploitscorev2": exploitscorev2,
        "impactscorev2": impactscorev2,
        "cvssv3": cvssv3,
        "exploitscorev3": exploitscorev3,
        "impactscorev3": impactscorev3,
    }

def calculate_car(cvss: float, exploit: float, impact: float) -> float:
    values = [v for v in [cvss, exploit, impact] if isinstance(v, float)]
    return round(sum(values) / len(values), 2) if values else 0.0

from datetime import datetime

def compute_visibility_score(cve_jsons: list[dict]) -> float:
    scores = []
    for cve in cve_jsons:
        pub = cve.get("publishedDate")
        if pub:
            try:
                pub_date = parser.isoparse(pub)
                days_old = (datetime.utcnow() - pub_date).days

                if days_old <= 7:
                    scores.append(1.0)
                elif days_old <= 30:
                    scores.append(0.8)
                elif days_old <= 90:
                    scores.append(0.5)
                else:
                    scores.append(0.2)

            except Exception:
                scores.append(random.uniform(0, 9))
        else:
            scores.append(random.uniform(0, 9))
    
    return round(sum(scores) / len(scores), 2) if scores else random.uniform(0, 9)

@celery_app.task(name="app.tasks.vuln_tasks.resolve_vuln_task", bind=True)
def resolve_vuln_task(cwe_id: str, software_name: str, software_version: str, software_vendor: str, cve_jsons: list, inventory_id: int, group_id: str):
    try:
        asyncio.run(async_resolve_vuln_task(cwe_id, software_name,
                    software_version, software_vendor, cve_jsons, inventory_id, group_id))
    except Exception as e:
        logger.info(f"[ERROR] CPE task failed: {e}")
        raise self.retry(exc=e, countdown=10, max_retries=3)


async def async_resolve_vuln_task(cwe_id: str, software_name: str, software_version: str, software_vendor: str, cve_jsons: list, inventory_id: int, group_id: str):
    async with AsyncNVDSessionLocal() as db_nvd, AsyncWorkerSessionLocal() as db:
        try:
            summary = get_vul_summary(
                cwe_id, software_name, software_version, software_vendor, cve_jsons, group_id)

            # Use first CVE as canonical
            # cve_record = db_nvd.query(models_nvd.CVEData).filter_by(cve_id=cve_jsons[0]["cve_id"]).first()
            # cwe_record = db_nvd.query(models_nvd.CWEData).filter_by(cwe_id=cwe_id).first() if cwe_id != "UNKNOWN" else None

            scores = get_max_cvss_scores(cve_jsons)
            car = calculate_car(
                scores["cvss"], scores["exploitscore"], scores["impactscore"])
            visibility = compute_visibility_score(cve_jsons)

            vuln = models_worker.Vulnerability(
                name=summary.get("name", "Unknown"),
                description=summary.get("description", ""),
                cvss=scores["cvss"],
                exploitscore=scores["exploitscore"],
                impactscore=scores["impactscore"],
                car=car,
                visibility_score=visibility,
            )
            db.add(vuln)
            await db.flush()

            # LLM-generated solution/mitigation
            sol = summary.get("solution", {})
            mit = summary.get("mitigation", {})

            solution = models_worker.Solution(
                vulnerability_id=vuln.id,
                name=sol.get("name", f"Solution for {vuln.name}"),
                description=sol.get("description", ""),
                references=sol.get("references", []),
                release_date=datetime.strptime(
                    sol["release_date"], "%Y-%m-%d") if sol.get("release_date") else None,
                type=sol.get("type", "patch"),
                priority=sol.get("priority", "medium"),
                rollback_available=sol.get("rollback_available", "no")
            )
            db.add(solution)

            mitigation = models_worker.Mitigation(
                vulnerability_id=vuln.id,
                name=mit.get("name", f"Mitigation for {vuln.name}"),
                description=mit.get("description", ""),
                references=mit.get("references", []),
                type=mit.get("type", "configuration"),
                effectiveness=mit.get("effectiveness", "moderate")
            )
            db.add(mitigation)

            # Link to agent via software inventory
            stmt = select(models_worker.AgentSoftwareInventory).filter_by(
                software_inventory_id=inventory_id)
            result = await db.execute(stmt)
            link = result.scalar_one_or_none()

            if link:
                agent_id = link.agent_id
                inventory = link.software

            if inventory:
                db.add(models_worker.AgentVulnerabilityStatus(
                    agent_id=agent_id,
                    vulnerability_id=vuln.id,
                    status="open",
                    cvssv2=scores["cvssv2"],
                    exploitscorev2=scores["exploitscorev2"],
                    impactscorev2=scores["impactscorev2"],
                    cvssv3=scores["cvssv3"],
                    exploitscorev3=scores["exploitscorev3"],
                    impactscorev3=scores["impactscorev3"],
                    car=car,
                    exploit_risk=scores["exploitscore"],
                    impact_risk=scores["impactscore"],
                    visibility_score=visibility
                ))

            await db.commit()
            print(
                f"[VULN SUMMARY] Stored: {vuln.name} (CWE={cwe_id})", flush=True)

            # Link Vulnerability to CVE Group
            org_id = inventory.org_id
            stmt = select(models_worker.CVEGroup).filter_by(
                organization_id=org_id, group_id=group_id)
            result = await db.execute(stmt)
            group = result.scalar_one_or_none()

            if group:
                stmt = select(models_worker.VulnerabilityGroupLink).filter_by(
                    group_id=group.id,
                    vulnerability_id=vuln.id
                )
                result = await db.execute(stmt)
                exists = result.scalar_one_or_none()

                if not exists:
                    db.add(models_worker.VulnerabilityGroupLink(
                        group_id=group.id,
                        vulnerability_id=vuln.id
                    ))
                    await db.commit()
                else:
                    print(
                        f"[SUMMARY] Vulnerability already linked to group {group.group_id}", flush=True)
            else:
                print(
                    f"[SUMMARY] No matching group found for org={org_id}, cwe={cwe_id}", flush=True)

        except Exception as e:
            print(
                f"[VULN ERROR] Failed to generate vuln summary: {e}", flush=True)
            await db.rollback()
