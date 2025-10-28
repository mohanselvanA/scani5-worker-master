# app/services/cve_matcher.py
from packaging.version import Version, InvalidVersion
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import models_nvd, models_worker
from sqlalchemy import select

def is_version_in_range(version: str, match: dict) -> bool:
    try:
        target_version = Version(version)
    except InvalidVersion:
        return False

    start_incl = match.get("versionStartIncluding")
    start_excl = match.get("versionStartExcluding")
    end_incl = match.get("versionEndIncluding")
    end_excl = match.get("versionEndExcluding")

    if start_incl and target_version < Version(start_incl):
        return False
    if start_excl and target_version <= Version(start_excl):
        return False
    if end_incl and target_version > Version(end_incl):
        return False
    if end_excl and target_version >= Version(end_excl):
        return False

    return True

async def get_matching_cves(cpe: str, version: str, db: AsyncSession):
    matched_cves = []
    stmt = select(models_nvd.CVEData)
    result = await db.execute(stmt)
    cve_entries = result.scalars().all()

    for cve in cve_entries:
        try:
            nodes = cve.cve_json.get("configurations", {}).get("nodes", [])
            for node in nodes:
                for match in node.get("cpe_match", []):
                    if match.get("vulnerable"):
                        match_cpe = match.get("cpe23Uri", "")
                        # Strip version from provided `cpe` and from match to compare only the base (product identifier)
                        cpe_parts = cpe.split(":")
                        match_parts = match_cpe.split(":")
                        if cpe_parts[:5] == match_parts[:5]:
                            if match_parts[5] != "*":  # If the match explicitly defines a version
                                if match_parts[5] == version:
                                    matched_cves.append(cve)
                                    break
                            elif is_version_in_range(version, match):
                                matched_cves.append(cve)
                                break
        except Exception as e:
            print(f"[WARN] Skipped CVE {cve.cve_id}: {e}", flush=True)

    return matched_cves
