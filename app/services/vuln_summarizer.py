# app/services/vuln_summarizer.py
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import models_nvd, models_worker
from app.services.llm_vulgen_client import get_llm_summary_by_cwe  # We'll define this to call LLaMA via LangGraph

def summarize_and_store_vulnerabilities(inventory_id: int, db: Session):
    cve_links = db.query(tables.InventoryCVE).filter_by(software_inventory_id=inventory_id).all()
    if not cve_links:
        print(f"[SUMMARY] No CVEs linked to inventory {inventory_id}", flush=True)
        return

    inventory = db.query(tables.SoftwareInventory).filter_by(id=inventory_id).first()
    if not inventory:
        print(f"[ERROR] Inventory ID {inventory_id} not found", flush=True)
        return

    agent_id = inventory.agent_id
    software_name = inventory.name
    software_version = inventory.version
    software_vendor = inventory.vendor

    cve_map = {}
    for link in cve_links:
        cve = db.query(tables.CVEData).filter_by(id=link.cve_id).first()
        if not cve:
            continue
        cwe_id = extract_cwe_id(cve)
        if cwe_id:
            cve_map.setdefault(cwe_id, []).append(cve)

    for cwe_id, cves in cve_map.items():
        cve_ids = [cve.cve_id for cve in cves]
        print(f"[SUMMARY] CWE {cwe_id} → CVEs: {cve_ids}", flush=True)

        result = get_vul_summary(
            cwe_id,
            software_name=software_name,
            software_version=software_version,
            software_vendor=software_vendor,
            cve_jsons=[cve.cve_json for cve in cves]
        )

        vuln = tables.Vulnerability(
            name=result.get("name"),
            description=result.get("description"),
            cwe_id=db.query(tables.CWEData.id).filter_by(cwe_id=cwe_id).scalar(),
            cvssv2=result.get("cvssv2"),
            exploitscorev2=result.get("exploitscorev2"),
            impactscorev2=result.get("impactscorev2"),
            cvssv3=result.get("cvssv3"),
            exploitscorev3=result.get("exploitscorev3"),
            impactscorev3=result.get("impactscorev3"),
            cve_id=db.query(tables.CVEData.id).filter_by(cve_id=cve_ids[0]).scalar(),
            identified_on=datetime.utcnow(),
            changed_on=datetime.utcnow()
        )
        db.add(vuln)
        db.flush()

        # Find the matching CVEGroup
        org_id = inventory.org_id
        group = db.query(tables.CVEGroup).filter_by(
            organization_id=org_id,
            group_id=group_id
        ).first()

        if group:
            exists = db.query(tables.VulnerabilityGroupLink).filter_by(
                group_id=group.id,
                vulnerability_id=vuln.id
            ).first()

            if not exists:
                db.add(tables.VulnerabilityGroupLink(
                    group_id=group.id,
                    vulnerability_id=vuln.id
                ))
            else:
                print(f"[SUMMARY] Vulnerability already linked to group {group.group_id}", flush=True)
        else:
            print(f"[SUMMARY] No matching group found for org={org_id}, cwe={cwe_id}", flush=True)

        if agent_id:
            exists = db.query(tables.AgentVulnerabilityStatus).filter_by(
                agent_id=agent_id, vulnerability_id=vuln.id
            ).first()
            if not exists:
                db.add(tables.AgentVulnerabilityStatus(
                    agent_id=agent_id,
                    vulnerability_id=vuln.id,
                    status="open",
                    cvssv2=vuln.cvssv2,
                    exploitscorev2=vuln.exploitscorev2,
                    impactscorev2=vuln.impactscorev2,
                    cvssv3=vuln.cvssv3,
                    exploitscorev3=vuln.exploitscorev3,
                    impactscorev3=vuln.impactscorev3
                ))

    db.commit()

def extract_cwe_id(cve):
    try:
        return cve.cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
    except Exception:
        return None
