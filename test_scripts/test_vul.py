# test_vul.py
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models import tables
from app.services.llm_vulgen_client import get_llm_summary_by_cwe
from datetime import datetime
import json


def extract_cwe_id(cve):
    try:
        return cve.cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
    except Exception:
        return None


def group_cves_by_cwe(cves):
    cwe_map = {}
    for cve in cves:
        cwe = extract_cwe_id(cve)
        if not cwe:
            continue
        if cwe not in cwe_map:
            cwe_map[cwe] = []
        cwe_map[cwe].append(cve)
    return cwe_map


def main():
    db: Session = SessionLocal()
    try:
        inventory_id = 11
        cve_links = db.query(tables.InventoryCVE).filter_by(software_inventory_id=inventory_id).all()
        cves = [db.query(tables.CVEData).filter_by(id=link.cve_id).first() for link in cve_links]

        grouped = group_cves_by_cwe(cves)

        cwe = "CWE-295"
        if cwe not in grouped:
            print(f"No CVEs found for {cwe}")
            return

        print(f"Found {len(grouped[cwe])} CVEs for {cwe}")

        cve_jsons = [cve.cve_json for cve in grouped[cwe]]

        print("\n=== PROMPT ===")
        print(json.dumps(cve_jsons, indent=2))

        result = get_llm_summary_by_cwe(cwe, cve_jsons)

        print("\n=== RAW RESULT ===")
        print(json.dumps(result, indent=2))

        print("\n=== PARSED SUMMARY ===")
        print(f"Name: {result.get('name')}")
        print(f"Description: {result.get('description')}")
        print(f"CVSSv2: {result.get('cvssv2')}, Exploitability: {result.get('exploitscorev2')}, Impact: {result.get('impactscorev2')}")
        print(f"CVSSv3: {result.get('cvssv3')}, Exploitability: {result.get('exploitscorev3')}, Impact: {result.get('impactscorev3')}")
        print(f"Visibility Score: {result.get('visibility_score')}")

        print("\n=== Patches ===")
        for patch in result.get("patches", []):
            print(f"- {patch['name']}: {patch['description']} (Type: {patch['type']}, Rollback: {patch['rollback_available']})")
            print(f"  References: {patch['references']}\n")

        print("\n=== Mitigations ===")
        for mit in result.get("mitigations", []):
            print(f"- {mit['name']}: {mit['description']} (Type: {mit['type']}, Effectiveness: {mit['effectiveness']})")
            print(f"  References: {mit['references']}\n")

    finally:
        db.close()


if __name__ == "__main__":
    main()