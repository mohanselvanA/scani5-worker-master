import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.tables import CPEData, CVEData
from app.config.config import settings

def normalize(text):
    return text.strip().lower().replace(" ", "_")


def test_software_vulnerabilities(session, software):
    vendor = normalize(software["vendor"])
    product = normalize(software["app_name"])
    version = software["app_version"]

    print(f"\n🔍 Searching CPEs for vendor='{vendor}', product='{product}', version='{version}'")

    cpes = session.query(CPEData).filter(
        CPEData.cpe_name.ilike(f"cpe:2.3:a:{vendor}:{product}:{version}:%")
    ).all()

    if not cpes:
        print("❌ No CPEs found.")
        return

    cpe_names = [c.cpe_name for c in cpes]
    print(f"✅ Found {len(cpe_names)} CPE(s):")
    for cpe in cpe_names:
        print(f"   - {cpe}")

    # Gather matching CVEs
    results = []
    for cpe_name in cpe_names:
        matching_cves = session.query(CVEData).filter(
            CVEData.cve_json["configurations"]["nodes"].astext.ilike(f'%{cpe_name}%')
        ).all()
        for cve in matching_cves:
            data = cve.cve_json
            results.append({
                "CVE ID": cve.cve_id,
                "CPE": cpe_name,
                "CVSS v2": data.get("impact", {}).get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore"),
                "CVSS v3": data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore"),
                "CWE": (
                    data.get("cve", {})
                        .get("problemtype", {})
                        .get("problemtype_data", [{}])[0]
                        .get("description", [{}])[0]
                        .get("value")
                ),
                "Summary": data.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value")
            })

    if results:
        print("\n📋 CVE Matches:")
        for entry in results:
            print(f"- CVE ID: {entry['CVE ID']}")
            print(f"  CPE: {entry['CPE']}")
            print(f"  CVSS v2: {entry.get('CVSS v2')}, CVSS v3: {entry.get('CVSS v3')}")
            print(f"  CWE: {entry.get('CWE')}")
            print(f"  Summary: {entry.get('Summary')[:120]}...")
            print()
    else:
        print("⚠️ No CVEs found for the matched CPEs.")


if __name__ == "__main__":
    from app.models.tables import Base  # Make sure this import works
    DATABASE_URL = (
        f"postgresql+psycopg2://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
        f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
    )

    engine = create_engine(DATABASE_URL)
    SessionLocal = sessionmaker(bind=engine)

    software = {
        "app_name": "vlc media player",
        "app_version": "3.0.11",
        "vendor": "videolan"
    }

    session = SessionLocal()
    try:
        test_software_vulnerabilities(session, software)
    finally:
        session.close()