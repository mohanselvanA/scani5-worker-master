import os, gzip, json, xml.etree.ElementTree as ET
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError
from app.models.tables import Base, CVEData, CPEData, CWEData
from app.config.config import settings

# --- Constants ---
CVE_LOCAL_FOLDER = "/app/nvd_feeds/cve"
CPE_LOCAL_FOLDER = "/app/nvd_feeds/cpe/nvdcpe-2.0-chunks"
CWE_XML_PATH = "/app/nvd_feeds/cwe/cwec_v4.17.xml"

# --- DB Setup ---
DATABASE_URL = (
    f"postgresql+psycopg2://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
    f"@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
)
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

# --- Sync Functions ---
def sync_cve_from_files(session):
    print("\n--- Syncing CVE from local files ---")
    inserted = 0
    for fname in sorted(os.listdir(CVE_LOCAL_FOLDER)):
        if not fname.endswith(".json.gz"):
            continue
        path = os.path.join(CVE_LOCAL_FOLDER, fname)
        print(f"📄 Reading: {path}")
        with gzip.open(path, 'rt', encoding='utf-8') as f:
            try:
                data = json.load(f)
                # Support both 1.1 and 2.0 schema
                items = data.get("vulnerabilities") or data.get("CVE_Items") or data.get("cveItems") or []
                for item in items:
                    # 2.0
                    cve_id = item.get("cve", {}).get("id")
                    # 1.1 fallback
                    if not cve_id:
                        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
                    if cve_id and not session.query(CVEData).filter_by(cve_id=cve_id).first():
                        session.add(CVEData(cve_id=cve_id, cve_json=item))
                        inserted += 1
                session.commit()
            except Exception as e:
                print(f"❌ Error in {fname}: {e}")
                session.rollback()
    print(f"✅ Inserted {inserted} CVEs.")

def sync_cpe_from_files(session):
    import json
    import os
    from datetime import datetime

    print("\n--- Syncing CPE from local files ---")
    inserted = 0

    for fname in sorted(os.listdir(CPE_LOCAL_FOLDER)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(CPE_LOCAL_FOLDER, fname)
        print(f"📄 Reading: {path}")
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                products = data.get("products", [])

                for product in products:
                    cpe_data = product.get("cpe", {})
                    cpe_uri = cpe_data.get("cpeName")
                    if not cpe_uri:
                        continue

                    # Avoid duplicates
                    if session.query(CPEData).filter_by(cpe_name=cpe_uri).first():
                        continue

                    # Extract parts from CPE string
                    parts = cpe_uri.split(":")
                    if len(parts) < 6:
                        continue

                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5]

                    entry = CPEData(
                        cpe_name=cpe_uri,
                        cpe_json={
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                            "deprecated": cpe_data.get("deprecated", False),
                            "titles": cpe_data.get("titles", []),
                            "refs": cpe_data.get("refs", []),
                        },
                        
                    )
                    session.add(entry)
                    inserted += 1

            session.commit()
        except Exception as e:
            print(f"❌ Error in {fname}: {e}")
            session.rollback()

    print(f"✅ Inserted {inserted} CPE entries.")

def element_to_dict(elem):
    """Recursively converts XML Element and its children to a dictionary."""
    result = dict(elem.attrib)
    for child in elem:
        tag = child.tag.split('}', 1)[-1]  # Remove namespace
        value = element_to_dict(child) if list(child) else child.text
        if tag in result:
            if not isinstance(result[tag], list):
                result[tag] = [result[tag]]
            result[tag].append(value)
        else:
            result[tag] = value
    return result

def sync_cwe_from_xml(session):
    print("\n--- Syncing CWE from local XML ---")
    count = 0
    try:
        tree = ET.parse(CWE_XML_PATH)
        root = tree.getroot()
        ns = {"cwe": "http://cwe.mitre.org/cwe-7"}
        for weakness in root.findall(".//cwe:Weakness", ns):
            cwe_id = weakness.get("ID")
            if cwe_id and not session.query(CWEData).filter_by(cwe_id=cwe_id).first():
                cwe_dict = element_to_dict(weakness)
                session.add(CWEData(cwe_id=cwe_id, cwe_json=cwe_dict))
                count += 1
        session.commit()
        print(f"✅ Inserted {count} CWE entries.")
    except Exception as e:
        print(f"❌ Error parsing CWE XML: {e}")
        session.rollback()

# --- Main Entry ---
if __name__ == "__main__":
    session = SessionLocal()
    try:
        sync_cve_from_files(session)
        sync_cpe_from_files(session)
        sync_cwe_from_xml(session)
    finally:
        session.close()
        print("\n🔐 Vulnerability database initialization complete.")