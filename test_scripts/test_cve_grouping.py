import re
import json
from collections import defaultdict
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.tables import CVEData, InventoryCVE, CWEData

embedder = SentenceTransformer("all-MiniLM-L6-v2")

def extract_cwe_code(cve: CVEData) -> str:
    try:
        entries = cve.cve_json.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
        for entry in entries:
            for d in entry.get("description", []):
                value = d.get("value", "")
                match = re.match(r"CWE-(\d+)$", value.strip())
                if match:
                    return f"CWE-{match.group(1)}"
    except Exception:
        pass
    return "CWE-UNKNOWN"

def get_cwe_root(cwe_id: str, cwe_map: dict) -> str:
    if not cwe_id.startswith("CWE-"):
        return cwe_id
    cwe_json = cwe_map.get(cwe_id)
    if not cwe_json:
        return cwe_id
    abstraction = cwe_json.get("Abstraction", "")
    if abstraction in ["Variant", "Class"]:
        for rel in cwe_json.get("Relationships", {}).get("Relationship", []):
            if rel.get("Nature") in ["ChildOf", "CanPrecede"]:
                return rel.get("CWE_ID", cwe_id)
    return cwe_id

def load_cwe_mapping(db: Session):
    rows = db.query(CWEData).all()
    return {row.cwe_id: row.cwe_json for row in rows}

def extract_cve_fields(cve: CVEData):
    j = cve.cve_json.get("cve", {})
    description = next((d.get("value", "") for d in j.get("description", {}).get("description_data", []) if d.get("lang") == "en"), "")
    references = [r.get("url", "") for r in j.get("references", {}).get("reference_data", [])]

    cpes = cve.cve_json.get("configurations", {}).get("nodes", [])
    vendor = product = version = ""
    for node in cpes:
        for match in node.get("cpe_match", []):
            if match.get("vulnerable"):
                cpe_parts = match.get("cpe23Uri", "").split(":")
                if len(cpe_parts) >= 5:
                    vendor = cpe_parts[3]
                    product = cpe_parts[4]
                    version = cpe_parts[5] if cpe_parts[5] != "*" else "any"
                    break

    impact = cve.cve_json.get("impact", {})
    v3 = impact.get("baseMetricV3", {}).get("cvssV3", {})

    return {
        "cve_id": cve.cve_id,
        "description": description,
        "cvssv3": v3.get("baseScore", ""),
        "exploitscorev3": impact.get("baseMetricV3", {}).get("exploitabilityScore", ""),
        "impactscorev3": impact.get("baseMetricV3", {}).get("impactScore", ""),
        "vendor": vendor,
        "product": product,
        "version": version,
        "references": references
    }

def cluster_unknown_cves(cves, threshold=0.5):
    if len(cves) <= 2:
        return {"Group-1": cves}
    texts = [extract_cve_fields(c)["description"] for c in cves]
    embeddings = embedder.encode(texts)
    similarity = cosine_similarity(embeddings)
    clusterer = AgglomerativeClustering(n_clusters=None, linkage='average', metric='precomputed', distance_threshold=1 - threshold)
    labels = clusterer.fit_predict(1 - similarity)
    grouped = defaultdict(list)
    for idx, label in enumerate(labels):
        grouped[label].append(cves[idx])
    return {f"Group-{i+1}": v for i, v in enumerate(grouped.values())}

def group_cves(db: Session, inventory_id: int = 46):
    cwe_map = load_cwe_mapping(db)
    cve_links = db.query(InventoryCVE).filter_by(software_inventory_id=inventory_id).all()
    cves = [link.cve for link in cve_links if link.cve]
    print(f"[INFO] Total CVEs: {len(cves)}")

    cwe_groups = defaultdict(list)
    for cve in cves:
        cwe = extract_cwe_code(cve)
        root = get_cwe_root(cwe, cwe_map) if cwe != "CWE-UNKNOWN" else "CWE-UNKNOWN"
        cwe_groups[root].append(cve)

    result = []
    group_counter = 1

    for cwe_id, group in cwe_groups.items():
        if cwe_id == "CWE-UNKNOWN":
            continue
        subgroups = defaultdict(list)
        for cve in group:
            f = extract_cve_fields(cve)
            key = f"{f['vendor']}|{f['product']}|{f['version']}".lower()
            subgroups[key].append(cve)

        for subkey, subgroup in subgroups.items():
            result.append({
                "group_id": f"Group-{group_counter}",
                "cwes": [cwe_id],
                "cves": [extract_cve_fields(c) for c in subgroup]
            })
            group_counter += 1

    unknowns = cwe_groups.get("CWE-UNKNOWN", [])
    if unknowns:
        sem_clusters = cluster_unknown_cves(unknowns)
        for label, cve_list in sem_clusters.items():
            result.append({
                "group_id": f"Group-{group_counter}",
                "cwes": [],
                "cves": [extract_cve_fields(c) for c in cve_list]
            })
            group_counter += 1

    return result

def main():
    db = SessionLocal()
    groups = group_cves(db)
    print(json.dumps(groups, indent=2))
    db.close()

if __name__ == "__main__":
    main()