import re
from collections import defaultdict
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering
from sklearn.feature_extraction.text import TfidfVectorizer
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import models_worker, models_nvd
from app.models.models_nvd import CVEData, CWEData
from app.models.models_worker import InventoryCVE
from app.utils.logging import logger

embedder = SentenceTransformer("all-MiniLM-L6-v2")

async def fetch_cwe_metadata(db_nvd: AsyncSession, cwe_id: str) -> dict | None:
     
    result = await db_nvd.execute(
        select(CWEData).where(CWEData.cwe_id == cwe_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        return None
    return row.cwe_json


def parse_cwe_title(cwe_json: dict) -> str:
    return cwe_json.get("Name") or "UNKNOWN CWE TITLE"

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

async def load_cwe_mapping(db: AsyncSession):
    result = await db.execute(select(CWEData))
    rows = result.scalars().all()
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

def extract_top_keywords(descriptions: list[str], top_n=5):
    vectorizer = TfidfVectorizer(stop_words="english", max_features=1000)
    X = vectorizer.fit_transform(descriptions)
    scores = X.sum(axis=0).A1
    vocab = vectorizer.get_feature_names_out()
    keyword_scores = list(zip(vocab, scores))
    keyword_scores.sort(key=lambda x: x[1], reverse=True)
    return [kw for kw, _ in keyword_scores[:top_n]]

async def group_cves(db: AsyncSession, db_nvd: AsyncSession, inventory_id: int, organization_id: int):
    cwe_map = await load_cwe_mapping(db_nvd)
    result = await db.execute(select(InventoryCVE).filter_by(software_inventory_id=inventory_id))
    cve_links = result.scalars().all()
    cve_ids = [link.cve_id for link in cve_links if link.cve_id]

    result = await db_nvd.execute(select(CVEData).where(CVEData.cve_id.in_(cve_ids)))
    cves = result.scalars().all()
    logger.info(f"[INFO] Total CVEs: {len(cves)}")

    cwe_groups = defaultdict(list)
    for cve in cves:
        cwe = extract_cwe_code(cve)
        root = get_cwe_root(cwe, cwe_map) if cwe != "CWE-UNKNOWN" else "CWE-UNKNOWN"
        cwe_groups[root].append(cve)

    result_data = []
    group_counter = 1

    cwe_metadata_cache: dict[str, dict] = {}

    for cwe_id, group in cwe_groups.items():
        if cwe_id == "CWE-UNKNOWN":
            continue

        if cwe_id not in cwe_metadata_cache:
            cwe_json = await fetch_cwe_metadata(db_nvd, cwe_id)
            if cwe_json:
                cwe_metadata_cache[cwe_id] = cwe_json
            else:
                cwe_metadata_cache[cwe_id] = {}

        cwe_json = cwe_metadata_cache[cwe_id]
        cwe_title = parse_cwe_title(cwe_json)

        subgroups = defaultdict(list)
        for cve in group:
            f = extract_cve_fields(cve)
            key = f"{f['vendor']}|{f['product']}|{f['version']}".lower()
            subgroups[key].append(cve)

        for subkey, subgroup in subgroups.items():
            f = extract_cve_fields(subgroup[0])
            safe_group_id = f"inv-{inventory_id}-grp-{group_counter}"
            result_data.append({
                "group_id": safe_group_id,
                "cwes": [cwe_id],
                "software_name": f["product"],
                "software_version": f["version"],
                "software_vendor": f["vendor"],
                "cves": [extract_cve_fields(c) for c in subgroup]
            })
            group = models_worker.CVEGroup(
            organization_id=organization_id,
            group_id=safe_group_id,
            reason = f"Grouped by CWE {cwe_id} affecting {f['vendor']} {f['product']} {f['version']}",
            cwe_id=cwe_id if cwe_id != "CWE-UNKNOWN" else None,
            cwe_title=cwe_title, 
            )
            db.add(group)
            await db.commit()
            result = await db.execute(select(models_worker.CVEGroup).filter_by(group_id=safe_group_id))
            group_obj = result.scalars().first()

            await db.execute(
                InventoryCVE.__table__.update()
                .where(InventoryCVE.software_inventory_id == inventory_id)
                .where(InventoryCVE.cve_id.in_([c.cve_id for c in subgroup]))
                .values(cve_group_id=group_obj.id)
            )
            await db.commit()
            group_counter += 1

    # unknowns = cwe_groups.get("CWE-UNKNOWN", [])
    # if unknowns:
    #     sem_clusters = cluster_unknown_cves(unknowns)
    #     for label, cve_list in sem_clusters.items():
    #         f = extract_cve_fields(cve_list[0])
    #         safe_group_id = f"inv-{inventory_id}-grp-{group_counter}"
    #         print(f"\n[DEBUG] Semantic Group ID: {safe_group_id}")
    #         print(f"[DEBUG] Grouped {len(cve_list)} CVEs:")
    #         for cve in cve_list:
    #             fields = extract_cve_fields(cve)
    #             print(json.dumps({
    #                 "cve_id": fields["cve_id"],
    #                 "cvssv3": fields["cvssv3"],
    #                 "exploitability": fields["exploitscorev3"],
    #                 "impact": fields["impactscorev3"],
    #                 "desc": fields["description"][:100] + "..." if fields["description"] else ""
    #             }, indent=2))

    #         result.append({
    #             "group_id": safe_group_id,
    #             "cwes": [],
    #             "software_name": f["product"],
    #             "software_version": f["version"],
    #             "software_vendor": f["vendor"],
    #             "cves": [extract_cve_fields(c) for c in cve_list]
    #         })
    #         descriptions = [extract_cve_fields(c)["description"] for c in cve_list]
    #         keywords = extract_top_keywords(descriptions)
    #         reason = f"Semantic cluster ({', '.join(keywords)}) among {len(cve_list)} CVEs"
    #         group = models_worker.CVEGroup(
    #         organization_id=organization_id,
    #         group_id=safe_group_id,
    #         reason = reason,
    #         cwe_id=None,
    #         )
    #         db.add(group)
    #         db.commit()
    #         group_obj = db.query(models_worker.CVEGroup).filter_by(group_id=safe_group_id).first()

    #         for cve_entry in cve_list:
    #             db.query(models_worker.InventoryCVE).filter_by(
    #                 software_inventory_id=inventory_id,
    #                 cve_id=cve_entry.cve_id
    #             ).update({"cve_group_id": group_obj.id})
    #         db.commit()
    #         group_counter += 1

    return result_data

