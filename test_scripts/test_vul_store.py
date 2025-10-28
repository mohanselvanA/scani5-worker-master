import re
import json
from collections import defaultdict
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.cluster import AgglomerativeClustering

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.tables import CVEData, InventoryCVE, CWEData

from langchain_core.runnables import RunnableLambda, RunnableMap
from langgraph.graph import StateGraph
from langchain.llms import Ollama
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate


embedder = SentenceTransformer("all-MiniLM-L6-v2")

llm = Ollama(model="llama3", base_url="http://192.168.4.8:11434", temperature=0.3)

prompt_template = PromptTemplate.from_template("""
You are a cybersecurity analyst.

Analyze the following CVEs gathered from NVD for the software {software_name}, with version {software_version} from vendor {software_vendor} and return a structured vulnerability summary as valid JSON with the following schema:

{{
  "name": "string",
  "description": "string",
  "cvssv3": "string",
  "exploitscorev3": "string",
  "impactscorev3": "string",
  "visibility_score": "string",
  "patches": [
    {{
      "name": "string",
      "description": "string",
      "references": ["string"],
      "release_date": "ISO 8601",
      "type": "string",
      "priority": "string",
      "rollback_available": "Yes/No"
    }}
  ],
  "mitigations": [
    {{
      "name": "string",
      "description": "string",
      "references": ["string"],
      "type": "string",
      "effectiveness": "string"
    }}
  ]
}}

Respond with **only the JSON**. No commentary.

Here is the list of CVEs which you need to summarize:

{cve_jsons}
""")

def get_vul_summary(cwe_id: str,software_name: str,software_version: str,software_vendor: str, cve_jsons: list[dict]) -> dict:
    chain = LLMChain(llm=llm, prompt=prompt_template)

    formatted_json = json.dumps(cve_jsons, indent=2)

    result = chain.invoke({
        "cwe_id": cwe_id,
        "software_name":software_name,
        "software_version":software_version,
        "software_vendor":software_name,
        "cve_jsons": formatted_json
    })

    return parse_result(result["text"])

def parse_result(text: str) -> dict:
    try:
        return json.loads(text)
    except Exception:
        print("[LLM WARNING] Failed to parse JSON. Returning raw.")
        return {"name": "Unknown", "description": text}

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

def send_to_llm(groups):

    for group in groups:
        cwe_id = group["cwes"][0] if group["cwes"] else "UNKNOWN"
        software_name = group["software_name"]
        software_version = group["software_version"]
        software_vendor = group["software_vendor"]
        cve_jsons = group["cves"]
        print(f"\n[LLM] Generating summary for group {group['group_id']} / CWE={cwe_id}")
        result = get_vul_summary(cwe_id, software_name, software_version, software_vendor, cve_jsons)
        print(json.dumps(result, indent=2))


    
    

def group_cves(db: Session, inventory_id: int = 31):
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
                "software_name": f["product"],
                "software_version": f["version"],
                "software_vendor": f["vendor"],
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
                "software_name": f["product"],
                "software_version": f["version"],
                "software_vendor": f["vendor"],
                "cves": [extract_cve_fields(c) for c in cve_list]
            })
            group_counter += 1

    send_to_llm(result)
    return result

def main():
    db = SessionLocal()
    groups = group_cves(db)
    print(json.dumps(groups, indent=2))
    db.close()

if __name__ == "__main__":
    main()