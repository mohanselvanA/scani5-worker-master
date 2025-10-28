import json
from collections import defaultdict
from sqlalchemy.orm import Session
from sentence_transformers import SentenceTransformer
from sklearn.cluster import KMeans
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain
from langchain.llms import Ollama

from app.core.database import SessionLocal
from app.models.tables import CVEData, InventoryCVE

# Load embedding model
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# Connect to Ollama LLM
llm = Ollama(model="llama3", base_url="http://192.168.4.8:11434")

# Prompt template
prompt_template = PromptTemplate.from_template("""
You are a cybersecurity analyst.
Group the following CVEs based on similar traits or behavior.
For each group, generate a JSON object:

[
  {{
    "name": "string",
    "description": "string",
    "cvssv2": "string",
    "exploitscorev2": "string",
    "impactscorev2": "string",
    "cvssv3": "string",
    "exploitscorev3": "string",
    "impactscorev3": "string",
    "visibility_score": "string",
    "cve_ids": ["string"],
    "patches": [...],
    "mitigations": [...]
  }}
]

CVEs:
```json
{cve_jsons}
```
""")

# LLM chain
chain = LLMChain(llm=llm, prompt=prompt_template)

# Fetch all CVEs for a given software inventory ID
def fetch_cves(db: Session, inventory_id: int):
    links = db.query(InventoryCVE).filter_by(software_inventory_id=inventory_id).all()
    return [link.cve for link in links if link.cve]

# Extract CWE from CVE
def extract_cwe(cve: CVEData) -> str:
    try:
        data = cve.cve_json["cve"]["problemtype"]["problemtype_data"]
        for p in data:
            for d in p.get("description", []):
                if d["value"].startswith("CWE-"):
                    return d["value"]
    except Exception:
        pass
    return "UNKNOWN"

# Group CVEs by CWE
def group_by_cwe(cves):
    groups = defaultdict(list)
    for cve in cves:
        cwe = extract_cwe(cve)
        groups[cwe].append(cve)
    return groups

# Filter only high severity CVEs
def rule_filter(cves):
    return [c for c in cves if c.cve_json.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", 0) >= 7]

# Cluster CVEs using embeddings
def cluster_by_embedding(cves, n_clusters=3):
    if len(cves) <= n_clusters:
        return {i: [cves[i]] for i in range(len(cves))}

    texts = [json.dumps(c.cve_json) for c in cves]
    embeddings = embedder.encode(texts)
    kmeans = KMeans(n_clusters=min(n_clusters, len(cves)), random_state=42)
    labels = kmeans.fit_predict(embeddings)

    clusters = defaultdict(list)
    for idx, label in enumerate(labels):
        clusters[label].append(cves[idx])
    return clusters

# Send clustered CVEs to LLM for grouping
def run_grouping_llm(cve_group):
    payload = [c.cve_json for c in cve_group]
    response = chain.invoke({"cve_jsons": json.dumps(payload, indent=2)})
    try:
        return json.loads(response['text'])
    except Exception as e:
        print("[LLM ERROR]", e)
        return {"error": str(e), "raw": response['text']}

# Main flow
def main():
    db = SessionLocal()
    cves = fetch_cves(db, inventory_id=11)
    print(f"[INFO] Total CVEs fetched: {len(cves)}")

    cwe_groups = group_by_cwe(cves)
    print(f"[INFO] Grouped into {len(cwe_groups)} CWEs")

    for cwe, group in cwe_groups.items():
        print(f"\n=== CWE: {cwe} ({len(group)} CVEs) ===")

        high_risk = rule_filter(group)
        print(f"→ After rule filter (CVSS >= 7): {len(high_risk)}")

        if not high_risk:
            continue

        clustered = cluster_by_embedding(high_risk)
        print(f"→ Clusters formed: {len(clustered)}")

        for cid, cluster in clustered.items():
            print(f"\n--- Cluster {cid} ({len(cluster)} CVEs) ---")
            result = run_grouping_llm(cluster)
            print(json.dumps(result, indent=2))

    db.close()

if __name__ == "__main__":
    main()