import re
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.models import models_nvd
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

embedder = SentenceTransformer("all-MiniLM-L6-v2")

# Cache index at module level
CPE_REFS = []
CPE_EMBEDDINGS = None

def normalize(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"[\s\-]+", "_", text.lower().strip())

def clean_tokens(text: str) -> list[str]:
    if not text:
        return []
    text = text.lower()
    text = re.sub(r"\(.*?\)", "", text)
    text = re.sub(r"\d+\.\d+(\.\d+)?", "", text)
    text = re.sub(r"[^a-z0-9]+", " ", text)
    tokens = [t.strip() for t in text.split() if len(t.strip()) > 2]
    return list(set(tokens))

def build_cpe_index(db):
    global CPE_REFS, CPE_EMBEDDINGS
    if CPE_EMBEDDINGS is not None:
        return  # already built

    cpe_rows = db.query(models_nvd.CPEData).all()
    cpe_texts = []
    refs = []

    for cpe in cpe_rows:
        vendor = cpe.cpe_json.get("vendor", "")
        product = cpe.cpe_json.get("product", "")
        text = f"{vendor}:{product}"
        cpe_texts.append(text)
        refs.append(cpe)

    CPE_REFS = refs
    CPE_EMBEDDINGS = embedder.encode(cpe_texts, convert_to_numpy=True, normalize_embeddings=True)

def find_semantic_cpe_match(vendor: str, product: str, db: Session, threshold=0.8):
    build_cpe_index(db)
    query_text = f"{vendor}:{product}"
    query_embedding = embedder.encode([query_text], convert_to_numpy=True, normalize_embeddings=True)
    similarities = cosine_similarity(query_embedding, CPE_EMBEDDINGS)[0]
    best_idx = np.argmax(similarities)
    best_score = similarities[best_idx]

    if best_score >= threshold:
        matched_cpe = CPE_REFS[best_idx]
        print(f"[EMBEDDING MATCH] '{query_text}' → '{matched_cpe.cpe_name}' (score={best_score:.2f})", flush=True)
        return matched_cpe.cpe_name
    else:
        print(f"[NO EMBEDDING MATCH] Max score: {best_score:.2f}", flush=True)
        return None

def find_best_cpe_match(db: Session, app_name: str, app_version: str, vendor: str = None):
    vendor = vendor or ""
    app_name_normalized = normalize(app_name)
    vendor_normalized = normalize(vendor)
    tokens = clean_tokens(app_name) + clean_tokens(vendor)

    print(f"[CPE LOOKUP] Normalized: vendor={vendor_normalized}, app_name={app_name_normalized}, version={app_version}", flush=True)

    # ---------- 1. Exact Match ----------
    query = db.query(models_nvd.CPEData).filter(
        models_nvd.CPEData.cpe_json["version"].astext == app_version,
        models_nvd.CPEData.cpe_json["vendor"].astext.ilike(f"%{vendor_normalized}%"),
        models_nvd.CPEData.cpe_json["product"].astext.ilike(f"%{app_name_normalized}%")
    )
    exact_matches = query.all()
    if exact_matches:
        print(f"[EXACT MATCH] Found {len(exact_matches)} candidate(s)", flush=True)
        for m in exact_matches[:3]:
            print(f"  → {m.cpe_name}", flush=True)
        return exact_matches[0].cpe_name

    # ---------- 2. Fallback Match with Version ----------
    print(f"[FALLBACK] No exact match. Trying token-based partial match with version...", flush=True)
    loose_query = db.query(models_nvd.CPEData).filter(
        models_nvd.CPEData.cpe_json["version"].astext == app_version
    )

    if vendor_normalized:
        loose_query = loose_query.filter(
            models_nvd.CPEData.cpe_json["vendor"].astext.ilike(f"%{vendor_normalized}%")
        )

    loose_query = loose_query.filter(
        or_(*[models_nvd.CPEData.cpe_json["product"].astext.ilike(f"%{token}%") for token in tokens])
    )

    fallback_matches = loose_query.all()
    if fallback_matches:
        print(f"[FALLBACK MATCH] Found {len(fallback_matches)} candidate(s)", flush=True)

        def match_score(cpe):
            product = (cpe.cpe_json.get("product") or "").lower()
            vendor = (cpe.cpe_json.get("vendor") or "").lower()
            return sum([
                sum(1 for token in tokens if token in product),
                sum(1 for token in tokens if token in vendor),
            ])

        best_match = sorted(
            fallback_matches,
            key=lambda c: (-match_score(c), c.cpe_name.count("*"), -len(c.cpe_name))
        )[0]
        print(f"[FALLBACK SELECTED] {best_match.cpe_name}", flush=True)
        return best_match.cpe_name

    # ---------- 3. Vendor + Product Only (Ignore version) ----------
    print(f"[NO VERSION MATCH] Trying product + vendor match without version...", flush=True)
    versionless_query = db.query(models_nvd.CPEData)

    if vendor_normalized:
        versionless_query = versionless_query.filter(
            models_nvd.CPEData.cpe_json["vendor"].astext.ilike(f"%{vendor_normalized}%")
        )

    versionless_query = versionless_query.filter(
        or_(*[models_nvd.CPEData.cpe_json["product"].astext.ilike(f"%{token}%") for token in tokens])
    )

    no_version_matches = versionless_query.all()
    if no_version_matches:
        print(f"[NO-VERSION MATCH] Found {len(no_version_matches)} candidate(s)", flush=True)
        best_match = sorted(
            no_version_matches,
            key=lambda c: (c.cpe_name.count("*"), -len(c.cpe_name))
        )[0]
        print(f"[NO-VERSION SELECTED] {best_match.cpe_name}", flush=True)
        return best_match.cpe_name

    # ---------- 4. Embedding-Based Semantic Match ----------
    print(f"[EMBEDDING] No heuristic match found. Trying semantic match...", flush=True)
    semantic_cpe = find_semantic_cpe_match(vendor_normalized, app_name_normalized, db)
    if semantic_cpe:
        return semantic_cpe

    print(f"[NO MATCH] No CPE found for {app_name} ({vendor}) version {app_version}", flush=True)
    return None