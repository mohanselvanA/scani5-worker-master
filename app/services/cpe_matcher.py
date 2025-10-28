
import re
from sqlalchemy import or_
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import models_nvd, models_worker
from sqlalchemy import select

def normalize(text: str) -> str:
    if not text:
        return ""
    return re.sub(r"[\s\-]+", "_", text.lower().strip())

def clean_tokens(text: str) -> list[str]:
    """
    Extract meaningful tokens from app name or vendor.
    Removes version numbers, symbols, and short/noisy words.
    """
    if not text:
        return []
    text = text.lower()
    text = re.sub(r"\(.*?\)", "", text)                     # remove "(arm64)"
    text = re.sub(r"\d+\.\d+(\.\d+)?", "", text)            # remove version numbers
    text = re.sub(r"[^a-z0-9]+", " ", text)                 # normalize separators
    tokens = [t.strip() for t in text.split() if len(t.strip()) > 2]
    return list(set(tokens))

async def find_best_cpe_match(db: AsyncSession, app_name: str, app_version: str, vendor: str = None):
    app_name_normalized = normalize(app_name)
    vendor_normalized = normalize(vendor)
    tokens = clean_tokens(app_name) + clean_tokens(vendor)

    print(f"[CPE LOOKUP] Normalized: vendor={vendor_normalized}, app_name={app_name_normalized}, version={app_version}", flush=True)

    # ---------- 1. Exact Match (strict) ----------
    stmt = (
        select(models_nvd.CPEData)
        .filter(
            models_nvd.CPEData.cpe_json["version"].astext == app_version,
            models_nvd.CPEData.cpe_json["vendor"].astext.ilike(f"%{vendor_normalized}%"),
            models_nvd.CPEData.cpe_json["product"].astext.ilike(f"%{app_name_normalized}%")
        )
    )

    result = await db.execute(stmt)
    exact_matches = result.scalars().all()

    if exact_matches:
        print(f"[EXACT MATCH] Found {len(exact_matches)} candidate(s)", flush=True)
        for m in exact_matches[:3]:
            print(f"  → {m.cpe_name}", flush=True)
        return exact_matches[0].cpe_name

    # ---------- 2. Fallback Token Match ----------
    print(f"[FALLBACK] No exact match. Trying token-based partial match...", flush=True)

    if not tokens:
        print("[FALLBACK] No usable tokens", flush=True)
        return None

    loose_stmt = (
        select(models_nvd.CPEData)
        .filter(models_nvd.CPEData.cpe_json["version"].astext == app_version)
    )

    # Filter by vendor if possible
    if vendor_normalized:
        loose_stmt = loose_stmt.filter(
            models_nvd.CPEData.cpe_json["vendor"].astext.ilike(f"%{vendor_normalized}%")
        )

    # Match product field with any token
    loose_stmt = loose_stmt.filter(
        or_(*[
            models_nvd.CPEData.cpe_json["product"].astext.ilike(f"%{token}%")
            for token in tokens
        ])
    )

    loose_result = await db.execute(loose_stmt)
    fallback_matches = loose_result.scalars().all()

    if not fallback_matches:
        print("[FALLBACK] No matches found in fallback tier", flush=True)
        return None

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
