# nvd_service.py

import json
from pathlib import Path

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
CACHE_FILE = DATA_DIR / "nvd_cache.json"


def _load_cache():
    if not CACHE_FILE.exists():
        return {}

    try:
        return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_cache(query: str, results):
    DATA_DIR.mkdir(exist_ok=True)

    cache = _load_cache()
    cache[query] = results
    CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def search_cves(query: str, results_per_page: int = 5, cache: bool = True):
    """
    Query the public NVD REST API for real CVE data.
    This uses the official NVD endpoint and does not require an API key.
    """

    if cache:
        cached = _load_cache().get(query)
        if cached:
            return cached

    params = {
        "keywordSearch": query,
        "resultsPerPage": results_per_page,
        "startIndex": 0,
    }

    response = requests.get(NVD_URL, params=params, timeout=40)
    response.raise_for_status()

    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])

    results = []

    for entry in vulnerabilities:
        cve = entry.get("cve", {})
        id_value = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description = descriptions[0].get("value", "") if descriptions else ""

        metrics = cve.get("metrics", {})
        severity = "Unknown"
        score = None

        cvss = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2")
        if cvss:
            first = cvss[0]
            severity = first.get("cvssData", {}).get("baseSeverity") or first.get("baseSeverity") or "Unknown"
            score = first.get("cvssData", {}).get("baseScore") or first.get("baseScore")

        results.append({
            "id": id_value,
            "description": description,
            "severity": severity,
            "score": score,
            "source": "NVD REST API",
        })

    _save_cache(query, results)

    return results
