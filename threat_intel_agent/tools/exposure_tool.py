# tools/exposure_tool.py

import sys
import json
import requests
from pathlib import Path
from langchain.tools import tool  # ⏪ Back to your original stable decorator
from services.nvd_service import search_cves
from utils.logger import logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

@tool
def exposure_check(software_version: str) -> str:
    """Queries vulnerability datasets and live API feeds to check for exposed CVEs."""
    print(f"\n=== EXPOSURE TOOL CALLED with: {software_version} ===\n")
    logger.info(f"Exposure check: {software_version}")

    # Tier 1: Local Check (Always stable, no networking risks)
    path = Path(__file__).resolve().parent.parent / "data" / "software_vulns.json"
    try:
        with open(path, "r") as f:
            vulns = json.load(f)
        result = vulns.get(software_version)
        if result:
            return str({
                "software": software_version,
                **result,
                "source": "Internal Vulnerability Dataset",
                "source_file": "data/software_vulns.json",
                "evidence_note": "This comes from the local sample dataset in data/software_vulns.json."
            })
    except Exception as local_err:
        logger.warning(f"Failed to read local cache definition files: {local_err}")

    # Tier 2: Remote Check (Prone to network drops or timeouts)
    try:
        nvd_results = search_cves(software_version, results_per_page=3)
        if nvd_results:
            return str({
                "software": software_version,
                "status": "Live NVD lookup",
                "cves": nvd_results,
                "confidence": 0.75,
                "source": "NVD REST API",
                "source_file": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "evidence_note": "This is real NVD data fetched from the public NVD API."
            })
    except Exception as exc:
        logger.warning("NVD lookup failed for %s: %s", software_version, exc)
        # 🛡️ Native Error Handling Fallback Strategy:
        return (
            f"Operational Alert: The external database gateway failed to resolve the request. "
            f"Technical Details: {type(exc).__name__}. Internal fallback mitigation activated: "
            f"Reporting status as 'No current confirmation evidence found due to network timeout'."
        )

    return f"No vulnerability data found for {software_version}"