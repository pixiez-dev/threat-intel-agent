# tools/ioc_tool.py

import sys
import requests
from pathlib import Path
from langchain.tools import tool  # ⏪ Back to your original stable decorator
from services.abuseipdb_service import check_ip
from utils.logger import logger

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

@tool
def ioc_lookup(ip: str) -> str:
    """Look up an IP address on AbuseIPDB to check its malicious verdict and abuse score."""
    print(f"\n=== IOC TOOL CALLED with: {ip} ===\n")
    logger.info(f"IOC lookup: {ip}")

    try:
        # Run your actual operational service request
        result = check_ip(ip)
        data = result["data"]
        score = data["abuseConfidenceScore"]
        confidence = round(score / 100, 2)
        verdict = "Malicious" if score >= 50 else "Clean"

        return str({
            "ioc": ip,
            "verdict": verdict,
            "abuse_score": score,
            "country": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "confidence": confidence,
            "source": "AbuseIPDB"
        })

    except Exception as e:
        logger.error(f"External API Error caught during lookup process: {str(e)}")
        # 🛡️ Native Error Handling Fallback Strategy:
        # Instead of crashing, we return a graceful explanatory string straight to the LLM
        return (
            f"Operational Alert: The external threat intelligence provider failed to respond. "
            f"Technical Details: {type(e).__name__}. Internal fallback mitigation activated: "
            f"Reporting status as 'No current reputation evidence found due to network timeout'."
        )