# pivot_tool.py

import json
from pathlib import Path
import sys
from langchain.tools import tool
from utils.logger import logger

PROJECT_ROOT = Path(__file__).resolve().parents[1] 
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
    
@tool
def pivot_lookup(ioc: str) -> str:
    """
    Find related domains and ASN
    from a known IP address.
    """

    print(f"\n=== PIVOT TOOL CALLED with: {ioc} ===\n")

    logger.info(
        f"Pivot lookup: {ioc}"
    )

    path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "pivot_data.json"
    )

    with open(path, "r") as f:
        pivots = json.load(f)

    result = pivots.get(ioc)

    if not result:
        return (
            f"No pivot data available for "
            f"{ioc}"
        )

    return str({
        "ioc": ioc,
        **result,
        "confidence": result.get("confidence", 0.85),
        "source": "Internal Pivot Dataset",
        "source_file": "data/pivot_data.json"
    })