#actor_tool.py

import json
import sys
from langchain.tools import tool
from utils.logger import logger
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1] 
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

def lookup_actor(actor_name: str):
    """
    Load the actor profile and TTP details from the local dataset.
    """

    path = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "actors.json"
    )

    with open(path, "r", encoding="utf-8") as f:
        actors = json.load(f)

    actor = actors.get(actor_name)

    if not actor:
        return {
            "actor": actor_name,
            "error": "Actor not found",
            "source_file": "data/actors.json"
        }

    ttps = []
    for ttp in actor.get("ttps", []):
        if isinstance(ttp, dict):
            ttps.append({
                "id": ttp.get("id", "UNKNOWN"),
                "name": ttp.get("name", "Unknown")
            })
        else:
            ttps.append({
                "id": str(ttp),
                "name": str(ttp)
            })

    confidence = actor.get("confidence")
    if confidence is None:
        confidence = round(
            min(
                0.98,
                0.55
                + 0.08 * len(ttps)
                + (0.05 if actor.get("aliases") else 0.0)
                + (0.05 if actor.get("description") else 0.0)
            ),
            2,
        )
    else:
        confidence = round(float(confidence), 2)

    return {
        "actor": actor_name,
        "aliases": actor.get("aliases", []),
        "description": actor.get("description", ""),
        "ttps": ttps,
        "confidence": confidence,
        "source": "Internal Threat Dataset",
        "source_file": "data/actors.json",
        "evidence_note": "Score derived from data/actors.json"
    }


@tool
def actor_lookup(actor_name: str) -> str:
    """
    Lookup threat actor profile and known TTPs.
    """

    print(f"\n=== ACTOR TOOL CALLED with: {actor_name} ===\n")

    logger.info(
        f"Actor lookup: {actor_name}"
    )

    return str(lookup_actor(actor_name))