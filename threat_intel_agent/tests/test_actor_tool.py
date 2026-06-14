# test_actor_tool.py

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.actor_tool import lookup_actor

def test_actor_tool_uses_dataset_confidence_and_ttp_details():
    print("\n--- Running Actor Tool Test ---")
    result = lookup_actor("APT29")

    assert isinstance(result, dict)
    assert result["actor"] == "APT29"
    assert result["confidence"] >= 0.0
    assert result["confidence"] <= 1.0
    assert result["source_file"] == "data/actors.json"

    with open(PROJECT_ROOT / "data" / "actors.json", "r", encoding="utf-8") as fh:
        actors = json.load(fh)

    actor = actors["APT29"]

    assert result["description"] == actor["description"]
    assert result["aliases"] == actor["aliases"]
    assert any(item["id"] == "T1566" for item in result["ttps"])
    assert any(item["name"] == "Phishing" for item in result["ttps"])
    
    print("SUCCESS: Actor tool validated successfully against data/actors.json!")
    print(f"Resulting Confidence Score: {result['confidence']}\n")

if __name__ == "__main__":
    test_actor_tool_uses_dataset_confidence_and_ttp_details()
