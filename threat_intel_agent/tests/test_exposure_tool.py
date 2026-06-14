# test_exposure_tool.py

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.exposure_tool import exposure_check

def test_exposure_tool_returns_local_dataset_result():
    print("\n--- Running Exposure Tool Test ---")
    result = exposure_check.invoke({"software_version": "Confluence 7.13"})

    assert "CVE-2022-26134" in result
    assert "Critical" in result
    assert "Internal Vulnerability Dataset" in result
    
    print("SUCCESS: Exposure tool correctly flagged local vulnerability data!")
    print(f"Output Sample: {result[:120]}...\n")

if __name__ == "__main__":
    test_exposure_tool_returns_local_dataset_result()
