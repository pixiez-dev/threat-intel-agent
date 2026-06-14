#test_tools.py

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.actor_tool import actor_lookup
from tools.exposure_tool import exposure_check
from tools.pivot_tool import pivot_lookup
from tools.ioc_tool import ioc_lookup

print(
    actor_lookup.invoke(
        {"actor_name": "APT29"}
    )
)

print(
    exposure_check.invoke(
        {
            "software_version":
            "Confluence 7.13"
        }
    )
)

print(
    pivot_lookup.invoke(
        {
            "ioc":
            "45.83.122.10"
        }
    )
)

print(
    ioc_lookup.invoke(
        {
            "ip":
            "8.8.8.8"
        }
    )
)