# agent/tools_registry.py

from tools.actor_tool import actor_lookup
from tools.ioc_tool import ioc_lookup
from tools.exposure_tool import exposure_check
from tools.pivot_tool import pivot_lookup

TOOLS = [
    actor_lookup,
    ioc_lookup,
    exposure_check,
    pivot_lookup
]