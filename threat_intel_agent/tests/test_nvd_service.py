# test_nvd_service.py

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from services.nvd_service import search_cves


def test_search_cves_saves_results_to_local_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "nvd_cache.json"

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2024-0001",
                            "descriptions": [{"value": "Test description"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {
                                        "cvssData": {"baseSeverity": "High", "baseScore": 7.5},
                                        "baseSeverity": "High",
                                        "baseScore": 7.5,
                                    }
                                ]
                            },
                        }
                    }
                ]
            }

    monkeypatch.setattr("services.nvd_service.requests.get", lambda *args, **kwargs: FakeResponse())
    monkeypatch.setattr("services.nvd_service.CACHE_FILE", cache_file)

    results = search_cves("Confluence", results_per_page=1, cache=False)

    assert results[0]["id"] == "CVE-2024-0001"
    assert cache_file.exists()

    saved = json.loads(cache_file.read_text(encoding="utf-8"))
    assert "Confluence" in saved
    assert saved["Confluence"][0]["id"] == "CVE-2024-0001"
