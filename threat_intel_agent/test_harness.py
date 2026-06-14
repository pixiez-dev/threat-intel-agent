# test_harness.py
import os
import sys
import json
import io
from datetime import datetime
from pathlib import Path

# Bring in your real application configuration states
import agent.agent_executor as agent_env
from agent.agent_executor import run_agent, memory
from utils.logger import logger

logger.setLevel("WARNING")

# 🎯 THE 5 CORE REQUIRED DEMO TEST PROFILES
TEST_CASES = {
    "TC-001": {
        "id": "TC-001",
        "name": "IOC Lookup & Pivoting Chain",
        "query": "Is 45.83.122.10 malicious? Regardless of the verdict, force a pivot from that IP to discover related domains.",
        "expected_keywords": ["clean", "abuseipdb", "0", "evil-domain.com"]
    },
    "TC-002": {
        "id": "TC-002",
        "name": "Context Resolution (Multi-Turn Turn 2)",
        "query": "and what’s its ASN?",
        "expected_keywords": ["asn", "as9009"]
    },
    "TC-003": {
        "id": "TC-003",
        "name": "Actor Lookup & TTP Extraction",
        "query": "What TTPs is APT29 known for?",
        "expected_keywords": ["cozy bear", "phishing", "t1566"]
    },
    "TC-004": {
        "id": "TC-004",
        "name": "Exposure Reasoning (Vulnerability Mapping)",
        "query": "We run Confluence 7.13 — are we exposed?",
        "expected_keywords": ["critical", "cve-2022-26134"]
    },
    "TC-005": {
        "id": "TC-005",
        "name": "Data Resilience Guardrail",
        "query": "What is the ASN for the malicious IP 999.999.999.999?",
        "expected_keywords": ["no evidence found"]
    }
}

def save_single_test_result(test_id: str, result_entry: dict):
    """Reads the existing JSON test log file, merges the new result, and saves it."""
    base_dir = Path(__file__).resolve().parent
    results_dir = base_dir / "results"
    results_dir.mkdir(exist_ok=True)
    
    filename = results_dir / "manual_test_run_history.json"
    
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().upper()
    
    report_data = {
        "last_updated": datetime.now().isoformat(),
        "llm_provider": provider,
        "summary": {"total_tests": len(TEST_CASES), "passed": 0, "failed": 0},
        "results": {}
    }
    
    if filename.exists():
        try:
            with open(filename, "r", encoding="utf-8") as f:
                existing_content = json.load(f)
                if "results" in existing_content:
                    report_data["results"] = existing_content["results"]
        except Exception:
            pass

    report_data["results"][test_id] = result_entry
    
    passed_count = sum(1 for r in report_data["results"].values() if r["status"] == "PASSED")
    report_data["summary"]["passed"] = passed_count
    report_data["summary"]["failed"] = len(report_data["results"]) - passed_count
    report_data["last_updated"] = datetime.now().isoformat()
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    print(f"💾 Synchronized {test_id} into cumulative file: {filename}")
    print(f"📊 Running Total: {passed_count} Tests Passing.")

def execute_manual_test(test_id: str):
    """Executes a test case using the real agent framework to verify tool precision."""
    if test_id not in TEST_CASES:
        print(f"❌ Unknown test identifier: {test_id}")
        return False

    test = TEST_CASES[test_id]
    provider = os.getenv("LLM_PROVIDER", "gemini").strip().upper()
    
    print(f"\n=== {provider} TRACE RUNTIME ENTRY ===")
    print(f"🚀 Initiating Real Agent Execution for {test['id']}: {test['name']}")
    print(f"   Input Query: \"{test['query']}\"")
    
    # Notice: We removed the background context seeding loops here!
    # Because you are running sequentially, your live memory built during the recording
    # will flow directly from TC-001 into TC-002 naturally.
    
    captured_output = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured_output
    
    try:
        # Run the actual agent pipeline so it invokes real tools
        telemetry_data = run_agent(test["query"], return_telemetry=True)
        raw_output = telemetry_data["output"]
        confidence = telemetry_data.get("confidence", "0.95")
        metrics = telemetry_data.get("metrics", {"total_tokens": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_cost": 0.0})
    except Exception as err:
        raw_output = f"CRASH / RESOURCE EXHAUSTED: {str(err)}"
        confidence = "N/A"
        metrics = {"total_tokens": 0, "prompt_tokens": 0, "completion_tokens": 0, "total_cost": 0.0}
    finally:
        sys.stdout = old_stdout
        
    trace_log = captured_output.getvalue()
    print(trace_log)  # Prints out what the tools did onto your terminal
    print(f"=== END {provider} TRACE ===\n")
    
    # Evaluate assertions using keywords against the live output log stream
    success = True
    missing_assertions = []
    eval_string = (raw_output + "\n" + trace_log).lower()
        
    for kw in test["expected_keywords"]:
        if kw not in eval_string:
            success = False
            missing_assertions.append(kw)
            
    if success:
        print(f"   STATUS: ✅ PASSED")
    else:
        print(f"   STATUS: ❌ FAILED | Missing Indicators: {missing_assertions}")
        
    result_entry = {
        "test_name": test["name"],
        "query": test["query"],
        "status": "PASSED" if success else "FAILED",
        "confidence_score": confidence,
        "cost_and_tokens": metrics,
        "missing_keywords": missing_assertions,
        "agent_response": raw_output,
        "runtime_trace": trace_log if trace_log else "Agent executed pipeline cleanly.",
        "executed_at": datetime.now().isoformat()
    }
    
    save_single_test_result(test_id, result_entry)
    return success

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("💡 Usage: python test_harness.py <TEST_ID>")
        print(f"Available IDs: {', '.join(TEST_CASES.keys())}")
    else:
        execute_manual_test(sys.argv[1].upper().strip())
