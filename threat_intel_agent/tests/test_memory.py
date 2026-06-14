# tests/test_memory.py

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agent.agent_executor import run_agent, memory

def test_multi_turn_context_retention():
    print("\n--- Running Multi-Turn Agent Context Tests ---")
    
    # Clean state slate
    memory.chat_history = []
    
    # Step 1: Establish entity context
    print("Turn 1: Checking IP identification context...")
    turn1_response = run_agent("Is 45.83.122.10 malicious?")
    assert "45.83.122.10" in memory.get_history()[0]["content"]
    
    # Step 2: Use an anaphoric pointer reference ("it" / "that IP") to test tracking
    print("Turn 2: Testing context resolution via relative referencing...")
    turn2_response = run_agent("Pivot from that IP to related domains.")
    
    # FIX: Parse your history dictionary entries correctly
    history = memory.get_history()
    
    # Verify that the final response contains text retrieved by our pivot tool execution
    assert any("evil-domain.com" in msg["content"] for msg in history if msg["role"] == "assistant")
    
    print("\nSUCCESS: Context memory verification completed perfectly! The agent can resolve relative pointers.")

if __name__ == "__main__":
    test_multi_turn_context_retention()