# web_app.py

import os
import sys
import json
from pathlib import Path

# Force the directory into python workspace memory paths
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
from agent.agent_executor import run_agent, memory

# Page UI Metadata Configurations
st.set_page_config(
    page_title="AI SOC Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Force the mouse pointer to stay as an arrow pointer or pointer hand over dropdown text elements
st.markdown(
    """
    <style>
    /* target the select box wrapper element */
    div[data-baseweb="select"] {
        cursor: pointer !important;
    }
    /* target the literal text inside the select box container */
    div[data-testid="stSelectbox"] div {
        cursor: pointer !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ===================================================
# SIDEBAR CONTROL CENTER (web_app.py)
# ===================================================
st.sidebar.title("🛡️ Threat Intel Engine")
st.sidebar.caption("Conversational Threat Intelligence Analyst")
st.sidebar.markdown("---")

# 1. Real-Time Dynamic LLM Provider Dropdown Selector
provider_options = ["Gemini", "Groq", "OpenAI"]
default_provider = os.getenv("LLM_PROVIDER", "gemini").strip().capitalize()

# Fallback in case the .env value isn't in our clean option list
if default_provider not in provider_options:
    default_provider = "Gemini"

selected_provider = st.sidebar.selectbox(
    "Active LLM Provider",
    options=provider_options,
    index=provider_options.index(default_provider)
)

# 2. Dynamically inject the user's choice into the runtime environment variables
os.environ["LLM_PROVIDER"] = selected_provider.lower()

# ===================================================
# 3. Dynamic LLM Initialization Guardrail (web_app.py)
# ===================================================
from agent import agent_executor

# Create a session state variable to track provider error states safely
if "provider_error" not in st.session_state:
    st.session_state.provider_error = None

try:
    # Attempt to cleanly rebuild the LLM instance based on dropdown switch
    agent_executor.llm = agent_executor._build_llm()
    
    # If successful, re-link the agent executor to use the freshly rebuilt LLM definition
    agent_executor.agent = agent_executor.create_agent(
        agent_executor.llm,
        agent_executor.TOOLS,
        system_prompt=agent_executor.SYSTEM_PROMPT,
    )
    # Clear out any stale historical initialization errors
    st.session_state.provider_error = None

except Exception as err:
    # Capture the initialization error text without letting the application crash
    error_msg = str(err)
    if "Missing credentials" in error_msg or "api_key" in error_msg:
        st.session_state.provider_error = f"🔑 **Authentication Failure:** Missing or invalid API key for **{selected_provider}**. Please add it to your `.env` configuration file."
    else:
        st.session_state.provider_error = f"⚠️ **Provider Error ({selected_provider}):** {error_msg}"

st.sidebar.markdown("---")

# Navigation Console
app_view = st.sidebar.radio(
    "Navigation Console",
    ["Analyst Chat Portal", "System Validation Suite"]
)

st.sidebar.markdown("---")
st.sidebar.markdown("**Egress Output Guard:** `max_tokens=350`")

# ===================================================
# VIEW 1: ANALYST CHAT PORTAL
# ===================================================
if app_view == "Analyst Chat Portal":
    st.title("🛡️ Autonomous Threat Intelligence Analyst Assistant")
    st.markdown("Query threat profiles, pivot assets, or audit real-time software version exposures cleanly.")

    if st.sidebar.button("Wipe Chat Memory Vault"):
        memory.clear()
        st.success("Session contextual history flushed cleanly.")
        st.rerun()

    st.markdown("---")

    # 🚨 DYNAMIC INITIALIZATION ERROR ALERT BANNER
    if st.session_state.provider_error:
        st.error(st.session_state.provider_error)
        st.info("💡 **Resolution:** Switch back to **Gemini** in the sidebar control center to resume analysis.")

    # Render Active Turn State Vault History Logs
    for msg in memory.get_history():
        if msg["role"] == "user":
            with st.chat_message("user"): st.write(msg["content"])
        else:
            with st.chat_message("assistant"): st.write(msg["content"])

    # Monitor user input entry (DISABLED if there is an active provider configuration error)
    if st.session_state.provider_error:
        st.chat_input("Chat integration disabled due to missing provider configuration credentials...", disabled=True)
    else:
        if user_query := st.chat_input("Ask about malicious IPs, Threat Actors (e.g., APT29), or Software versions..."):
            with st.chat_message("user"):
                st.write(user_query)

            with st.spinner("Invoking agents..."):
                agent_response = run_agent(user_query)

            # Render and refresh chat turns
            with st.chat_message("assistant", avatar="🤖"):
                st.write(agent_response)
            st.rerun()

# ===================================================
# VIEW 2: SYSTEM VALIDATION SUITE (MANUAL PIACED HARNESS)
# ===================================================
elif app_view == "System Validation Suite":
    st.title("📊 Evaluation: Test Harness")
    st.markdown("Execute diagnostics one test case at a time.")
    
    try:
        import test_harness
        TEST_CASES = test_harness.TEST_CASES
    except ImportError:
        st.error("Unable to link test_harness.py matrix array fields. Check folder files layout placement.")
        TEST_CASES = {}

    if TEST_CASES:
        # Dropdown list selector mapped dynamically to the dict keys to fix indexing crashes
        selected_tc = st.selectbox("Select Target Framework Case Profile", list(TEST_CASES.keys()))
        case_details = TEST_CASES[selected_tc]
        
        # Display case description overview
        st.info(f"**Test Target Focus:** {case_details['name']} \n\n **Query payload sent:** *\"{case_details['query']}\"*")
        
        if st.button("Trigger Selective Evaluation Run", type="primary"):
            st.markdown("---")
            with st.spinner(f"Invoking active diagnostic pipeline routing for {selected_tc}..."):
                # Execute the real model run pipeline and save incrementally to the history file
                success = test_harness.execute_manual_test(selected_tc)
                
                if success:
                    st.success(f"🎉 **{selected_tc} Validation Passed!** Result successfully archived to the local test logs matrix.")
                else:
                    st.error(f"💥 **{selected_tc} Assertion Failed / Token Drop.** Check trace logs and quota constraints below.")
        
        st.markdown("---")
        st.subheader("📋 Cumulative Evaluation Report Progress Summary")
        st.markdown("Every manual selection you verify updates this master document cache incrementally without overwriting historical pass entries.")
        
        # Pull up the live history matrix file to render inside the Streamlit engine
        history_path = Path("results/manual_test_run_history.json")
        if history_path.exists():
            with open(history_path, "r", encoding="utf-8") as f:
                json_report = json.load(f)
                
            # Render neat mini stats cards
            summary = json_report.get("summary", {})
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Unique Profiles Verified", f"{len(json_report.get('results', {}))} / {summary.get('total_tests', 8)}")
            col2.metric("Compliance Success (Passed)", f"{summary.get('passed', 0)} Runs")
            col3.metric("Pipeline Failures (Quota Drops)", f"{summary.get('failed', 0)} Runs")
            
            st.markdown("#### Detailed Raw JSON Matrix Content")
            st.json(json_report)
        else:
            st.warning("No archived execution trace detected inside `results/manual_test_run_history.json` yet. Run a case above to begin documentation tracking.")
