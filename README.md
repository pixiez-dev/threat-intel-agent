# Threat Intel Agent

A small SOC-oriented assistant for threat-intelligence questions, built around a tool-using LangChain and local dataset (mock). The project is designed to support both a command-line demo and a Streamlit web interface.

## 1. Project overview

This project combines:
- a reasoning agent that interprets analyst questions,
- a small set of threat-intelligence tools for actors, exposures, IP reputation, and pivoting,
- local JSON datasets for evidence-backed answers,
- optional live API enrichment for IP reputation (AbuseIPDB) and vulnerability lookups (NVD).

The main goal is to make the reasoning process visible and explainable: the agent should use tools, cite evidence, and return structured information rather than inventing facts.

## 2. Tech stack

### Core
- Python
- LangChain
- Streamlit (for the dashboard UI)

### LLM providers
The current runtime supports switching the provider through the LLM_PROVIDER setting:
- Gemini
- OpenAI
- Groq

The provider is selected in env file for cli and web streamlit using the drop-dwon button.

### Evidence/dataset and services
- Local JSON datasets in data/
- AbuseIPDB API for live IP reputation checks
- NVD REST API for public CVE/vulnerability lookups
  
## 3. Setup

### Prerequisites
- Python 3.10+
- A project virtual environment (the repository already includes a local venv under the parent folder)

### 1. Clone Repository (if using zip file, skip this part)

```bash
git clone (https://github.com/pixiez-dev/threat-intel-agent.git)
```

---

### 2. Navigate to threat_intel_agent folder

```bash
cd threat_intel_agent
```

---

### 3. Create Virtual Environment

```bash
python -m venv venv
```

---

### 4. Activate Virtual Environment

### Windows

```bash
.\venv\Scripts\activate
```

---

### 5. Install Dependencies

```bash
pip install -r requirements2.txt
```

---

### 6. Environment Configuration

Create a `.env` file from the .env.exmaple. 

Create a local .env file in the project root using the same variable names as the included example file.
At minimum, the app expects:
- LLM_PROVIDER (for example: gemini, openai, groq)
- API keys for the provider you choose
- ABUSEIPDB_API_KEY if you want live IP reputation checks

### Project Structure

```text
project/ 
│venv/
│threat-intel-agent/  
├── app.py (CLI)
├── web_app.py (streamlit)
├── .env.example (create your own .env file)
├── requirements2.txt
├── test_harness.py
│
├── data/
│   ├── actors.json
│   ├── pivot_data.json
│   ├── nvd_cache.json
│   ├── software_vulnls.json
│
├── logs/ 
│   ├── agent.log
│
├── agent/
│   ├── memory.py 
│   ├── agent_executor.py 
│   ├── tools_registry.py  
│
├── tools/
│   ├── actor_tool.py
│   ├── exposure_tool.py
│   ├── ioc_tool.py
│   ├── pivot_tool.py
│
├── security/
│   ├── prompt_guard.py
│
├── utils/
│   ├── logger.py 
|
├── services/ 
│   ├── abuseipdb_service.py
│   ├── nvd_service.py
|
└── tests/
    ├── test_actor_tool.py
    ├── test_agent.py
    ├── test_nvd_services.py
    ├── test_memory.py (no code, empty)
    ├── test_exposure_tool.py 
    ├── test_prompt_guard.py 
    ├── test_tools.py
```

### Run the app
Command-line version:

```powershell
python app.py
```

Web version:

```powershell
streamlit run web_app.py
```

## 4. Simplified architecture

### Entry points
- app.py: console chat interface
- web_app.py: Streamlit web chat interface

### Agent runtime
- agent/agent_executor.py
  - loads the configured model,
  - builds the LangChain agent,
  - applies prompt guardrails,
  - keeps chat memory for multi-turn context,
  - prints trace output for inspection.

### Tools
- agent/tools_registry.py
  - registers the threat-intelligence tools that the agent can call.

The tool set is:
- actor_lookup: reads actor profiles and TTPs from data/actors.json
- ioc_lookup: checks IP reputation through AbuseIPDB
- exposure_check: checks software exposure using local vulnerability data and NVD fallback
- pivot_lookup: returns related pivot context from data/pivot_data.json

### Data layer
- data/actors.json: threat actor descriptions, aliases, and TTP mappings
- data/software_vulns.json: software/version exposure examples and CVEs
- data/pivot_data.json: pivot relationships for IOC/IP context
- data/nvd_cache.json: cached NVD results when live lookups are used

### Security / guardrails
- security/prompt_guard.py: blocks obvious prompt-injection phrases and filters out off-scope requests before the agent runs

### Validation
- tests/: contains verification checks for actor data, exposure logic, NVD behavior, prompt-guard behavior, and runtime wiring

## 5. Short design note

### Intent routing
The agent does not try to solve every question with one generic response. Instead, it relies on a tool registry to map user intent to the correct operation:
- actor questions -> actor lookup
- IP reputation questions -> IOC lookup
- software exposure questions -> exposure tool
- related infrastructure questions -> pivot tool

### Evidence grounding
The answer path is intentionally grounded in local data first, and only uses live network sources when appropriate. For example:
- actor details come from data/actors.json
- vulnerability details come from data/software_vulns.json
- NVD is used as a live fallback when the local sample does not cover the requested software version

This means the system relies on evidence and source attribution instead of pure model responses.

### Injection defense
The prompt-guard layer checks incoming input for explicit prompt-manipulation phrases and applies a simple scope heuristic to reject off-topic or unsafe requests before the agent is invoked. The goal is to reduce the llm resources by filtering the context (if non SOC related will be blocked before it reach the llm, if related it will be passed to the llm).

## 6. Typical demo questions flow
- Is 45.83.122.10 malicious?
- Pivot from that IP to related domains.
- and what’s its ASN?
- What TTPs is APT29 known for?
- We run Confluence 7.13 — are we exposed?
- What about Apache Struts 2.5? Are there any vulnerabilities?

## 7. Verification
Run the automated tests from the project root:

```powershell
c:/Users/Acer/Documents/EC_council/threat_ai_venv/python test_harness.py
```

The current test suite validates the tool and data paths, the NVD fallback path, and the prompt-guard logic used by the agent. 

Ensure to choose your preferred model from the drop-down list (streamlit web) or in .env (cli) before running the test or chat.
