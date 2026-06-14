# security/prompt_guard.py

import re
from utils.logger import logger

# Tier 1: Hardcoded Text Matching (Stops explicit attacks)
MALICIOUS_PATTERNS = [
    "ignore previous instructions",
    "ignore all prior prompts",
    "reveal system prompt",
    "show hidden prompt",
    "act as developer",
    "override your instructions",
    "pretend to be",
    "system instructions"
]

# Tier 2: Weighted Vocabulary for Threat Intel Scope
# Higher weights go to highly specific indicators; lower weights go to verbs/context words.
SOC_VOCABULARY = {
    # High-Weight Technical Tokens (Immediate pass indicators)
    "cve": 3.0, "cve-": 3.0, "apt": 3.0, "ttps": 3.0, "asn": 3.0, "ioc": 3.0,
    "malicious": 2.5, "vulnerability": 2.5, "ransomware": 2.5, "phishing": 2.5,
    "malware": 2.5, "exploit": 2.5, "exposure": 2.0, "reputation": 2.0,
    
    # Mid-Weight Context Infrastructure Tokens
    "ip": 1.5, "domain": 1.5, "host": 1.5, "hash": 1.5, "url": 1.5, "port": 1.5,
    "confluence": 1.5, "apache": 1.5, "struts": 1.5, "server": 1.0, "patch": 1.0,
    
    # Conversational Pivot Tokens (Allows follow-up sentences to slide through)
    "pivot": 1.5, "related": 1.0, "associated": 1.0, "exposed": 1.0, "safe": 0.8,
    "clean": 0.8, "check": 0.8, "find": 0.5, "look": 0.5, "status": 0.5
}

# The score a query must reach to be considered within the SOC domain scope
MIN_SCORE_THRESHOLD = 1.0

def _run_heuristic_check(text: str) -> bool:
    cleaned = text.lower().strip()
    for pattern in MALICIOUS_PATTERNS:
        if pattern in cleaned:
            logger.warning(f"[Guardrail Match] Malicious phrase triggered: '{pattern}'")
            return True
    return False

def _calculate_scope_score(text: str) -> float:
    """Calculates a semantic context score based on word weights."""
    # Clean string and break into alphanumeric lowercase words
    words = re.findall(r'\b[a-z0-9_-]+\b', text.lower())
    
    total_score = 0.0
    matched_words = set()
    
    for word in words:
        # Match explicit words or regex patterns (e.g., matching 'cve-2022-26134' via 'cve')
        for vocab_item, weight in SOC_VOCABULARY.items():
            if vocab_item in word and vocab_item not in matched_words:
                total_score += weight
                matched_words.add(vocab_item) # Count each unique keyword match only once per input
                
    return total_score

def detect_injection(text: str) -> tuple[bool, str]:
    """
    Main Entrypoint called by agent_executor.py.
    Returns a tuple: (is_blocked, response_message)
    """
    if not text.strip():
        return True, "Request rejected: Empty input."

    # Tier 1: Injection Phrase Defense
    if _run_heuristic_check(text):
        return True, "Security Alert: Malicious interaction pattern or system prompt manipulation detected. Request rejected."

    # Tier 2: Pure Local Threshold Engine
    scope_score = _calculate_scope_score(text)
    logger.info(f"[Guardrail Engine] Calculated prompt scope score: {scope_score}")
    
    if scope_score < MIN_SCORE_THRESHOLD:
        logger.warning(f"[Guardrail Block] Query dropped locally. Score {scope_score} is below threshold {MIN_SCORE_THRESHOLD}.")
        return True, "Request Filtered: This query falls outside the operational scope of this Threat Intelligence Agent."

    return False, ""