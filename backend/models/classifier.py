"""
AI Threat Classifier
Multi-model analysis pipeline for threat detection.
"""

import time
import re
import math
import html
import unicodedata
from typing import Optional


# ─── Sanitization ──────────────────────────────────────────────────────────

def sanitize_output(text: str) -> str:
    """
    Sanitize any string before including it in API response.
    Prevents second-order payload delivery through AI summaries.
    """
    if not text:
        return ""
    # Strip control chars
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Escape HTML entities
    text = html.escape(text, quote=True)
    # Break javascript: and data: protocols
    text = re.sub(r'javascript\s*:', 'javascript\u200b:', text, flags=re.IGNORECASE)
    text = re.sub(r'data\s*:', 'data\u200b:', text, flags=re.IGNORECASE)
    return text[:2000]  # Hard cap on response length


# ─── Obfuscation Entropy Analysis ──────────────────────────────────────────

def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def obfuscation_score(text: str) -> float:
    """
    Estimate obfuscation likelihood based on:
    - High Shannon entropy (compressed / encrypted-looking)
    - High ratio of non-alphanumeric chars
    - Presence of known obfuscation markers
    """
    if not text or len(text) < 10:
        return 0.0

    entropy = shannon_entropy(text)
    # Normalize to 0-1 (max entropy for ASCII is ~7 bits)
    entropy_score = min(entropy / 7.0, 1.0)

    # Non-alphanumeric ratio
    non_alnum = sum(1 for c in text if not c.isalnum() and not c.isspace())
    na_ratio = min(non_alnum / max(len(text), 1), 1.0)

    # Known obfuscation patterns
    obf_patterns = [
        r'(?:\+\[\]|\[\]\[|\(\!\+)',          # JSFuck
        r'(?:\\x[0-9a-fA-F]{2}){4,}',         # Hex escape chains
        r'(?:[A-Za-z0-9+/]{4}){10,}={0,2}$',  # Long base64
        r'(?:eval|Function|setTimeout)\s*\(',   # Dynamic eval
        r'String\.fromCharCode\s*\(',           # Char code concat
        r'(?:unescape|decodeURIComponent)\s*\(',# Decode calls
    ]
    pattern_hits = sum(
        1 for p in obf_patterns if re.search(p, text, re.IGNORECASE)
    )
    pattern_score = min(pattern_hits / len(obf_patterns), 1.0)

    # Weighted combination
    score = (entropy_score * 0.35) + (na_ratio * 0.25) + (pattern_score * 0.40)
    return round(min(score, 1.0), 3)


# ─── Rule-based Prompt Injection Scoring ───────────────────────────────────

PROMPT_INJECTION_PATTERNS = [
    # High confidence
    (0.95, r'ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?'),
    (0.95, r'disregard\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)'),
    (0.90, r'your\s+(?:new|real|true|actual)\s+(?:goal|objective|task)\s+is'),
    (0.90, r'from\s+now\s+on\s+you\s+(?:are|must|will|should)'),
    (0.90, r'forget\s+(?:everything|all)\s+(?:you\s+(?:were|are)|about)'),
    (0.85, r'(?:reveal|print|output|show|display)\s+(?:your|the)\s+(?:system\s+)?prompt'),
    (0.85, r'act\s+as\s+if\s+you\s+have\s+no\s+(?:restrictions?|limits?|guidelines?)'),
    (0.85, r'\bDAN\b.*do\s+anything\s+now'),
    (0.80, r'(?:jailbreak|uncensored|unrestricted|unfiltered)\s+(?:mode|ai|model|version)'),
    # Medium confidence
    (0.65, r'\[INST\]|\[/INST\]|<\|(?:im_start|im_end|system|user|assistant)\|>'),
    (0.60, r'(?:exfil(?:trate)?|data\s+(?:breach|leak|theft))'),
    (0.55, r'pretend\s+(?:you|that)\s+(?:are|have\s+no)'),
    (0.50, r'(?:bypass|circumvent|override)\s+(?:your|the|all)\s+(?:safety|filter|restriction)'),
]

def prompt_injection_score(text: str) -> float:
    """
    Multi-pattern prompt injection scorer.
    Returns highest confidence match found.
    """
    if not text:
        return 0.0

    text_lower = text.lower()
    max_score = 0.0
    match_count = 0

    for confidence, pattern in PROMPT_INJECTION_PATTERNS:
        try:
            if re.search(pattern, text_lower, re.IGNORECASE | re.DOTALL):
                match_count += 1
                if confidence > max_score:
                    max_score = confidence
        except re.error:
            continue

    # Boost score if multiple patterns match
    if match_count > 1:
        boost = min(match_count * 0.05, 0.15)
        max_score = min(max_score + boost, 1.0)

    return round(max_score, 3)


# ─── YARA-like Signature Matching ──────────────────────────────────────────

MALWARE_SIGNATURES = {
    "EICAR_TEST":         r'X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}',
    "METERPRETER_STUB":   r'(?:meterpreter|msfvenom|msf/payload)',
    "WEBSHELL_PHP":       r'(?:eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|gzuncompress))',
    "WEBSHELL_GENERIC":   r'(?:passthru|shell_exec|proc_open|system)\s*\(',
    "CRYPTOMINER_XMR":    r'(?:stratum\+tcp|xmrig|monero|coinhive|cryptonight)',
    "LOG4SHELL":          r'\$\{(?:j|J)ndi:(?:ldap|rmi|dns)',
    "SSTI_PAYLOADS":      r'(?:\{\{.*7\*7.*\}\}|\$\{.*7\*7.*\})',
    "XXSSPROTECTION_BYPASS": r'(?:<\s*script\s*>.*<\s*/\s*script\s*>)',
}

def malware_signature_scan(text: str) -> list[str]:
    """Scan for known malware signatures. Returns list of matched signature names."""
    matches = []
    for name, pattern in MALWARE_SIGNATURES.items():
        try:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                matches.append(sanitize_output(name))
        except re.error:
            continue
    return matches


# ─── Main Analysis Entry Point ──────────────────────────────────────────────

def analyze(text: str) -> dict:
    """
    Run full AI-augmented analysis pipeline.
    Returns sanitized result dict.
    """
    start = time.time()

    pi_score  = prompt_injection_score(text)
    obf_score = obfuscation_score(text)
    sigs      = malware_signature_scan(text)

    # Build summary
    parts = []
    if pi_score >= 0.85:
        parts.append(f"High-confidence prompt injection detected (score: {pi_score:.0%}).")
    elif pi_score >= 0.5:
        parts.append(f"Possible prompt injection attempt (score: {pi_score:.0%}).")

    if obf_score >= 0.7:
        parts.append(f"Heavy obfuscation detected (entropy score: {obf_score:.0%}).")
    elif obf_score >= 0.4:
        parts.append(f"Moderate obfuscation patterns present (score: {obf_score:.0%}).")

    if sigs:
        parts.append(f"Malware signatures matched: {', '.join(sigs)}.")

    if not parts:
        if pi_score < 0.1 and obf_score < 0.1:
            parts.append("No significant AI threat indicators detected.")
        else:
            parts.append("Low-level indicators present; manual review recommended.")

    summary = sanitize_output(" ".join(parts))

    latency_ms = int((time.time() - start) * 1000)

    return {
        "promptInjectionScore":    pi_score,
        "obfuscationScore":        obf_score,
        "malwareSignatureMatches": sigs,
        "threatSummary":           summary,
        "modelUsed":               "ZC-RuleEngine-v1 + Entropy-Analyzer",
        "latencyMs":               latency_ms,
    }
