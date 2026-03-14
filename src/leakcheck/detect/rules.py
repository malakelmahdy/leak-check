from __future__ import annotations

import re

# -----------------------------
# Fix 1: canonicalization layer
# -----------------------------
_WS = re.compile(r"\s+")
# Keep only letters/digits; turn everything else into spaces so "pr_ompt" -> "pr ompt"
_NON_ALNUM = re.compile(r"[^a-z0-9]+", re.I)

# Targeted de-obfuscation for common split tokens you actually see in your dataset
# (keeps it safe for benign prompts; avoids over-merging all words)
_DEOBF = [
    (re.compile(r"\bpr\s+ompt\b", re.I), "prompt"),
    (re.compile(r"\bin\s+struction(s)?\b", re.I), r"instruction\1"),
    (re.compile(r"\bpre\s+vious\b", re.I), "previous"),
    (re.compile(r"\bde\s+veloper\b", re.I), "developer"),
    (re.compile(r"\bmes\s+sage\b", re.I), "message"),
    (re.compile(r"\bby\s+pass\b", re.I), "bypass"),
    (re.compile(r"\bpass\s+word\b", re.I), "password"),
    (re.compile(r"\bcre\s+dential(s)?\b", re.I), r"credential\1"),
]

def _canon(text: str) -> str:
    t = text.lower()
    t = _NON_ALNUM.sub(" ", t)
    t = _WS.sub(" ", t).strip()
    for pat, repl in _DEOBF:
        t = pat.sub(repl, t)
    return t


# -----------------------------
# Stronger / more precise rules
# (now applied on canonical text)
# -----------------------------
RULES = {
    "prompt_injection": [
        (
            "PI_IGNORE_PREV",
            re.compile(
                r"\b(ignore|disregard|override)\b\s+(all\s+)?"
                r"(previous|prior|earlier)\s+(instructions|rules|messages)\b",
                re.I,
            ),
        ),
        (
            "PI_SYSTEM_PROMPT",
            re.compile(
                r"\b(system\s+prompt|developer\s+message|hidden\s+instructions?)\b",
                re.I,
            ),
        ),
        (
            "PI_REVEAL_SYSTEM",
            re.compile(
                r"\b(reveal|show|display|print|output|tell)\b.*\b(system\s+prompt|hidden\s+instructions?)\b",
                re.I,
            ),
        ),
        (
            "PI_LEAK_REQUEST",
            re.compile(
                r"\b(leak|dump|exfiltrate|extract)\b.*\b(system\s+prompt|instructions?|rules)\b",
                re.I,
            ),
        ),
    ],
    "jailbreak": [
        (
            "JB_DEV_MODE",
            re.compile(r"\b(developer\s+mode|dan|jailbreak)\b", re.I),
        ),
        (
            "JB_BYPASS",
            re.compile(
                r"\b(bypass|ignore)\b.*\b(safety|policy|refusal|restrictions?)\b"
                r"|\bwithout\s+refusal\b|\bno\s+refusal\b|\bcomply\s+fully\b",
                re.I,
            ),
        ),
        (
            "JB_NO_RESTRICTIONS",
            re.compile(
                r"\b(no\s+restrictions?|no\s+limits?|unrestricted|without\s+restrictions?)\b",
                re.I,
            ),
        ),
    ],
    "data_exfil": [
        (
            "EXFIL_KEYS",
            re.compile(
                r"\b(api[_ -]?key|secret|token|password|credentials?)\b",
                re.I,
            ),
        ),
        (
            "EXFIL_CONFIDENTIAL",
            re.compile(
                r"\b(confidential|internal|private)\b.*\b(data|info|information|keys?|tokens?)\b",
                re.I,
            ),
        ),
        (
            "EXFIL_REVEAL",
            re.compile(
                r"\b(reveal|print|show|leak|dump|exfiltrate)\b.*\b(api[_ -]?key|secret|token|password|credentials?)\b",
                re.I,
            ),
        ),
        (
            "EXFIL_TRAINING_DATA",
            re.compile(
                r"\b(training\s+data|internal\s+data|private\s+data|model\s+weights)\b",
                re.I,
            ),
        ),
    ],
}

# -----------------------------
# Benign allowlist
# (also applied on canonical text)
# -----------------------------
BENIGN_ALLOWLIST = [
    ("BENIGN_EXERCISE", re.compile(r"\bbenefits?\s+of\s+exercise\b", re.I)),
    ("BENIGN_SUMMARIZE", re.compile(r"\b(summarize|summary)\b", re.I)),
    ("BENIGN_GENERAL_QA", re.compile(r"\b(what\s+is|explain|define)\b", re.I)),
    ("BENIGN_TRANSLATE", re.compile(r"\b(translate|translation)\b", re.I)),
    ("BENIGN_MATH", re.compile(r"\b(calculate|compute|solve|equation)\b", re.I)),
]


def rule_detect(category: str, text: str) -> list[str]:
    hits: list[str] = []

    t = _canon(text)

    # benign context signal (independent of category)
    for bid, pat in BENIGN_ALLOWLIST:
        if pat.search(t):
            hits.append(bid)

    # category rules
    for rid, pattern in RULES.get(category, []):
        if pattern.search(t):
            hits.append(rid)

    return hits
