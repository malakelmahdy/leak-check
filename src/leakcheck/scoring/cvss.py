from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING

"""
Legacy raw CVSS v3.1 helpers.

LeakCheck no longer uses this module in the active scoring path. The current
severity model is implemented in `score.py` as a deterministic CVSS-aligned
0.0-10.0 policy over LeakCheck evidence. These helpers are retained only as a
historical reference for the superseded raw-CVSS experiment.
"""

CVSS_V31_EXPLOITABILITY_COEFFICIENT = 8.22
CVSS_V31_IMPACT_COEFFICIENT_UNCHANGED = 6.42
CVSS_V31_IMPACT_COEFFICIENT_CHANGED = 7.52
CVSS_V31_SCOPE_COEFFICIENT_CHANGED = 1.08

CVSS_V31_ATTACK_VECTOR = {
    "network": 0.85,
    "adjacent": 0.62,
    "local": 0.55,
    "physical": 0.20,
}

CVSS_V31_ATTACK_COMPLEXITY = {
    "low": 0.77,
    "high": 0.44,
}

CVSS_V31_PRIVILEGES_REQUIRED = {
    "unchanged": {
        "none": 0.85,
        "low": 0.62,
        "high": 0.27,
    },
    "changed": {
        "none": 0.85,
        "low": 0.68,
        "high": 0.50,
    },
}

CVSS_V31_USER_INTERACTION = {
    "none": 0.85,
    "required": 0.62,
}

CVSS_V31_SCOPE = {
    "unchanged": "U",
    "changed": "C",
}

CVSS_V31_CIA = {
    "none": 0.00,
    "low": 0.22,
    "high": 0.56,
}

CVSS_V31_EXPLOIT_CODE_MATURITY = {
    "high": 1.00,
    "functional": 0.97,
    "proof_of_concept": 0.94,
    "unproven": 0.91,
}

CVSS_V31_REMEDIATION_LEVEL = {
    "unavailable": 1.00,
    "workaround": 0.97,
    "temporary_fix": 0.96,
    "official_fix": 0.95,
}

CVSS_V31_REPORT_CONFIDENCE = {
    "confirmed": 1.00,
    "reasonable": 0.96,
    "unknown": 0.92,
}

CVSS_V31_SECURITY_REQUIREMENT = {
    "low": 0.50,
    "medium": 1.00,
    "high": 1.50,
}

CVSS_V31_VECTOR_CODES = {
    "attack_vector": {
        "network": "N",
        "adjacent": "A",
        "local": "L",
        "physical": "P",
    },
    "attack_complexity": {
        "low": "L",
        "high": "H",
    },
    "privileges_required": {
        "none": "N",
        "low": "L",
        "high": "H",
    },
    "user_interaction": {
        "none": "N",
        "required": "R",
    },
    "scope": CVSS_V31_SCOPE,
    "impact": {
        "none": "N",
        "low": "L",
        "high": "H",
    },
    "exploit_code_maturity": {
        "high": "H",
        "functional": "F",
        "proof_of_concept": "P",
        "unproven": "U",
    },
    "remediation_level": {
        "unavailable": "U",
        "workaround": "W",
        "temporary_fix": "T",
        "official_fix": "O",
    },
    "report_confidence": {
        "confirmed": "C",
        "reasonable": "R",
        "unknown": "U",
    },
    "security_requirement": {
        "low": "L",
        "medium": "M",
        "high": "H",
    },
}


@dataclass(frozen=True)
class CVSSv31Metrics:
    attack_vector: str
    attack_complexity: str
    privileges_required: str
    user_interaction: str
    scope: str
    confidentiality: str
    integrity: str
    availability: str
    exploit_code_maturity: str
    remediation_level: str
    report_confidence: str
    confidentiality_requirement: str
    integrity_requirement: str
    availability_requirement: str
    modified_attack_vector: str
    modified_attack_complexity: str
    modified_privileges_required: str
    modified_user_interaction: str
    modified_scope: str
    modified_confidentiality: str
    modified_integrity: str
    modified_availability: str


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def roundup_1_decimal(value: float) -> float:
    d = Decimal(str(value))
    return float((d * Decimal("10")).to_integral_value(rounding=ROUND_CEILING) / Decimal("10"))


def cvss_v31_impact_subscore(confidentiality: float, integrity: float, availability: float) -> float:
    c = clamp(confidentiality, 0.0, 1.0)
    i = clamp(integrity, 0.0, 1.0)
    a = clamp(availability, 0.0, 1.0)
    return 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))


def cvss_v31_impact(scope: str, impact_subscore: float) -> float:
    iss = clamp(impact_subscore, 0.0, 1.0)
    if scope == "changed":
        return (
            CVSS_V31_IMPACT_COEFFICIENT_CHANGED * (iss - 0.029)
            - 3.25 * ((iss - 0.02) ** 15)
        )
    return CVSS_V31_IMPACT_COEFFICIENT_UNCHANGED * iss


def cvss_v31_exploitability(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
) -> float:
    av = CVSS_V31_ATTACK_VECTOR[attack_vector]
    ac = CVSS_V31_ATTACK_COMPLEXITY[attack_complexity]
    pr = CVSS_V31_PRIVILEGES_REQUIRED[scope][privileges_required]
    ui = CVSS_V31_USER_INTERACTION[user_interaction]
    return CVSS_V31_EXPLOITABILITY_COEFFICIENT * av * ac * pr * ui


def cvss_v31_base_score(scope: str, impact: float, exploitability: float) -> float:
    if impact <= 0:
        return 0.0
    if scope == "changed":
        return roundup_1_decimal(min(CVSS_V31_SCOPE_COEFFICIENT_CHANGED * (impact + exploitability), 10.0))
    return roundup_1_decimal(min(impact + exploitability, 10.0))


def cvss_v31_temporal_score(base_score: float, exploit_code_maturity: str, remediation_level: str, report_confidence: str) -> float:
    e = CVSS_V31_EXPLOIT_CODE_MATURITY[exploit_code_maturity]
    rl = CVSS_V31_REMEDIATION_LEVEL[remediation_level]
    rc = CVSS_V31_REPORT_CONFIDENCE[report_confidence]
    return roundup_1_decimal(base_score * e * rl * rc)


def cvss_v31_modified_impact_subscore(
    confidentiality_requirement: str,
    integrity_requirement: str,
    availability_requirement: str,
    modified_confidentiality: float,
    modified_integrity: float,
    modified_availability: float,
) -> float:
    cr = CVSS_V31_SECURITY_REQUIREMENT[confidentiality_requirement]
    ir = CVSS_V31_SECURITY_REQUIREMENT[integrity_requirement]
    ar = CVSS_V31_SECURITY_REQUIREMENT[availability_requirement]
    mc = clamp(modified_confidentiality, 0.0, 1.0)
    mi = clamp(modified_integrity, 0.0, 1.0)
    ma = clamp(modified_availability, 0.0, 1.0)
    return min(1.0 - ((1.0 - cr * mc) * (1.0 - ir * mi) * (1.0 - ar * ma)), 0.915)


def cvss_v31_modified_impact(scope: str, modified_impact_subscore: float) -> float:
    miss = clamp(modified_impact_subscore, 0.0, 0.915)
    if scope == "changed":
        return (
            CVSS_V31_IMPACT_COEFFICIENT_CHANGED * (miss - 0.029)
            - 3.25 * ((miss * 0.9731 - 0.02) ** 13)
        )
    return CVSS_V31_IMPACT_COEFFICIENT_UNCHANGED * miss


def cvss_v31_environmental_score(
    modified_scope: str,
    modified_impact: float,
    modified_exploitability: float,
    exploit_code_maturity: str,
    remediation_level: str,
    report_confidence: str,
) -> float:
    e = CVSS_V31_EXPLOIT_CODE_MATURITY[exploit_code_maturity]
    rl = CVSS_V31_REMEDIATION_LEVEL[remediation_level]
    rc = CVSS_V31_REPORT_CONFIDENCE[report_confidence]

    if modified_impact <= 0:
        return 0.0

    if modified_scope == "changed":
        adjusted = roundup_1_decimal(min(CVSS_V31_SCOPE_COEFFICIENT_CHANGED * (modified_impact + modified_exploitability), 10.0))
    else:
        adjusted = roundup_1_decimal(min(modified_impact + modified_exploitability, 10.0))

    return roundup_1_decimal(adjusted * e * rl * rc)


def cvss_v31_vector_string(metrics: CVSSv31Metrics) -> str:
    return (
        "CVSS:3.1/"
        f"AV:{CVSS_V31_VECTOR_CODES['attack_vector'][metrics.attack_vector]}/"
        f"AC:{CVSS_V31_VECTOR_CODES['attack_complexity'][metrics.attack_complexity]}/"
        f"PR:{CVSS_V31_VECTOR_CODES['privileges_required'][metrics.privileges_required]}/"
        f"UI:{CVSS_V31_VECTOR_CODES['user_interaction'][metrics.user_interaction]}/"
        f"S:{CVSS_V31_VECTOR_CODES['scope'][metrics.scope]}/"
        f"C:{CVSS_V31_VECTOR_CODES['impact'][metrics.confidentiality]}/"
        f"I:{CVSS_V31_VECTOR_CODES['impact'][metrics.integrity]}/"
        f"A:{CVSS_V31_VECTOR_CODES['impact'][metrics.availability]}/"
        f"E:{CVSS_V31_VECTOR_CODES['exploit_code_maturity'][metrics.exploit_code_maturity]}/"
        f"RL:{CVSS_V31_VECTOR_CODES['remediation_level'][metrics.remediation_level]}/"
        f"RC:{CVSS_V31_VECTOR_CODES['report_confidence'][metrics.report_confidence]}/"
        f"CR:{CVSS_V31_VECTOR_CODES['security_requirement'][metrics.confidentiality_requirement]}/"
        f"IR:{CVSS_V31_VECTOR_CODES['security_requirement'][metrics.integrity_requirement]}/"
        f"AR:{CVSS_V31_VECTOR_CODES['security_requirement'][metrics.availability_requirement]}/"
        f"MAV:{CVSS_V31_VECTOR_CODES['attack_vector'][metrics.modified_attack_vector]}/"
        f"MAC:{CVSS_V31_VECTOR_CODES['attack_complexity'][metrics.modified_attack_complexity]}/"
        f"MPR:{CVSS_V31_VECTOR_CODES['privileges_required'][metrics.modified_privileges_required]}/"
        f"MUI:{CVSS_V31_VECTOR_CODES['user_interaction'][metrics.modified_user_interaction]}/"
        f"MS:{CVSS_V31_VECTOR_CODES['scope'][metrics.modified_scope]}/"
        f"MC:{CVSS_V31_VECTOR_CODES['impact'][metrics.modified_confidentiality]}/"
        f"MI:{CVSS_V31_VECTOR_CODES['impact'][metrics.modified_integrity]}/"
        f"MA:{CVSS_V31_VECTOR_CODES['impact'][metrics.modified_availability]}"
    )


def cvss_v31_severity(score: float) -> str:
    if score == 0.0:
        return "none"
    if score <= 3.9:
        return "low"
    if score <= 6.9:
        return "medium"
    if score <= 8.9:
        return "high"
    return "critical"
