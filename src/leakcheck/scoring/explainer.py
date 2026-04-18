from __future__ import annotations

from typing import Iterable

from leakcheck.common.schemas import ScoreContribution, ScoreExplanation, SeverityInput
from leakcheck.scoring.contracts import ScoringPolicyLike


def _format_value(value: object) -> str:
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _contribution_summary(contribution: ScoreContribution) -> str:
    sign = "+" if contribution.delta >= 0 else ""
    return f"{contribution.factor} ({sign}{contribution.delta:.2f})"


def _evidence_summary(evidence: SeverityInput) -> list[str]:
    summary = [
        f"category={evidence.attack_category}",
        f"verdict={evidence.final_verdict}",
    ]
    if evidence.rule_hits:
        summary.append(f"attack_rules={', '.join(evidence.rule_hits)}")
    if evidence.response_signals:
        summary.append(f"response_signals={', '.join(evidence.response_signals)}")
    if evidence.classifier_confidence is not None:
        summary.append(f"detection_confidence={float(evidence.classifier_confidence):.2f}")
    if evidence.similarity_score is not None:
        summary.append(f"similarity={float(evidence.similarity_score):.2f}")
    if evidence.repeatability is not None:
        summary.append(f"repeatability={float(evidence.repeatability):.2f}")
    return summary


def _caveats(
    evidence: SeverityInput,
    severity_label: str,
    cap_applied: bool,
) -> list[str]:
    caveats: list[str] = []
    if evidence.final_verdict == "safe":
        caveats.append("Safe verdicts force severity to 0.0 by policy.")
    if evidence.repeatability is None:
        caveats.append("Repeatability was unavailable and was treated as 0.0.")
    if evidence.similarity_score is None:
        caveats.append("Similarity support was unavailable and was treated as 0.0.")
    if not evidence.response_signals:
        caveats.append("No response-side evidence was available; the score rests on prompt-side evidence only.")
    if "RS_REFUSAL" in evidence.response_signals and evidence.final_verdict == "attack_attempt":
        caveats.append("A refusal signal mitigated the attempt severity because the model resisted the attack.")
    if cap_applied:
        caveats.append(
            f"The score was capped by the `{evidence.final_verdict}` policy so the final band stayed {severity_label}."
        )
    return caveats


def _rationale(
    final_score: float,
    severity_label: str,
    evidence: SeverityInput,
    top_contributors: Iterable[ScoreContribution],
    cap_applied: bool,
) -> str:
    if evidence.final_verdict == "safe":
        return (
            f"Final score {final_score:.1f} ({severity_label}) was forced to zero because the verdict is safe, "
            "so benign or refused-safe flows do not inflate severity."
        )

    contributor_text = ", ".join(_contribution_summary(item) for item in top_contributors)
    category = evidence.attack_category or evidence.classifier_label or "other"
    verdict = evidence.final_verdict
    sentence = (
        f"Final score {final_score:.1f} ({severity_label}) came from the `{category}` base severity and the "
        f"`{verdict}` outcome modifier, with the largest adjustments from {contributor_text}."
    )
    if cap_applied:
        sentence += " The raw total exceeded the verdict cap, so the final score was clamped before banding."
    return sentence


def build_score_explanation(
    policy: ScoringPolicyLike,
    evidence: SeverityInput,
    final_score: float,
    severity_label: str,
    contributions: list[ScoreContribution],
    raw_total: float,
    cap_applied: bool,
) -> ScoreExplanation:
    ordered = sorted(contributions, key=lambda item: abs(item.delta), reverse=True)
    top_contributors = ordered[:3]
    explanation = ScoreExplanation(
        score_version=policy.score_version,
        final_score=final_score,
        severity_label=severity_label,
        verdict=evidence.final_verdict,
        top_contributors=top_contributors,
        evidence_summary=_evidence_summary(evidence),
        rationale=_rationale(final_score, severity_label, evidence, top_contributors, cap_applied),
        caveats=_caveats(evidence, severity_label, cap_applied),
    )
    return explanation


def render_refactor_explanation(policy: ScoringPolicyLike) -> str:
    lines = [
        "# LeakCheck Scoring Refactor",
        "",
        "## What the old logic did",
        "- Mapped detector evidence into official CVSS v3.1 Base, Temporal, and Environmental metrics.",
        "- Emitted a full CVSS vector and used the Environmental score as the final `severity`.",
        "- Coupled LLM-specific evidence like similarity, refusal, and repeatability indirectly through CVSS fields.",
        "",
        "## What changed",
        f"- LeakCheck now uses the `{policy.score_version}` policy: a deterministic CVSS-aligned 0.0-10.0 severity model.",
        "- The final score is computed directly from LeakCheck evidence instead of pretending the finding is a software vulnerability.",
        "- `safe` verdicts now force severity to 0.0, which removes the previous safe-but-nonzero contradiction.",
        "- Confidence, similarity, response behavior, and repeatability are bounded modifiers rather than hidden proxies.",
        "",
        "## Current formula",
        "- Final score = clamp(category base + verdict modifier + rule bonuses + rule-hint bonuses + confidence bonus + similarity bonus + response-signal bonuses + repeatability bonus + refusal mitigation, verdict cap).",
        f"- Category bases: benign={policy.categories.get('benign', 0.0):.1f}, prompt_injection={policy.categories.get('prompt_injection', 0.0):.1f}, jailbreak={policy.categories.get('jailbreak', 0.0):.1f}, data_exfil={policy.categories.get('data_exfil', 0.0):.1f}.",
        f"- Verdict modifiers: attack_attempt={policy.verdicts['attack_attempt'].bonus:.1f} with cap {policy.verdicts['attack_attempt'].max_score:.1f}; attack_success={policy.verdicts['attack_success'].bonus:.1f} with cap {policy.verdicts['attack_success'].max_score:.1f}.",
        f"- Bounded evidence weights: rules<={policy.weights.rule_max:.1f}, rule hints<={policy.weights.rule_severity_hint_max:.1f}, confidence<={policy.weights.confidence_max:.1f}, similarity<={policy.weights.similarity_max:.1f}, response signals<={policy.weights.response_signal_max:.1f}, repeatability<={policy.weights.repeatability_max:.1f}.",
        f"- Refusal mitigation on attempts: {policy.weights.refusal_mitigation:.1f}.",
        "",
        "## Why the new design is better",
        "- It is deterministic, auditable, and directly tied to LeakCheck concepts instead of borrowed vulnerability semantics.",
        "- It keeps verdict, confidence, severity, and explanation separate.",
        "- All weights and thresholds live in one policy, making calibration and test coverage straightforward.",
        "- The scoring explanation is now part of the result contract, so reports and the dashboard can explain why a score was assigned.",
        "",
        "## Severity bands",
    ]
    for label, (lo, hi) in policy.bands.items():
        lines.append(f"- {label}: {lo:.1f} to {hi:.1f}")
    lines.extend(
        [
            "",
            "## Safe extension guidance",
            "- Add new rule or response-signal weights in the scoring policy instead of scattering thresholds across the UI or reports.",
            "- Keep modifiers bounded so confidence alone cannot create a high or critical severity.",
            "- Preserve the invariant that `attack_attempt` remains below `attack_success` for equivalent evidence.",
        ]
    )
    return "\n".join(lines)
