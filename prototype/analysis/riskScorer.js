// analysis/riskScorer.js

export function calculateRisk(findings) {
    // No leakage → minimal risk
    if (!findings || findings.length === 0) {
        return {
            score: 5,
            level: "Low",
            rationale: "No privacy leakage detected.",
        };
    }

    let score = 0;

    findings.forEach((f) => {
        if (f.severity === "Critical") score += 40;
        if (f.severity === "High") score += 30;
        if (f.severity === "Medium") score += 20;
        if (f.severity === "Low") score += 10;
    });

    score = Math.min(score, 100);

    let level = "Low";
    if (score > 75) level = "Critical";
    else if (score > 50) level = "High";
    else if (score > 25) level = "Medium";

    return {
        score,
        level,
        rationale: "Risk calculated based on detected leakage severity.",
    };
}
