// analysis/leakageDetector.js

export function detectLeakage(text) {
    const findings = [];

    const patterns = [
        {
            type: "Email Address",
            regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
            severity: "High",
        },
        {
            type: "Phone Number",
            regex: /\+?\d[\d\s\-()]{8,}\d/,
            severity: "Medium",
        },
        {
            type: "Credit Card Number",
            regex: /\b(?:\d[ -]*?){13,16}\b/,
            severity: "Critical",
        },
        {
            type: "API Key / Secret",
            regex: /(sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z\-_]{30,})/,
            severity: "Critical",
        },
        {
            type: "JWT Token",
            regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
            severity: "Critical",
        },
        {
            type: "Bearer Token",
            regex: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/i,
            severity: "Critical",
        },
        {
            type: "IBAN / Bank Account",
            regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/,
            severity: "Critical",
        },
        {
            type: "National ID Number",
            regex: /\b\d{9,12}\b/,
            severity: "High",
        },
        {
            type: "Passport Number",
            regex: /\b[A-Z]\d{7,8}\b/,
            severity: "High",
        },
        {
            type: "IP Address (IPv4)",
            regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
            severity: "Medium",
        },
        {
            type: "Date of Birth",
            regex: /\b(19|20)\d{2}[-/](0[1-9]|1[0-2])[-/](0[1-9]|[12]\d|3[01])\b/,
            severity: "Medium",
        },
        {
            type: "Physical Address (Basic)",
            regex: /\b\d{1,5}\s\w+(\s\w+)*\s(St|Street|Ave|Avenue|Rd|Road|Blvd|Lane)\b/i,
            severity: "Medium",
        },
        {
            type: "Sensitive Keyword",
            regex: /\b(password|secret|api[_-]?key|token|ssn|credential|private)\b/i,
            severity: "Low",
        },
    ];


    patterns.forEach((pattern) => {
        if (pattern.regex.test(text)) {
            findings.push({
                type: pattern.type,
                severity: pattern.severity,
                description: `${pattern.type} detected in model response.`,
            });
        }
    });

    return findings;
}
