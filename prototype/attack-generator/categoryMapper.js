/**
 * Category Mapper
 * Maps real attack categories to our internal system categories
 */

/**
 * Map external category names to internal ones
 * @param {string} externalCategory - Category from prompt_injections.csv
 * @returns {string} Internal category name
 */
export function mapCategory(externalCategory) {
    const mapping = {
        // Instruction Override attacks → Prompt Injection
        'Instruction Override': 'promptInjection',

        // Jailbreak-style attacks → Jailbreak
        'Jailbreak': 'jailbreak',
        'Role-Playing': 'jailbreak',
        'Context Manipulation': 'jailbreak',
        'Psychological Manipulation': 'jailbreak',
        'Authority Role': 'jailbreak',

        // Data extraction/leakage → Data Leakage
        'Hijacking': 'promptInjection', // Often tries to extract prompts

        // Formatting/encoding tricks → Prompt Injection
        'Formatting Trick': 'promptInjection',
        'Multilingual': 'promptInjection',

        // Default fallback
        'default': 'promptInjection'
    };

    return mapping[externalCategory] || mapping.default;
}

/**
 * Determine severity from effectiveness and complexity
 * @param {string} effectiveness - Low/Medium/High
 * @param {string} complexity - Simple/Moderate/Complex
 * @returns {string} Severity level
 */
export function determineSeverity(effectiveness, complexity) {
    // High effectiveness = Critical/High severity
    if (effectiveness === 'High') {
        return complexity === 'Complex' ? 'Critical' : 'High';
    }

    // Medium effectiveness = High/Medium severity
    if (effectiveness === 'Medium') {
        return complexity === 'Complex' ? 'High' : 'Medium';
    }

    // Low effectiveness = Medium/Low severity
    return complexity === 'Complex' ? 'Medium' : 'Low';
}

/**
 * Get attack name from ID and subcategory
 * @param {string} id - Attack ID (e.g., "IO-001")
 * @param {string} subcategory - Attack subcategory
 * @returns {string} Human-readable name
 */
export function getAttackName(id, subcategory) {
    return `${id}: ${subcategory}`;
}
