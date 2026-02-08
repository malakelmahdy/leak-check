/**
 * Mutation Engine
 * Applies transformations to attack templates
 * Provides simple mutations for Option A (no LLM required)
 */

/**
 * Mutation strategies
 */
const MUTATION_STRATEGIES = {
    // Level 1: Just variable substitution
    BASIC: 1,

    // Level 2: Variable substitution + case variations
    MODERATE: 2,

    // Level 3: Variable substitution + case + encoding
    ADVANCED: 3,

    // Level 4: All mutations + spacing variations
    AGGRESSIVE: 4,

    // Level 5: Maximum mutation (all techniques)
    MAXIMUM: 5
};

/**
 * Substitute variables in template with random values
 * @param {string} template - Template string with {placeholders}
 * @param {Object} variables - Variables object from CSV
 * @returns {string} String with variables replaced
 */
function substituteVariables(template, variables) {
    if (!variables || Object.keys(variables).length === 0) {
        return template;
    }

    let result = template;

    // Replace each variable with a random value from its options
    for (const [varName, values] of Object.entries(variables)) {
        if (values && values.length > 0) {
            const randomValue = values[Math.floor(Math.random() * values.length)];
            const placeholder = `{${varName}}`;

            // Replace all occurrences of this variable
            result = result.split(placeholder).join(randomValue);
        }
    }

    return result;
}

/**
 * Apply case variations to text
 * @param {string} text - Input text
 * @returns {string} Text with random case variation
 */
function applyCaseVariation(text) {
    const strategies = [
        // No change (50% chance)
        () => text,

        // Random word capitalization
        () => {
            return text.split(' ').map(word => {
                if (Math.random() > 0.5) {
                    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
                }
                return word.toLowerCase();
            }).join(' ');
        },

        // aLtErNaTiNg CaSe (for 30% of words)
        () => {
            return text.split('').map((char, i) => {
                if (Math.random() > 0.7) {
                    return i % 2 === 0 ? char.toLowerCase() : char.toUpperCase();
                }
                return char;
            }).join('');
        }
    ];

    const strategy = strategies[Math.floor(Math.random() * strategies.length)];
    return strategy();
}

/**
 * Apply spacing variations
 * @param {string} text - Input text
 * @returns {string} Text with spacing variations
 */
function applySpacingVariation(text) {
    const variations = [
        // No change (most common)
        () => text,

        // Add extra spaces randomly
        () => text.split(' ').map(word => {
            return Math.random() > 0.8 ? `  ${word}` : word;
        }).join(' '),

        // Add newlines at punctuation
        () => text.replace(/([.!?])\s/g, (match) => {
            return Math.random() > 0.7 ? match + '\n' : match;
        })
    ];

    const variation = variations[Math.floor(Math.random() * variations.length)];
    return variation();
}

/**
 * Apply simple encoding transformations
 * @param {string} text - Input text
 * @param {number} percentage - Percentage of text to encode (0-100)
 * @returns {string} Partially encoded text
 */
function applyEncoding(text, percentage = 30) {
    // URL encode random portions
    const words = text.split(' ');
    const numToEncode = Math.floor(words.length * (percentage / 100));

    // Pick random words to encode
    const indicesToEncode = new Set();
    while (indicesToEncode.size < numToEncode && indicesToEncode.size < words.length) {
        indicesToEncode.add(Math.floor(Math.random() * words.length));
    }

    return words.map((word, index) => {
        if (indicesToEncode.has(index)) {
            // URL encode this word
            return encodeURIComponent(word);
        }
        return word;
    }).join(' ');
}

/**
 * Add obfuscation characters
 * @param {string} text - Input text
 * @returns {string} Text with obfuscation
 */
function addObfuscation(text) {
    const techniques = [
        // No change (most common)
        () => text,

        // Add invisible zero-width characters
        () => {
            const zeroWidth = '\u200B'; // Zero-width space
            return text.split('').map(char => {
                return Math.random() > 0.9 ? char + zeroWidth : char;
            }).join('');
        },

        // Add homoglyphs (look-alike characters)
        () => {
            const homoglyphs = {
                'a': ['а', 'ɑ'],  // Cyrillic a, Latin alpha
                'e': ['е', 'ė'],  // Cyrillic e
                'o': ['о', 'ο'],  // Cyrillic o, Greek omicron
                'i': ['і', 'ı'],  // Cyrillic i, dotless i
            };

            return text.split('').map(char => {
                const lower = char.toLowerCase();
                if (homoglyphs[lower] && Math.random() > 0.85) {
                    const alternatives = homoglyphs[lower];
                    return alternatives[Math.floor(Math.random() * alternatives.length)];
                }
                return char;
            }).join('');
        }
    ];

    const technique = techniques[Math.floor(Math.random() * techniques.length)];
    return technique();
}

/**
 * Main mutation function
 * @param {Object} attack - Attack template from CSV
 * @param {number} mutationLevel - Mutation intensity (1-5)
 * @returns {Object} Mutated attack object
 */
export function mutateAttack(attack, mutationLevel = 2) {
    if (!attack || !attack.template) {
        return null;
    }

    // Start with variable substitution
    let mutatedText = substituteVariables(attack.template, attack.parsedVariables);

    // Apply additional mutations based on level
    if (mutationLevel >= MUTATION_STRATEGIES.MODERATE) {
        if (Math.random() > 0.5) {
            mutatedText = applyCaseVariation(mutatedText);
        }
    }

    if (mutationLevel >= MUTATION_STRATEGIES.ADVANCED) {
        if (Math.random() > 0.6) {
            mutatedText = applyEncoding(mutatedText, 20);
        }
    }

    if (mutationLevel >= MUTATION_STRATEGIES.AGGRESSIVE) {
        mutatedText = applySpacingVariation(mutatedText);
    }

    if (mutationLevel >= MUTATION_STRATEGIES.MAXIMUM) {
        if (Math.random() > 0.7) {
            mutatedText = addObfuscation(mutatedText);
        }
    }

    return {
        text: mutatedText,
        name: attack.name,
        category: attack.category,
        severity: attack.severity,
        mutationLevel: mutationLevel
    };
}

/**
 * Generate multiple variants of an attack
 * @param {Object} attack - Base attack template
 * @param {number} count - Number of variants to generate
 * @param {number} mutationLevel - Mutation intensity
 * @returns {Array} Array of mutated attacks
 */
export function generateVariants(attack, count = 3, mutationLevel = 2) {
    const variants = [];

    for (let i = 0; i < count; i++) {
        const mutated = mutateAttack(attack, mutationLevel);
        if (mutated) {
            variants.push(mutated);
        }
    }

    return variants;
}

/**
 * Get mutation level description
 * @param {number} level - Mutation level (1-5)
 * @returns {string} Human-readable description
 */
export function getMutationDescription(level) {
    const descriptions = {
        1: 'Basic - Variable substitution only',
        2: 'Moderate - Variables + case variations',
        3: 'Advanced - Variables + case + encoding',
        4: 'Aggressive - All techniques + spacing',
        5: 'Maximum - Full obfuscation arsenal'
    };

    return descriptions[level] || descriptions[2];
}

export { MUTATION_STRATEGIES };
