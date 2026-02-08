/**
 * CSV Loader Module
 * Loads attack datasets from CSV files at server startup
 * Provides fast in-memory access to attack templates
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// ES module path resolution
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// In-memory cache of loaded datasets
let attackDatasets = {
    promptInjection: [],
    jailbreak: [],
    dataLeakage: []
};

/**
 * Parse CSV content into structured attack objects
 * @param {string} csvContent - Raw CSV file content
 * @returns {Array} Array of attack objects
 */
function parseCSV(csvContent) {
    const lines = csvContent.trim().split('\n');
    if (lines.length < 2) return []; // Empty or header-only

    const headers = lines[0].split(',').map(h => h.trim());
    const attacks = [];

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim()) continue; // Skip empty lines

        // Parse CSV line (handle quoted fields with commas)
        const values = parseCSVLine(line);

        if (values.length !== headers.length) {
            console.warn(`Skipping malformed CSV line ${i + 1}`);
            continue;
        }

        const attack = {};
        headers.forEach((header, index) => {
            attack[header] = values[index];
        });

        // Parse variables field into structured object
        if (attack.variables) {
            attack.parsedVariables = parseVariables(attack.variables);
        }

        attacks.push(attack);
    }

    return attacks;
}

/**
 * Parse a single CSV line, handling quoted fields
 * @param {string} line - CSV line
 * @returns {Array} Array of field values
 */
function parseCSVLine(line) {
    const values = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        const nextChar = line[i + 1];

        if (char === '"') {
            if (inQuotes && nextChar === '"') {
                // Escaped quote
                current += '"';
                i++; // Skip next quote
            } else {
                // Toggle quote state
                inQuotes = !inQuotes;
            }
        } else if (char === ',' && !inQuotes) {
            // Field separator
            values.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }

    // Add last field
    values.push(current.trim());

    return values;
}

/**
 * Parse variables string into structured object
 * Format: "var1:val1|val2|val3;var2:val1|val2"
 * @param {string} variablesStr - Variables string from CSV
 * @returns {Object} Structured variables object
 */
function parseVariables(variablesStr) {
    if (!variablesStr || variablesStr.trim() === '') return {};

    const variables = {};
    const varPairs = variablesStr.split(';');

    varPairs.forEach(pair => {
        const [varName, valuesStr] = pair.split(':');
        if (varName && valuesStr) {
            variables[varName.trim()] = valuesStr.split('|').map(v => v.trim());
        }
    });

    return variables;
}

/**
 * Load all CSV datasets from the datasets directory
 * Called once at server startup
 */
export async function loadDatasets() {
    const datasetsDir = path.join(__dirname, '../datasets');

    console.log('📂 Loading attack datasets from:', datasetsDir);

    try {
        // Load Template-Based Attacks (Original)
        loadTemplateAttacks(datasetsDir);

        // Load Real Attack Prompts (New - prompt_injections.csv)
        await loadRealAttacks(datasetsDir);

        const totalAttacks =
            attackDatasets.promptInjection.length +
            attackDatasets.jailbreak.length +
            attackDatasets.dataLeakage.length;

        console.log(`✅ Total attacks loaded: ${totalAttacks}\n`);

    } catch (error) {
        console.error('❌ Error loading datasets:', error);
    }
}

/**
 * Load template-based attacks (original CSV files)
 */
function loadTemplateAttacks(datasetsDir) {
    // Load Prompt Injection attacks
    const piPath = path.join(datasetsDir, 'prompt_injection_attacks.csv');
    if (fs.existsSync(piPath)) {
        const content = fs.readFileSync(piPath, 'utf-8');
        const parsed = parseCSV(content);
        attackDatasets.promptInjection.push(...parsed);
        console.log(`   ✅ Loaded ${parsed.length} template prompt injection attacks`);
    } else {
        console.warn(`   ⚠️ Missing: prompt_injection_attacks.csv`);
    }

    // Load Jailbreak attacks
    const jbPath = path.join(datasetsDir, 'jailbreak_attacks.csv');
    if (fs.existsSync(jbPath)) {
        const content = fs.readFileSync(jbPath, 'utf-8');
        const parsed = parseCSV(content);
        attackDatasets.jailbreak.push(...parsed);
        console.log(`   ✅ Loaded ${parsed.length} template jailbreak attacks`);
    } else {
        console.warn(`   ⚠️ Missing: jailbreak_attacks.csv`);
    }

    // Load Data Leakage attacks  
    const dlPath = path.join(datasetsDir, 'data_leakage_attacks.csv');
    if (fs.existsSync(dlPath)) {
        const content = fs.readFileSync(dlPath, 'utf-8');
        const parsed = parseCSV(content);
        attackDatasets.dataLeakage.push(...parsed);
        console.log(`   ✅ Loaded ${parsed.length} template data leakage attacks`);
    } else {
        console.warn(`   ⚠️ Missing: data_leakage_attacks.csv`);
    }
}

/**
 * Load real attack prompts from prompt_injections.csv
 */
async function loadRealAttacks(datasetsDir) {
    const realAttacksPath = path.join(datasetsDir, 'prompt_injections.csv');

    if (!fs.existsSync(realAttacksPath)) {
        console.warn(`   ⚠️ Missing: prompt_injections.csv`);
        return;
    }

    const content = fs.readFileSync(realAttacksPath, 'utf-8');
    const realAttacks = await parseRealAttackCSV(content);

    // Categorize and add to appropriate datasets
    for (const attack of realAttacks) {
        const internalCategory = attack.internalCategory;
        if (attackDatasets[internalCategory]) {
            attackDatasets[internalCategory].push(attack);
        }
    }

    console.log(`   ✅ Loaded ${realAttacks.length} real attack prompts`);
}

/**
 * Parse real attack CSV (different format than templates)
 * @param {string} csvContent - Raw CSV content
 * @returns {Array} Array of processed attack objects
 */
async function parseRealAttackCSV(csvContent) {
    // Import mapper functions
    const { mapCategory, determineSeverity, getAttackName } =
        await import('./categoryMapper.js');

    const lines = csvContent.trim().split('\n');
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const attacks = [];

    for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (!line.trim()) continue;

        const values = parseCSVLine(line);

        if (values.length !== headers.length) {
            continue; // Skip malformed lines
        }

        // Map to object
        const rawAttack = {};
        headers.forEach((header, index) => {
            rawAttack[header] = values[index];
        });

        // Transform to our internal format
        const attack = {
            // Original fields
            id: rawAttack.id,
            text: rawAttack.text,  // This is the full attack, NOT a template
            category: rawAttack.category,
            subcategory: rawAttack.subcategory,

            // Mapped fields for compatibility
            name: getAttackName(rawAttack.id, rawAttack.subcategory),
            severity: determineSeverity(rawAttack.effectiveness, rawAttack.complexity),
            internalCategory: mapCategory(rawAttack.category),

            // Metadata
            effectiveness: rawAttack.effectiveness,
            complexity: rawAttack.complexity,
            language: rawAttack.language,
            source: rawAttack.source,

            // Flag to differentiate from templates
            isRealAttack: true,
            template: rawAttack.text, // For mutation engine compatibility
            parsedVariables: {} // No variables in real attacks
        };

        attacks.push(attack);
    }

    return attacks;
}

/**
 * Get dataset for a specific category
 * @param {string} category - 'promptInjection', 'jailbreak', or 'dataLeakage'
 * @returns {Array} Array of attack templates
 */
export function getDataset(category) {
    return attackDatasets[category] || [];
}

/**
 * Get a random attack from a category
 * @param {string} category - Attack category
 * @returns {Object|null} Random attack template or null if category empty
 */
export function getRandomAttack(category) {
    const dataset = getDataset(category);
    if (dataset.length === 0) return null;

    const randomIndex = Math.floor(Math.random() * dataset.length);
    return dataset[randomIndex];
}

/**
 * Get dataset statistics
 * @returns {Object} Statistics about loaded datasets
 */
export function getStats() {
    return {
        promptInjection: attackDatasets.promptInjection.length,
        jailbreak: attackDatasets.jailbreak.length,
        dataLeakage: attackDatasets.dataLeakage.length,
        total: attackDatasets.promptInjection.length +
            attackDatasets.jailbreak.length +
            attackDatasets.dataLeakage.length
    };
}
