// DOM Elements
const attackTypeSelect = document.getElementById('attackType');
const generateBtn = document.getElementById('generateBtn');
const generatedAttackDiv = document.getElementById('generatedAttack');
const attackNameEl = document.getElementById('attackName');
const attackCategoryEl = document.getElementById('attackCategory');
const attackSeverityEl = document.getElementById('attackSeverity');
const attackTextArea = document.getElementById('attackText');
const actionButtonsDiv = document.getElementById('actionButtons');
const copyBtn = document.getElementById('copyBtn');
const testBtn = document.getElementById('testBtn');
const attackLogDiv = document.getElementById('attackLog');

// Attack history
let attackHistory = [];

// Mutation level (default: 2 - Moderate)
let mutationLevel = 2;

// Generate Attack using new CSV-based API
generateBtn.addEventListener('click', async () => {
    const attackType = attackTypeSelect.value;

    // Show loading state
    generateBtn.textContent = '⏳ Generating...';
    generateBtn.disabled = true;

    try {
        const response = await fetch('http://localhost:3000/generate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                category: attackType,
                mutationLevel: mutationLevel
            })
        });

        if (!response.ok) {
            throw new Error('Failed to generate attack');
        }

        const data = await response.json();
        const attack = data.attack;

        if (!attack) {
            alert('Failed to generate attack');
            return;
        }

        // Display the attack
        displayAttack(attack);

        // Add to history
        addToHistory(attack);

    } catch (error) {
        console.error('Error generating attack:', error);
        alert('Failed to generate attack. Make sure the server is running.');
    } finally {
        // Reset button
        generateBtn.textContent = '🎲 Generate Random Attack';
        generateBtn.disabled = false;
    }
});


// Mutation Level Slider Handler
const mutationLevelSlider = document.getElementById('mutationLevel');
const mutationLevelLabel = document.getElementById('mutationLevelLabel');

const mutationLevelNames = {
    1: 'Basic',
    2: 'Moderate',
    3: 'Advanced',
    4: 'Aggressive',
    5: 'Maximum'
};

// Only add event listener if slider exists
if (mutationLevelSlider && mutationLevelLabel) {
    mutationLevelSlider.addEventListener('input', (e) => {
        mutationLevel = parseInt(e.target.value);
        mutationLevelLabel.textContent = `${mutationLevelNames[mutationLevel]} (${mutationLevel})`;
    });
} else {
    console.warn('Mutation level slider not found in DOM');
}


function displayAttack(attack) {
    attackNameEl.textContent = attack.name;
    attackCategoryEl.textContent = attack.category;
    attackCategoryEl.className = 'badge badge-' + getCategoryClass(attack.category);

    attackSeverityEl.textContent = attack.severity;
    attackSeverityEl.style.background = getSeverityColor(attack.severity);
    attackSeverityEl.className = 'badge';

    attackTextArea.value = attack.text;

    generatedAttackDiv.style.display = 'block';
    actionButtonsDiv.style.display = 'flex';
}

function getCategoryClass(category) {
    if (category.includes('Injection')) return 'injection';
    if (category.includes('Jailbreak')) return 'jailbreak';
    if (category.includes('Leakage')) return 'leakage';
    return 'leakage';
}

function getSeverityColor(severity) {
    switch (severity) {
        case 'Critical': return 'rgba(244, 67, 54, 0.2)';
        case 'High': return 'rgba(255, 152, 0, 0.2)';
        case 'Medium': return 'rgba(255, 193, 7, 0.2)';
        default: return 'rgba(69, 162, 158, 0.2)';
    }
}

function addToHistory(attack) {
    const timestamp = new Date().toLocaleTimeString();
    attackHistory.unshift({ ...attack, timestamp });

    // Update log display
    if (attackHistory.length === 1) {
        attackLogDiv.innerHTML = '';
    }

    const logEntry = document.createElement('div');
    logEntry.style.cssText = 'padding: 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); margin-bottom: 0.5rem;';
    logEntry.innerHTML = `
        <div style="display: flex; justify-content: space-between; margin-bottom: 0.5rem;">
            <strong style="color: #66fcf1;">${attack.name}</strong>
            <span style="color: #888; font-size: 0.85rem;">${timestamp}</span>
        </div>
        <div style="color: #c5c6c7; font-size: 0.9rem; font-family: 'Courier New', monospace; opacity: 0.8;">
            ${attack.text.substring(0, 100)}${attack.text.length > 100 ? '...' : ''}
        </div>
    `;

    attackLogDiv.insertBefore(logEntry, attackLogDiv.firstChild);

    // Keep only last 10
    if (attackHistory.length > 10) {
        attackHistory = attackHistory.slice(0, 10);
        if (attackLogDiv.children.length > 10) {
            attackLogDiv.removeChild(attackLogDiv.lastChild);
        }
    }
}

// Copy to Clipboard
copyBtn.addEventListener('click', () => {
    attackTextArea.select();
    document.execCommand('copy');

    const originalText = copyBtn.textContent;
    copyBtn.textContent = '✅ Copied!';
    copyBtn.style.background = '#45a29e';

    setTimeout(() => {
        copyBtn.textContent = originalText;
        copyBtn.style.background = '#45a29e';
    }, 2000);
});

// Test in Chat
testBtn.addEventListener('click', () => {
    // Store attack in sessionStorage
    sessionStorage.setItem('testAttack', attackTextArea.value);

    // Redirect to chat
    window.location.href = 'chat.html?test=true';
});
