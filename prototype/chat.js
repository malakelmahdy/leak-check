const chatBox = document.querySelector(".chat-box");
const inputField = document.querySelector("#user-input");
const sendButton = document.querySelector("#send-btn");
let currentSessionId = null;

// =====================
// Chat Message Helpers
// =====================
function clearChat() {
    chatBox.innerHTML = '';
}

function addMessage(message, sender) {
    const msgDiv = document.createElement("div");
    msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
    msgDiv.textContent = message;
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function typeMessage(text, sender) {
    const msgDiv = document.createElement("div");
    msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
    chatBox.appendChild(msgDiv);

    let index = 0;
    const typingSpeed = 30;

    const typeInterval = setInterval(() => {
        msgDiv.textContent += text.charAt(index);
        index++;
        chatBox.scrollTop = chatBox.scrollHeight;
        if (index === text.length) clearInterval(typeInterval);
    }, typingSpeed);
}

// =====================
// Main Chat Logic
// =====================
async function simulateBotResponse(userMessage) {
    const selectedModel = document.getElementById("modelSelect").value;

    // Typing indicator
    const botTyping = document.createElement("div");
    botTyping.classList.add("bot-message", "typing");
    botTyping.textContent = "•••";
    chatBox.appendChild(botTyping);
    chatBox.scrollTop = chatBox.scrollHeight;


    try {
        // Get user from local storage
        const userStr = localStorage.getItem("user");
        const user = userStr ? JSON.parse(userStr) : null;

        // Get selected model
        const modelSelect = document.getElementById("modelSelect");
        const selectedModel = modelSelect ? modelSelect.value : "gemini";

        const payload = {
            message: userMessage,
            userId: user ? user.user_id : null,
            sessionId: currentSessionId, // Send current session ID
            model: selectedModel // Send selected model
        };


        const res = await fetch("http://localhost:3000/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        const data = await res.json();
        botTyping.remove();

        // 🔴 Backend / API error handling
        if (data.error) {
            typeMessage("⚠️ " + data.error, "bot");
            return;
        }

        // Update Session ID if created/changed
        if (data.sessionId && data.sessionId !== currentSessionId) {
            currentSessionId = data.sessionId;
            loadSessionList(); // Refresh sidebar to show new chat
        }

        // Normal response
        typeMessage(data.reply, "bot");

        // ✅ Update report ONLY if backend analysis exists
        if (data.findings && data.risk) {
            updateLeakageReport(data.findings, data.risk);
        }
    } catch (error) {
        botTyping.remove();
        typeMessage("⚠️ Gemini API error: " + error.message, "bot");
    }
}

// =====================
// Session Management
// =====================
async function loadSessionList() {
    const userStr = localStorage.getItem("user");
    if (!userStr) return;
    const user = JSON.parse(userStr);
    const listContainer = document.getElementById("session-list");

    try {
        const res = await fetch(`http://localhost:3000/sessions/${user.user_id}`);
        const sessions = await res.json();

        listContainer.innerHTML = ""; // Clear list

        if (sessions.length === 0) {
            listContainer.innerHTML = "<div style='padding:1rem; opacity:0.6; font-size:0.8rem'>No chats yet</div>";
            return;
        }

        sessions.forEach(session => {
            const item = document.createElement("div");
            item.className = `session-item ${session.id === currentSessionId ? 'active' : ''}`;
            item.textContent = session.title || "Untitled Chat";
            item.onclick = () => loadSession(session.id);
            listContainer.appendChild(item);
        });

    } catch (error) {
        console.error("Failed to load sessions:", error);
    }
}

async function loadSession(sessionId) {
    const userStr = localStorage.getItem("user");
    if (!userStr) return;
    const user = JSON.parse(userStr);

    currentSessionId = sessionId;
    clearChat();
    // Update active state in sidebar
    loadSessionList();
    addMessage("Loading conversation...", "bot");

    try {
        const res = await fetch(`http://localhost:3000/history/${user.user_id}/${sessionId}`);
        const history = await res.json();

        clearChat(); // Clear "Loading..."

        if (history.length === 0) {
            addMessage("Start chatting!", "bot");
        }

        history.forEach(msg => {
            const sender = msg.role === "user" ? "user" : "bot";
            addMessage(msg.content, sender);

            if (msg.findings && msg.risk) {
                updateLeakageReport(msg.findings, msg.risk);
            }
        });

    } catch (error) {
        console.error("Failed to load session history:", error);
    }
}

function startNewChat() {
    currentSessionId = null;
    clearChat();
    addMessage("👋 Hi there! I’m LeakCheck’s AI test bot. Start a new chat!", "bot");
    loadSessionList(); // Remove active class from others
}

// Initialize
document.addEventListener("DOMContentLoaded", () => {
    loadSessionList();

    // Wire up New Chat button
    const newChatBtn = document.getElementById("new-chat-btn");
    if (newChatBtn) {
        newChatBtn.addEventListener("click", startNewChat);
    }
});

// =====================
// Leakage Risk Report (DISPLAY ONLY)
// =====================
function updateLeakageReport(findings, risk) {
    // 🛑 Defensive guard (prevents ALL crashes)
    if (!risk || typeof risk.score !== "number") {
        console.error("❌ Invalid or missing risk object:", risk);
        return;
    }

    const reportDetails = document.getElementById("report-details");
    const riskScoreEl = document.getElementById("risk-score");
    const riskLevelEl = document.getElementById("risk-level");

    // No threats case
    if (!findings || findings.length === 0) {
        reportDetails.innerHTML = `<p>✅ No security threats detected.</p>`;
        riskScoreEl.textContent = `${risk.score} / 100`;
        riskLevelEl.textContent = risk.level;
        updateGauge(risk.score, risk.level);
        return;
    }

    // Categorize findings
    const categories = {
        leakage: findings.filter(f => !f.category || !["injection", "manipulation", "extraction", "obfuscation", "dan", "roleplay", "bypass", "hypothetical", "harmful", "jailbreak_success"].includes(f.category)),
        injection: findings.filter(f => ["injection", "manipulation", "extraction", "obfuscation"].includes(f.category)),
        jailbreak: findings.filter(f => ["dan", "roleplay", "bypass", "hypothetical", "harmful", "jailbreak_success"].includes(f.category))
    };

    // Build categorized HTML
    let findingsHtml = "";

    if (categories.leakage.length > 0) {
        findingsHtml += `<div class="threat-category"><span class="badge badge-leakage">🔓 DATA LEAKAGE</span>`;
        findingsHtml += `<ul>${categories.leakage.map(f => `<li><strong>${f.type}</strong> — ${f.severity}</li>`).join("")}</ul></div>`;
    }

    if (categories.injection.length > 0) {
        findingsHtml += `<div class="threat-category"><span class="badge badge-injection">⚠️ PROMPT INJECTION</span>`;
        findingsHtml += `<ul>${categories.injection.map(f => `<li><strong>${f.type}</strong> — ${f.severity}</li>`).join("")}</ul></div>`;
    }

    if (categories.jailbreak.length > 0) {
        findingsHtml += `<div class="threat-category"><span class="badge badge-jailbreak">🚨 JAILBREAK ATTEMPT</span>`;
        findingsHtml += `<ul>${categories.jailbreak.map(f => `<li><strong>${f.type}</strong> — ${f.severity}</li>`).join("")}</ul></div>`;
    }

    reportDetails.innerHTML = `
        ${findingsHtml}
        <p><strong>Recommendation:</strong> ${risk.rationale}</p>
    `;

    // Display backend-calculated risk
    riskScoreEl.textContent = `${risk.score} / 100`;
    riskLevelEl.textContent = risk.level;

    updateGauge(risk.score, risk.level);
}


// =====================
// Gauge Animation
// =====================
function updateGauge(score, level) {
    const gaugeCircle = document.querySelector(".gauge-progress");
    const gaugeText = document.querySelector(".gauge-text");
    const circumference = 314;

    const offset = circumference - (score / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;

    let color = "#45a29e";
    if (level === "Medium") color = "#f1c40f";
    if (level === "High") color = "#e67e22";
    if (level === "Critical") color = "#e74c3c";

    gaugeCircle.style.stroke = color;
    gaugeText.style.fill = color;

    let current = 0;
    const interval = setInterval(() => {
        gaugeText.textContent = `${current}%`;
        current++;
        if (current >= score) clearInterval(interval);
    }, 15);
}

// =====================
// Download Report
// =====================
document.getElementById("download-report").addEventListener("click", () => {
    const reportText = `
LeakCheck Leakage Risk Report
-----------------------------
Risk Score: ${document.getElementById("risk-score").textContent}
Severity: ${document.getElementById("risk-level").textContent}

Details:
${document.getElementById("report-details").innerText}
`;

    const blob = new Blob([reportText], { type: "text/plain" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "LeakCheck_Report.txt";
    link.click();
});

// =====================
// Send Message Handlers
// =====================
sendButton.addEventListener("click", () => {
    const userMessage = inputField.value.trim();
    if (!userMessage) return;

    addMessage(userMessage, "user");
    inputField.value = "";
    simulateBotResponse(userMessage);
});

inputField.addEventListener("keypress", (e) => {
    if (e.key === "Enter") {
        sendButton.click();
    }
});

// const chatBox = document.querySelector(".chat-box");
// const inputField = document.querySelector("#user-input");
// const sendButton = document.querySelector("#send-btn");

// // =====================
// // Chat Message Helpers
// // =====================
// function addMessage(message, sender) {
//     const msgDiv = document.createElement("div");
//     msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//     msgDiv.textContent = message;
//     chatBox.appendChild(msgDiv);
//     chatBox.scrollTop = chatBox.scrollHeight;
// }

// function typeMessage(text, sender) {
//     const msgDiv = document.createElement("div");
//     msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//     chatBox.appendChild(msgDiv);

//     let index = 0;
//     const typingSpeed = 30;

//     const typeInterval = setInterval(() => {
//         msgDiv.textContent += text.charAt(index);
//         index++;
//         chatBox.scrollTop = chatBox.scrollHeight;
//         if (index === text.length) clearInterval(typeInterval);
//     }, typingSpeed);
// }

// // =====================
// // Main Chat Logic
// // =====================
// async function simulateBotResponse(userMessage) {
//     const selectedModel = document.getElementById("modelSelect").value;

//     // Typing indicator
//     const botTyping = document.createElement("div");
//     botTyping.classList.add("bot-message", "typing");
//     botTyping.textContent = "•••";
//     chatBox.appendChild(botTyping);
//     chatBox.scrollTop = chatBox.scrollHeight;

//     if (selectedModel === "gemini") {
//         try {
//             const res = await fetch("http://localhost:3000/chat", {
//                 method: "POST",
//                 headers: { "Content-Type": "application/json" },
//                 body: JSON.stringify({ message: userMessage }),
//             });

//             const data = await res.json();
//             botTyping.remove();

//             typeMessage(data.reply, "bot");

//             // 🔍 Update Leakage Risk Report with BACKEND results
//             updateLeakageReport(data.findings, data.risk);
//         } catch (error) {
//             botTyping.remove();
//             typeMessage("⚠️ Gemini API error: " + error.message, "bot");
//         }
//     } else {
//         botTyping.remove();
//         typeMessage("This is a placeholder response for non-Gemini models.", "bot");
//     }
// }

// // =====================
// // Leakage Risk Report (DISPLAY ONLY)
// // =====================
// function updateLeakageReport(findings, risk) {
//     const reportDetails = document.getElementById("report-details");
//     const riskScoreEl = document.getElementById("risk-score");
//     const riskLevelEl = document.getElementById("risk-level");

//     // No leakage
//     if (!findings || findings.length === 0) {
//         reportDetails.innerHTML = `<p>✅ No privacy leakage detected.</p>`;
//         riskScoreEl.textContent = `${risk.score} / 100`;
//         riskLevelEl.textContent = risk.level;
//         updateGauge(risk.score, risk.level);
//         return;
//     }

//     // Display findings
//     const findingsHtml = findings.map((f) => `<li><strong>${f.type}</strong> — Severity: ${f.severity}</li>`).join("");

//     reportDetails.innerHTML = `
//         <ul>${findingsHtml}</ul>
//         <p><strong>Recommendation:</strong> Review prompts and apply output filtering.</p>
//     `;

//     // Display backend-calculated risk
//     riskScoreEl.textContent = `${risk.score} / 100`;
//     riskLevelEl.textContent = risk.level;

//     updateGauge(risk.score, risk.level);
// }

// // =====================
// // Gauge Animation
// // =====================
// function updateGauge(score, level) {
//     const gaugeCircle = document.querySelector(".gauge-progress");
//     const gaugeText = document.querySelector(".gauge-text");
//     const circumference = 314;

//     const offset = circumference - (score / 100) * circumference;
//     gaugeCircle.style.strokeDashoffset = offset;

//     let color = "#45a29e";
//     if (level === "Medium") color = "#f1c40f";
//     if (level === "High") color = "#e67e22";
//     if (level === "Critical") color = "#e74c3c";

//     gaugeCircle.style.stroke = color;
//     gaugeText.style.fill = color;

//     let current = 0;
//     const interval = setInterval(() => {
//         gaugeText.textContent = `${current}%`;
//         current++;
//         if (current >= score) clearInterval(interval);
//     }, 15);
// }

// // =====================
// // Download Report
// // =====================
// document.getElementById("download-report").addEventListener("click", () => {
//     const reportText = `
// LeakCheck Leakage Risk Report
// -----------------------------
// Risk Score: ${document.getElementById("risk-score").textContent}
// Severity: ${document.getElementById("risk-level").textContent}

// Details:
// ${document.getElementById("report-details").innerText}
// `;

//     const blob = new Blob([reportText], { type: "text/plain" });
//     const link = document.createElement("a");
//     link.href = URL.createObjectURL(blob);
//     link.download = "LeakCheck_Report.txt";
//     link.click();
// });

// // =====================
// // Send Message Handlers
// // =====================
// sendButton.addEventListener("click", () => {
//     const userMessage = inputField.value.trim();
//     if (!userMessage) return;

//     addMessage(userMessage, "user");
//     inputField.value = "";
//     simulateBotResponse(userMessage);
// });

// inputField.addEventListener("keypress", (e) => {
//     if (e.key === "Enter") {
//         sendButton.click();
//     }
// });

// const chatBox = document.querySelector(".chat-box");
// const inputField = document.querySelector("#user-input");
// const sendButton = document.querySelector("#send-btn");

// // =====================
// // Chat Message Helpers
// // =====================
// function addMessage(message, sender) {
//     const msgDiv = document.createElement("div");
//     msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//     msgDiv.textContent = message;
//     chatBox.appendChild(msgDiv);
//     chatBox.scrollTop = chatBox.scrollHeight;
// }

// function typeMessage(text, sender) {
//     const msgDiv = document.createElement("div");
//     msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//     chatBox.appendChild(msgDiv);

//     let index = 0;
//     const typingSpeed = 30;

//     const typeInterval = setInterval(() => {
//         msgDiv.textContent += text.charAt(index);
//         index++;
//         chatBox.scrollTop = chatBox.scrollHeight;
//         if (index === text.length) clearInterval(typeInterval);
//     }, typingSpeed);
// }

// // =====================
// // Main Chat Logic
// // =====================
// async function simulateBotResponse(userMessage) {
//     const selectedModel = document.getElementById("modelSelect").value;

//     // Typing indicator
//     const botTyping = document.createElement("div");
//     botTyping.classList.add("bot-message", "typing");
//     botTyping.textContent = "•••";
//     chatBox.appendChild(botTyping);
//     chatBox.scrollTop = chatBox.scrollHeight;

//     if (selectedModel === "gemini") {
//         try {
//             const res = await fetch("http://localhost:3000/chat", {
//                 method: "POST",
//                 headers: { "Content-Type": "application/json" },
//                 body: JSON.stringify({ message: userMessage }),
//             });

//             const data = await res.json();
//             botTyping.remove();

//             typeMessage(data.reply, "bot");

//             // 🔍 Update Leakage Risk Report with REAL findings
//             updateLeakageReport(data.findings);
//         } catch (error) {
//             botTyping.remove();
//             typeMessage("⚠️ Gemini API error: " + error.message, "bot");
//         }
//     } else {
//         botTyping.remove();
//         typeMessage("This is a placeholder response for non-Gemini models.", "bot");
//     }
// }

// // =====================
// // Leakage Risk Report
// // =====================
// function updateLeakageReport(findings) {
//     const reportDetails = document.getElementById("report-details");
//     const riskScoreEl = document.getElementById("risk-score");
//     const riskLevelEl = document.getElementById("risk-level");

//     // No leakage
//     if (!findings || findings.length === 0) {
//         reportDetails.innerHTML = `<p>✅ No privacy leakage detected.</p>`;
//         riskScoreEl.textContent = "5 / 100";
//         riskLevelEl.textContent = "Low";
//         updateGauge(5, "Low");
//         return;
//     }

//     // Display findings
//     const findingsHtml = findings.map((f) => `<li><strong>${f.type}</strong> — Severity: ${f.severity}</li>`).join("");

//     reportDetails.innerHTML = `
//     <ul>${findingsHtml}</ul>
//     <p><strong>Recommendation:</strong> Review prompts and apply output filtering.</p>
//   `;

//     // Deterministic risk scoring
//     let score = 0;
//     findings.forEach((f) => {
//         if (f.severity === "Critical") score += 40;
//         if (f.severity === "High") score += 30;
//         if (f.severity === "Medium") score += 20;
//         if (f.severity === "Low") score += 10;
//     });

//     score = Math.min(score, 100);

//     let level = "Low";
//     if (score > 75) level = "Critical";
//     else if (score > 50) level = "High";
//     else if (score > 25) level = "Medium";

//     riskScoreEl.textContent = `${score} / 100`;
//     riskLevelEl.textContent = level;

//     updateGauge(score, level);
// }

// // =====================
// // Gauge Animation
// // =====================
// function updateGauge(score, level) {
//     const gaugeCircle = document.querySelector(".gauge-progress");
//     const gaugeText = document.querySelector(".gauge-text");
//     const circumference = 314;

//     const offset = circumference - (score / 100) * circumference;
//     gaugeCircle.style.strokeDashoffset = offset;

//     let color = "#45a29e";
//     if (level === "Medium") color = "#f1c40f";
//     if (level === "High") color = "#e67e22";
//     if (level === "Critical") color = "#e74c3c";

//     gaugeCircle.style.stroke = color;
//     gaugeText.style.fill = color;

//     let current = 0;
//     const interval = setInterval(() => {
//         gaugeText.textContent = `${current}%`;
//         current++;
//         if (current >= score) clearInterval(interval);
//     }, 15);
// }

// // =====================
// // Download Report
// // =====================
// document.getElementById("download-report").addEventListener("click", () => {
//     const reportText = `
// LeakCheck Leakage Risk Report
// -----------------------------
// Risk Score: ${document.getElementById("risk-score").textContent}
// Severity: ${document.getElementById("risk-level").textContent}

// Details:
// ${document.getElementById("report-details").innerText}
// `;

//     const blob = new Blob([reportText], { type: "text/plain" });
//     const link = document.createElement("a");
//     link.href = URL.createObjectURL(blob);
//     link.download = "LeakCheck_Report.txt";
//     link.click();
// });

// // =====================
// // Send Message Handlers
// // =====================
// sendButton.addEventListener("click", () => {
//     const userMessage = inputField.value.trim();
//     if (!userMessage) return;

//     addMessage(userMessage, "user");
//     inputField.value = "";
//     simulateBotResponse(userMessage);
// });

// inputField.addEventListener("keypress", (e) => {
//     if (e.key === "Enter") {
//         sendButton.click();
//     }
// });
