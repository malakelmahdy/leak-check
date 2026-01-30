const chatBox = document.querySelector(".chat-box");
const inputField = document.querySelector("#user-input");
const sendButton = document.querySelector("#send-btn");
const modelSelector = document.getElementById("modelSelect");
const reportSection = document.getElementById("report-section");

// API Key Management UI
const apiKeyModal = document.createElement("div");
apiKeyModal.innerHTML = `
    <div id="apiKeyModal" style="display:none; position:fixed; top:50%; left:50%; transform:translate(-50%,-50%); 
        background:#1f2833; padding:2rem; border-radius:12px; z-index:2000; box-shadow:0 0 30px rgba(0,0,0,0.8);">
        <h3 style="color:#66fcf1; margin-bottom:1rem;">Configure API Keys</h3>
        <div style="margin-bottom:1rem;">
            <label style="color:#c5c6c7;">OpenAI Key:</label>
            <input type="password" id="openaiKey" style="width:100%; padding:0.5rem; margin-top:0.5rem; 
                background:#0b0c10; border:1px solid #45a29e; color:#fff; border-radius:6px;">
        </div>
        <div style="margin-bottom:1rem;">
            <label style="color:#c5c6c7;">Anthropic Key:</label>
            <input type="password" id="anthropicKey" style="width:100%; padding:0.5rem; margin-top:0.5rem; 
                background:#0b0c10; border:1px solid #45a29e; color:#fff; border-radius:6px;">
        </div>
        <button onclick="saveApiKeys()" style="background:#66fcf1; color:#0b0c10; padding:0.5rem 1rem; 
            border:none; border-radius:6px; cursor:pointer; margin-right:0.5rem;">Save</button>
        <button onclick="closeApiKeyModal()" style="background:#e74c3c; color:#fff; padding:0.5rem 1rem; 
            border:none; border-radius:6px; cursor:pointer;">Cancel</button>
    </div>
    <div id="modalOverlay" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; 
        background:rgba(0,0,0,0.7); z-index:1999;"></div>
`;
document.body.appendChild(apiKeyModal);

// Load keys from localStorage
let apiKeys = JSON.parse(localStorage.getItem("leakcheck_keys") || "{}");
let currentProvider = "gemini";
let currentModel = "models/gemini-2.5-flash";

// Provider configuration (from /providers endpoint)
let providers = {
    gemini: { name: "Google Gemini", requiresKey: false, models: ["models/gemini-2.5-flash"] },
    openai: { name: "OpenAI", requiresKey: true, models: ["gpt-3.5-turbo", "gpt-4"] },
    anthropic: { name: "Anthropic", requiresKey: true, models: ["claude-3-5-sonnet-20241022"] },
};

// Initialize
async function initializeApp() {
    await loadProviders();
    loadApiKeys();
    setupModelSelector();
}

async function loadProviders() {
    try {
        const res = await fetch("http://localhost:3000/providers");
        const data = await res.json();
        providers = data.providers.reduce((acc, p) => {
            acc[p.id] = p;
            return acc;
        }, {});
    } catch (error) {
        console.error("Failed to load providers:", error);
    }
}

function loadApiKeys() {
    // Load saved keys
    document.getElementById("openaiKey").value = apiKeys.openai || "";
    document.getElementById("anthropicKey").value = apiKeys.anthropic || "";
}

function saveApiKeys() {
    apiKeys = {
        openai: document.getElementById("openaiKey").value.trim(),
        anthropic: document.getElementById("anthropicKey").value.trim(),
    };
    localStorage.setItem("leakcheck_keys", JSON.stringify(apiKeys));
    closeApiKeyModal();
    alert("API keys saved securely in browser!");
}

function openApiKeyModal() {
    document.getElementById("apiKeyModal").style.display = "block";
    document.getElementById("modalOverlay").style.display = "block";
}

function closeApiKeyModal() {
    document.getElementById("apiKeyModal").style.display = "none";
    document.getElementById("modalOverlay").style.display = "none";
}

function setupModelSelector() {
    // Update model options when provider changes
    modelSelector.addEventListener("change", (e) => {
        const selected = e.target.value.split(":");
        currentProvider = selected[0];
        currentModel = selected[1];

        // Show/hide API key indicator
        updateApiKeyIndicator();
    });

    updateApiKeyIndicator();
}

function updateApiKeyIndicator() {
    const provider = providers[currentProvider];
    const hasKey = !provider?.requiresKey || (apiKeys[currentProvider] && apiKeys[currentProvider].length > 0);

    // Add key indicator to UI
    let indicator = document.getElementById("keyIndicator");
    if (!indicator) {
        indicator = document.createElement("span");
        indicator.id = "keyIndicator";
        indicator.style.cssText = "margin-left:1rem; font-size:0.85rem; cursor:pointer;";
        document.querySelector(".chat-header").appendChild(indicator);
    }

    indicator.innerHTML = hasKey ? `✅ ${provider.name} Ready` : `❌ ${provider.name} API Key Needed`;
    indicator.onclick = provider.requiresKey ? openApiKeyModal : null;
}

function addMessage(message, sender) {
    const msgDiv = document.createElement("div");
    msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
    msgDiv.textContent = message;
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function generateReport(analysis) {
    const riskScore = analysis.riskScore || 0;
    const severity = analysis.severity || "Low";
    const detectedTypes = analysis.detectedTypes || [];

    document.getElementById("risk-score").textContent = `${riskScore}/100`;
    document.getElementById("risk-level").textContent = severity;

    const detailsHtml = `
        <ul>
            ${detectedTypes.length > 0 ? detectedTypes.map((type) => `<li>⚠️ Potential ${type.replace("_", " ")} detected</li>`).join("") : "<li>✅ No sensitive data leaked</li>"}
        </ul>
        <p><strong>Provider:</strong> ${providers[currentProvider]?.name || currentProvider}</p>
        <p><strong>Model:</strong> ${analysis.model || currentModel}</p>
        <p><strong>Recommendations:</strong> ${detectedTypes.length > 0 ? "Review model prompts and implement stricter filters" : "No immediate action required"}</p>
    `;

    document.getElementById("report-details").innerHTML = detailsHtml;

    // Animate gauge
    const gaugeCircle = document.querySelector(".gauge-progress");
    const gaugeText = document.querySelector(".gauge-text");
    const circumference = 314;
    const offset = circumference - (riskScore / 100) * circumference;
    gaugeCircle.style.strokeDashoffset = offset;

    const color = severity === "High" ? "#e74c3c" : severity === "Medium" ? "#f1c40f" : "#45a29e";
    gaugeCircle.style.stroke = color;
    gaugeText.style.fill = color;

    let current = 0;
    const interval = setInterval(() => {
        current++;
        gaugeText.textContent = `${current}%`;
        if (current >= riskScore) clearInterval(interval);
    }, 15);

    reportSection.style.display = "block";
}

async function sendMessage(userMessage) {
    const botTyping = document.createElement("div");
    botTyping.classList.add("bot-message", "typing");
    botTyping.textContent = "•••";
    chatBox.appendChild(botTyping);
    chatBox.scrollTop = chatBox.scrollHeight;

    // Check for API key if required
    const provider = providers[currentProvider];
    if (provider?.requiresKey && !apiKeys[currentProvider]) {
        botTyping.remove();
        addMessage(`⚠️ API key required for ${provider.name}. Click the key indicator above to configure.`, "bot");
        return;
    }

    try {
        const res = await fetch("http://localhost:3000/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: userMessage,
                provider: currentProvider,
                apiKey: apiKeys[currentProvider] || null,
                model: currentModel,
            }),
        });

        const data = await res.json();
        botTyping.remove();

        if (data.error) {
            addMessage(`⚠️ Error: ${data.error}`, "bot");
        } else {
            addMessage(data.reply, "bot");
            generateReport({
                riskScore: data.riskScore,
                severity: data.severity,
                detectedTypes: data.detectedTypes,
                model: data.model,
            });
        }
    } catch (error) {
        botTyping.remove();
        addMessage(`⚠️ Network error: ${error.message}`, "bot");
    }
}

// Event Listeners
sendButton.addEventListener("click", () => {
    const userMessage = inputField.value.trim();
    if (!userMessage) return;

    addMessage(userMessage, "user");
    inputField.value = "";
    sendMessage(userMessage);
});

inputField.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendButton.click();
});

// Initialize on load
initializeApp();

// const chatBox = document.querySelector(".chat-box");
// const inputField = document.querySelector("#user-input");
// const sendButton = document.querySelector("#send-btn");
// const modelSelector = document.querySelector("#model-select");

// function addMessage(message, sender) {
//   const msgDiv = document.createElement("div");
//   msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//   msgDiv.textContent = message;
//   chatBox.appendChild(msgDiv);
//   chatBox.scrollTop = chatBox.scrollHeight;
// }

// // Simulated bot typing animation
// // function simulateBotResponse(userMessage) {
// //   const botTyping = document.createElement("div");
// //   botTyping.classList.add("bot-message");
// //   botTyping.textContent = "•••"; // typing dots
// //   botTyping.classList.add("typing");
// //   chatBox.appendChild(botTyping);
// //   chatBox.scrollTop = chatBox.scrollHeight;

// //   // Simulate delay based on message length
// //   const delay = Math.min(2000 + userMessage.length * 30, 4000);

// //   setTimeout(() => {
// //     botTyping.remove();

// //     // Dummy bot responses (replace later with API calls)
// //     const responses = [
// //       "Interesting point! Let me think about that...",
// //       "That’s a valid concern. Here’s what I found...",
// //       "Based on my analysis, here’s what might be happening...",
// //       "Good question! It could depend on the model’s configuration.",
// //       "This model seems more resilient to prompt injections than others.",
// //     ];

// //     const reply =
// //       responses[Math.floor(Math.random() * responses.length)];

// //     typeMessage(reply, "bot");
// //   }, delay);
// // }
// async function simulateBotResponse(userMessage) {
//     const selectedModel = document.getElementById("modelSelect").value;

//     // Show typing dots
//     const botTyping = document.createElement("div");
//     botTyping.classList.add("bot-message", "typing");
//     botTyping.textContent = "•••";
//     chatBox.appendChild(botTyping);
//     chatBox.scrollTop = chatBox.scrollHeight;

//     if (selectedModel === "gemini") {
//         try {
//            const res = await fetch("http://localhost:3000/chat", {
//                method: "POST",
//                headers: { "Content-Type": "application/json" },
//                body: JSON.stringify({ message: userMessage }),
//            });

//             const data = await res.json();
//             botTyping.remove();
//             typeMessage(data.reply, "bot");
//         } catch (error) {
//             botTyping.remove();
//             typeMessage("⚠️ Gemini API error: " + error.message, "bot");
//         }
//     } else {
//         botTyping.remove();
//         const responses = ["Simulated model reply...", "This is a placeholder response for non-Gemini models."];
//         const reply = responses[Math.floor(Math.random() * responses.length)];
//         typeMessage(reply, "bot");
//     }
// }

// // === Simulate Risk Report after chatting ===

// function generateReport() {
//     // Simulated random data
//     const riskScore = Math.floor(Math.random() * 100);
//     let severity = "Low";
//     if (riskScore > 75) severity = "Critical";
//     else if (riskScore > 50) severity = "High";
//     else if (riskScore > 25) severity = "Medium";

//     const issues = ["Potential prompt injection detected.", "Sensitive data pattern matched in response.", "Weak input sanitization found.", "No major leaks detected."];

//     const randomIssues = issues.sort(() => 0.5 - Math.random()).slice(0, 2);

//     // Update text values
//     document.getElementById("risk-score").textContent = `${riskScore}/100`;
//     document.getElementById("risk-level").textContent = severity;
//     document.getElementById("report-details").innerHTML = `
//     <ul>
//       ${randomIssues.map((issue) => `<li>${issue}</li>`).join("")}
//     </ul>
//     <p><strong>Recommendations:</strong> Review model prompts, apply stricter filters, and use contextual grounding.</p>
//   `;

//     // Animate circular gauge
//     const gaugeCircle = document.querySelector(".gauge-progress");
//     const gaugeText = document.querySelector(".gauge-text");
//     const circumference = 314;
//     const offset = circumference - (riskScore / 100) * circumference;
//     gaugeCircle.style.strokeDashoffset = offset;

//     // Change color based on severity
//     let color = "#45a29e";
//     if (severity === "Medium") color = "#f1c40f";
//     if (severity === "High") color = "#e67e22";
//     if (severity === "Critical") color = "#e74c3c";
//     gaugeCircle.style.stroke = color;
//     gaugeText.style.fill = color;

//     // Animate text count-up
//     let current = 0;
//     const interval = setInterval(() => {
//         current++;
//         gaugeText.textContent = `${current}%`;
//         if (current >= riskScore) clearInterval(interval);
//     }, 15);
// }
// // function generateReport() {
// //     const loader = document.getElementById("report-loader");
// //     const reportContent = document.getElementById("report-content");

// //     // Hide old report and show loader
// //     reportContent.classList.add("hidden");
// //     loader.classList.remove("hidden");

// //     // Simulate processing delay (like a real scan)
// //     setTimeout(() => {
// //         loader.classList.add("hidden");
// //         reportContent.classList.remove("hidden");

// //         // Simulated random data
// //         const riskScore = Math.floor(Math.random() * 100);
// //         let severity = "Low";
// //         if (riskScore > 75) severity = "Critical";
// //         else if (riskScore > 50) severity = "High";
// //         else if (riskScore > 25) severity = "Medium";

// //         const issues = ["Potential prompt injection detected.", "Sensitive data pattern matched in response.", "Weak input sanitization found.", "No major leaks detected."];

// //         const randomIssues = issues.sort(() => 0.5 - Math.random()).slice(0, 2);

// //         // Update text values
// //         document.getElementById("risk-score").textContent = `${riskScore}/100`;
// //         document.getElementById("risk-level").textContent = severity;
// //         document.getElementById("report-details").innerHTML = `
// //       <ul>
// //         ${randomIssues.map((issue) => `<li>${issue}</li>`).join("")}
// //       </ul>
// //       <p><strong>Recommendations:</strong> Review model prompts, apply stricter filters, and use contextual grounding.</p>
// //     `;

// //         // Animate circular gauge
// //         const gaugeCircle = document.querySelector(".gauge-progress");
// //         const gaugeText = document.querySelector(".gauge-text");
// //         const circumference = 314;
// //         const offset = circumference - (riskScore / 100) * circumference;
// //         gaugeCircle.style.strokeDashoffset = offset;

// //         // Change color based on severity
// //         let color = "#45a29e";
// //         if (severity === "Medium") color = "#f1c40f";
// //         if (severity === "High") color = "#e67e22";
// //         if (severity === "Critical") color = "#e74c3c";
// //         gaugeCircle.style.stroke = color;
// //         gaugeText.style.fill = color;

// //         // Animate text count-up
// //         let current = 0;
// //         const interval = setInterval(() => {
// //             current++;
// //             gaugeText.textContent = `${current}%`;
// //             if (current >= riskScore) clearInterval(interval);
// //         }, 15);
// //     }, 2000); // Simulated delay (2 seconds)
// // }

// document.getElementById("download-report").addEventListener("click", () => {
//     const reportText = `
// LeakCheck Leakage Risk Report
// -----------------------------
// Risk Score: ${document.getElementById("risk-score").textContent}
// Severity: ${document.getElementById("risk-level").textContent}
// Details:
// ${document.getElementById("report-details").innerText}
//   `;

//     const blob = new Blob([reportText], { type: "text/plain" });
//     const link = document.createElement("a");
//     link.href = URL.createObjectURL(blob);
//     link.download = "LeakCheck_Report.txt";
//     link.click();
// });

// // Call after each chat exchange
// sendButton.addEventListener("click", () => {
//   const userMessage = inputField.value.trim();
//   if (!userMessage) return;
//   addMessage(userMessage, "user");
//   inputField.value = "";
//   simulateBotResponse(userMessage);
//   setTimeout(generateReport, 4000); // generate after response
// });

// // Typing effect for the bot
// function typeMessage(text, sender) {
//   const msgDiv = document.createElement("div");
//   msgDiv.classList.add(sender === "user" ? "user-message" : "bot-message");
//   chatBox.appendChild(msgDiv);

//   let index = 0;
//   const typingSpeed = 30;

//   const typeInterval = setInterval(() => {
//     msgDiv.textContent += text.charAt(index);
//     index++;
//     chatBox.scrollTop = chatBox.scrollHeight;
//     if (index === text.length) clearInterval(typeInterval);
//   }, typingSpeed);
// }

// // Handle send message
// sendButton.addEventListener("click", () => {
//   const userMessage = inputField.value.trim();
//   if (!userMessage) return;
//   addMessage(userMessage, "user");
//   inputField.value = "";
//   simulateBotResponse(userMessage);
// });

// // Allow pressing Enter to send
// inputField.addEventListener("keypress", (e) => {
//   if (e.key === "Enter") {
//     sendButton.click();
//   }
// });
