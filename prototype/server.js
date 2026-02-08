import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import https from "https";
import crypto from "crypto";
import nodemailer from "nodemailer";
import path from "path";
import { fileURLToPath } from "url";

import { detectLeakage } from "./analysis/leakageDetector.js";
import { detectPromptInjection } from "./analysis/promptInjectionDetector.js";
import { detectJailbreak } from "./analysis/jailbreakDetector.js";
import { loadDatasets, getRandomAttack } from "./attack-generator/csvLoader.js";
import { mutateAttack, generateVariants } from "./attack-generator/mutationEngine.js";

import "dotenv/config"; // Load env vars

// =====================
// Email Configuration
// =====================
let transporter;

async function setupTransporter() {
    if (process.env.EMAIL_USER && process.env.EMAIL_USER.includes("@")) {
        // Use Real Email (Gmail)
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });
        console.log(`✅ Using Real Email: ${process.env.EMAIL_USER}`);
    } else {
        // Fallback to Ethereal
        try {
            const testAccount = await nodemailer.createTestAccount();
            transporter = nodemailer.createTransport({
                host: testAccount.smtp.host,
                port: testAccount.smtp.port,
                secure: testAccount.smtp.secure,
                auth: {
                    user: testAccount.user,
                    pass: testAccount.pass,
                },
            });
            console.log("✅ Ethereal Email Transporter Ready (Test Mode)");
            console.log(`   User: ${testAccount.user}`);
        } catch (err) {
            console.error("Failed to create test account.", err);
        }
    }
}
setupTransporter();
import { calculateRisk } from "./analysis/riskScorer.js";

// Load attack datasets on startup (async)
(async () => {
    await loadDatasets();
})();

const app = express();
app.use(express.json());
app.use(cors());

// Serve static files (HTML, CSS, JS, etc.)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
console.log('📁 Serving static files from:', __dirname);
app.use(express.static(__dirname));

// =====================
// Firebase Configuration
// =====================
const FIREBASE_DB_URL = "https://leck-check-22dae-default-rtdb.firebaseio.com";

// =====================
// Gemini API Configuration
// =====================
// ⚠️ NOTE: For production, move this to a .env file
const GEMINI_API_KEY = "AIzaSyDgwvlXtwUNTy4TmUHAbEVbqJ7K4vpNDpI";
const MODEL = "models/gemini-2.5-flash";

// HTTPS agent (dev-only)
const agent = new https.Agent({ rejectUnauthorized: false });

// =====================
// Auth Endpoints
// =====================

// Helper to hash passwords
const hashPassword = (password) => {
    return crypto.scryptSync(password, 'salt', 64).toString('hex');
};

// Signup Endpoint (Step 1: Send OTP)
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: "All fields are required." });
    }

    try {
        // 1. Check if user already exists in main users list
        const checkRes = await fetch(`${FIREBASE_DB_URL}/users.json`);
        let users = {};
        if (checkRes.ok) users = await checkRes.json() || {};

        const userExists = Object.values(users).some(u => u.email === email);
        if (userExists) {
            return res.status(400).json({ error: "User already exists." });
        }

        // 2. Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();

        // 3. Store pending registration
        // Use hashed email as key to handle special chars
        const pendingKey = crypto.createHash('md5').update(email).digest('hex');

        const pendingUser = {
            full_name: name,
            email: email,
            password_hash: hashPassword(password),
            otp: otp,
            createdAt: new Date().toISOString()
        };

        const saveRes = await fetch(`${FIREBASE_DB_URL}/pending_registrations/${pendingKey}.json`, {
            method: "PUT", // Use PUT to overwrite existing pending reg for this email
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(pendingUser),
        });

        if (!saveRes.ok) {
            const errorText = await saveRes.text();
            console.error(`Firebase Error (${saveRes.status}):`, errorText);
            throw new Error("Failed to save pending registration");
        }

        // 4. Send Email
        if (transporter) {
            const info = await transporter.sendMail({
                from: '"Leak Check Security" <noreply@leakcheck.ai>',
                to: email,
                subject: "Your Verification Code - Leak Check",
                text: `Your verification code is: ${otp}`,
                html: `<b>Your verification code is: ${otp}</b>`,
            });
            console.log("📨 Email sent: %s", info.messageId);
            console.log("🔗 Preview URL: %s", nodemailer.getTestMessageUrl(info));
        } else {
            console.log("⚠️ Transporter not ready. OTP:", otp);
        }

        res.status(200).json({
            message: "OTP sent to your email.", preview: nodemailer.getTestMessageUrl
                ? "Check server console for Ethereal URL" : null
        });

    } catch (error) {
        console.error("Signup Error:", error);
        res.status(500).json({ error: "Signup failed." });
    }
});

// Verify OTP Endpoint (Step 2: Confirm)
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ error: "Email and OTP are required." });
    }

    try {
        const pendingKey = crypto.createHash('md5').update(email).digest('hex');

        // 1. Fetch pending registration
        const pendingRes = await fetch(`${FIREBASE_DB_URL}/pending_registrations/${pendingKey}.json`);
        const pendingUser = await pendingRes.json();

        if (!pendingUser) {
            return res.status(400).json({ error: "No pending registration found or expired." });
        }

        // 2. Verify OTP
        if (pendingUser.otp !== otp) {
            return res.status(400).json({ error: "Invalid OTP." });
        }

        // 3. Create User in main DB
        // Fetch users to determine ID
        const usersRes = await fetch(`${FIREBASE_DB_URL}/users.json`);
        let users = {};
        if (usersRes.ok) users = await usersRes.json() || {};
        const userList = Object.values(users);

        let nextId = 1;
        if (userList.length > 0) {
            const maxId = userList.reduce((max, user) => {
                const uid = parseInt(user.user_id) || 0;
                return uid > max ? uid : max;
            }, 0);
            nextId = maxId + 1;
        }

        const newUser = {
            user_id: nextId,
            full_name: pendingUser.full_name,
            email: pendingUser.email,
            password_hash: pendingUser.password_hash,
            created_at: new Date().toISOString(),
            last_login_at: "",
            status: "active"
        };

        const createRes = await fetch(`${FIREBASE_DB_URL}/users.json`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(newUser),
        });

        if (!createRes.ok) throw new Error("Failed to create user");

        // 4. Delete pending registration
        await fetch(`${FIREBASE_DB_URL}/pending_registrations/${pendingKey}.json`, {
            method: "DELETE"
        });

        res.status(201).json({ message: "Account verified and created!", userId: nextId });

    } catch (error) {
        console.error("Verification Error:", error);
        res.status(500).json({ error: "Verification failed." });
    }
});

// Login Endpoint
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        const response = await fetch(`${FIREBASE_DB_URL}/users.json`);
        const users = await response.json();

        if (!users) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        const hashedPassword = hashPassword(password);
        // Update to match password_hash and full_name
        const user = Object.values(users).find(u => u.email === email && u.password_hash === hashedPassword);

        if (!user) {
            return res.status(401).json({ error: "Invalid credentials." });
        }

        // In a real app, you would return a JWT token here
        res.json({ message: "Login successful!", user: { name: user.full_name, email: user.email } });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: "Login failed." });
    }
});

// =====================
// Chat Endpoint
// =====================
// =====================
// Chat Endpoint
// =====================
// =====================
// Chat Endpoint (Session-based) - Supports Gemini and Llama
// =====================
app.post("/chat", async (req, res) => {
    let { message, userId, sessionId, model = "llama" } = req.body;

    if (!message) {
        return res.status(400).json({ error: "Message is required." });
    }

    try {
        let modelReply;

        // Choose model endpoint
        if (model === "llama") {
            // Call local Llama server (must be running on port 8080)
            const llamaResponse = await fetch("http://127.0.0.1:8080/v1/chat/completions", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    messages: [
                        {
                            role: "system",
                            content: "You are a helpful AI assistant. Respond naturally in plain text. Do not use JSON format or function calling. Answer user questions directly and conversationally."
                        },
                        {
                            role: "user",
                            content: message
                        }
                    ],
                    temperature: 0.7,
                    max_tokens: 512
                })
            });

            if (!llamaResponse.ok) {
                throw new Error(`Llama server error: ${llamaResponse.status}`);
            }

            const llamaData = await llamaResponse.json();

            // Parse Llama response - handle both function calling and normal format
            let rawResponse = llamaData.choices[0].message.content;

            // If response is JSON function call, extract the actual text
            try {
                const parsed = JSON.parse(rawResponse);
                if (parsed.name && parsed.parameters) {
                    // Extract text from function call parameters
                    modelReply = parsed.parameters.s || parsed.parameters.text || JSON.stringify(parsed.parameters);
                } else {
                    modelReply = rawResponse;
                }
            } catch (e) {
                // Not JSON, use as-is (normal text response)
                modelReply = rawResponse;
            }

        } else {
            // Use Gemini
            const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/${MODEL}:generateContent?key=${GEMINI_API_KEY}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: message }] }],
                }),
                agent,
            });

            const data = await response.json();

            if (!data.candidates || data.candidates.length === 0) {
                console.error("Gemini API error:", data);
                return res.status(500).json({
                    error: data.error?.message || "No response from Gemini.",
                });
            }

            modelReply = data.candidates[0].content.parts[0].text;
        }

        // Run all 3 detectors (for both Gemini and Llama)
        const leakageFindings = await detectLeakage(modelReply);
        const injectionFindings = await detectPromptInjection(message, modelReply);
        const jailbreakFindings = await detectJailbreak(message, modelReply);

        // Combine all findings
        const findings = [...leakageFindings, ...injectionFindings, ...jailbreakFindings];
        const risk = calculateRisk(findings);

        // =====================
        // Store in Firebase
        // =====================
        if (userId) {
            const timestamp = Date.now();
            const dateStr = new Date().toISOString();

            // Generate Session ID if new
            if (!sessionId) {
                sessionId = `${timestamp}_${Math.random().toString(36).substr(2, 9)}`;
                // Create initial metadata
                await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions/${sessionId}/metadata.json`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        id: sessionId,
                        title: message.substring(0, 30) + (message.length > 30 ? "..." : ""), // Simple title generation
                        createdAt: timestamp,
                        lastUpdated: timestamp
                    })
                });
            } else {
                // Update lastUpdated
                await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions/${sessionId}/metadata/lastUpdated.json`, {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(timestamp)
                });
            }

            // 1. User Message
            await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions/${sessionId}/messages.json`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    role: "user",
                    content: message,
                    timestamp: timestamp,
                    date: dateStr
                })
            });

            // 2. Bot Response
            await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions/${sessionId}/messages.json`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    role: "model",
                    content: modelReply,
                    findings: findings.length > 0 ? findings : null,
                    risk: risk,
                    timestamp: timestamp + 1,
                    date: dateStr
                })
            });
        }

        res.json({
            reply: modelReply,
            findings,
            risk,
            sessionId // Return the session ID so frontend can update state
        });
    } catch (error) {
        console.error("Chat endpoint error:", error);
        res.status(500).json({
            error: `Failed to process chat: ${error.message}`,
        });
    }
});

// Get User Sessions
app.get("/sessions/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        // Fetch all sessions (we want metadata only really, but Firebase structure prevents easy separation unless we query)
        // For simplicity in prototype, we'll fetch all session METADATA if we structured it correctly, 
        // but since we nested metadata INSIDE the session node along with messages, we might fetch too much data.
        // BETTER: Fetch `chats/{userId}/sessions` but utilize shallow=true if using REST API to get keys? 
        // OR: Just fetch all and map. For a prototype with small history it's fine.

        // Actually, let's just fetch everything and process server-side or restructure.
        // Restructuring `chats/{userId}/metadata` separately from `chats/{userId}/messages` is better but let's stick to what we built:
        // `chats/{userId}/sessions/{sessionId}/metadata`

        const response = await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions.json`); // Fetch all sessions
        const data = await response.json();

        if (!data) return res.json([]);

        // Extract metadata from each session
        const sessions = Object.values(data).map(session => session.metadata).filter(m => m)
            .sort((a, b) => b.lastUpdated - a.lastUpdated); // Newest first

        res.json(sessions);
    } catch (error) {
        console.error("Sessions Error:", error);
        res.status(500).json({ error: "Failed to fetch sessions." });
    }
});

// Get Session History
app.get("/history/:userId/:sessionId", async (req, res) => {
    const { userId, sessionId } = req.params;
    try {
        const response = await fetch(`${FIREBASE_DB_URL}/chats/${userId}/sessions/${sessionId}/messages.json`);
        const data = await response.json();

        if (!data) return res.json([]);

        const history = Object.values(data).sort((a, b) => a.timestamp - b.timestamp);
        res.json(history);
    } catch (error) {
        console.error("History Error:", error);
        res.status(500).json({ error: "Failed to fetch history." });
    }
});

// =====================
// Attack Generation Endpoint (CSV-based)
// =====================
app.post('/generate-attack', (req, res) => {
    const { category, mutationLevel = 2, generateMultiple = false } = req.body;

    if (!category) {
        return res.status(400).json({ error: 'Category is required' });
    }

    try {
        // Get a random attack from the category
        const baseAttack = getRandomAttack(category);

        if (!baseAttack) {
            return res.status(404).json({
                error: `No attacks found for category: ${category}`
            });
        }

        if (generateMultiple) {
            // Generate multiple variants
            const variants = generateVariants(baseAttack, 3, mutationLevel);
            res.json({ variants });
        } else {
            // Generate single mutated attack
            const mutated = mutateAttack(baseAttack, mutationLevel);
            res.json({ attack: mutated });
        }

    } catch (error) {
        console.error('Attack generation error:', error);
        res.status(500).json({ error: 'Failed to generate attack' });
    }
});

// =====================
// Server Startup
// =====================
app.listen(3000, () => {
    console.log("✅ Server running on http://localhost:3000");
});

// import express from "express";
// import fetch from "node-fetch";
// import cors from "cors";
// import https from "https";
// import { detectLeakage } from "./analysis/leakageDetector.js";
// import { calculateRisk } from "./analysis/riskScorer.js";

// const app = express();
// app.use(express.json());
// app.use(cors());

// // === Gemini API integration ===
// // ⚠️ IMPORTANT: Move this to .env later (for now we keep it working)
// const GEMINI_API_KEY = "AIzaSyDgwvlXtwUNTy4TmUHAbEVbqJ7K4vpNDpI";
// const MODEL = "models/gemini-2.5-flash";
// const agent = new https.Agent({ rejectUnauthorized: false });

// app.post("/chat", async (req, res) => {
//     const { message } = req.body;

//     try {
//         const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/${MODEL}:generateContent?key=${GEMINI_API_KEY}`, {
//             method: "POST",
//             headers: { "Content-Type": "application/json" },
//             body: JSON.stringify({
//                 contents: [{ parts: [{ text: message }] }],
//             }),
//             agent,
//         });

//         const data = await response.json();

//         // ✅ Check for valid response
//        if (data.candidates && data.candidates.length > 0) {
//            const modelReply = data.candidates[0].content.parts[0].text;

//            const findings = detectLeakage(modelReply);
//            const risk = calculateRisk(findings);

//            res.json({
//                reply: modelReply,
//                findings,
//                risk,
//            });
// console.log("Risk score:", risk);

//         //    const findings = detectLeakage(modelReply);

//         //    console.log("========== LEAK CHECK ==========");
//         //    console.log("Model reply:");
//         //    console.log(modelReply);
//         //    console.log("Detected findings:");
//         //    console.log(findings);
//         //    console.log("================================");

//         //    res.json({
//         //        reply: modelReply,
//         //        findings,
//         //    });
//        } else {
//            console.error("Gemini API error:", data);
//            res.status(500).json({
//                error: data.error?.message || "No response from Gemini. Please try again.",
//            });
//        }
//     } catch (error) {
//         console.error("Error contacting Gemini:", error);
//         res.status(500).json({ error: "Failed to contact Gemini API." });
//     }
// });

// app.listen(3000, () => console.log("✅ Server running on http://localhost:3000"));
