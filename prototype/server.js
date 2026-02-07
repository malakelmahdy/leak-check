import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import https from "https";

import { detectLeakage } from "./analysis/leakageDetector.js";
import { calculateRisk } from "./analysis/riskScorer.js";

const app = express();
app.use(express.json());
app.use(cors());

// =====================
// Gemini API Configuration
// =====================
// ⚠️ NOTE: For production, move this to a .env file
const GEMINI_API_KEY = "AIzaSyDgwvlXtwUNTy4TmUHAbEVbqJ7K4vpNDpI";
const MODEL = "models/gemini-2.5-flash";

// HTTPS agent (dev-only)
const agent = new https.Agent({ rejectUnauthorized: false });

// =====================
// Chat Endpoint
// =====================
app.post("/chat", async (req, res) => {
    const { message } = req.body;

    if (!message) {
        return res.status(400).json({ error: "Message is required." });
    }

    try {
        const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/${MODEL}:generateContent?key=${GEMINI_API_KEY}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                contents: [{ parts: [{ text: message }] }],
            }),
            agent,
        });

        const data = await response.json();

        // Validate Gemini response
        if (!data.candidates || data.candidates.length === 0) {
            console.error("Gemini API error:", data);
            return res.status(500).json({
                error: data.error?.message || "No response from Gemini.",
            });
        }

        const modelReply = data.candidates[0].content.parts[0].text;

        // =====================
        // Leak Check Pipeline
        // =====================
        const findings = detectLeakage(modelReply);
        const risk = calculateRisk(findings);

        // Debug logs (safe to keep for evaluation)
        console.log("========== LEAK CHECK ==========");
        console.log("Model reply:");
        console.log(modelReply);
        console.log("Detected findings:");
        console.log(findings);
        console.log("Risk assessment:");
        console.log(risk);
        console.log("================================");

        // Send structured response to frontend
        res.json({
            reply: modelReply,
            findings,
            risk,
        });
    } catch (error) {
        console.error("Error contacting Gemini:", error);
        res.status(500).json({
            error: "Failed to contact Gemini API.",
        });
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
