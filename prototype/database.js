import sqlite3 from "sqlite3";

const db = new sqlite3.Database("leakcheck.db");

// Initialize tables
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            model_type TEXT,
            prompt TEXT,
            response TEXT,
            risk_score INTEGER,
            detected_leaks TEXT,
            status TEXT
        )
    `);
});

export function storeResult(prompt, response, leakResults, riskScore) {
    return new Promise((resolve, reject) => {
        db.run(
            `INSERT INTO audits (model_type, prompt, response, risk_score, detected_leaks, status)
             VALUES (?, ?, ?, ?, ?, ?)`,
            ["gemini", prompt, response, riskScore.score, JSON.stringify(riskScore.detectedTypes), "completed"],
            function (err) {
                if (err) reject(err);
                else resolve(this.lastID);
            },
        );
    });
}

export function getAuditHistory(limit = 50) {
    return new Promise((resolve, reject) => {
        db.all(`SELECT * FROM audits ORDER BY timestamp DESC LIMIT ?`, [limit], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}
