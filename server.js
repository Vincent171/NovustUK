// ─────────────────────────────────────────────────────────────────────────────
// server.js (Novust) — cleaned + fixed
// ─────────────────────────────────────────────────────────────────────────────
const express = require("express");
const cors = require("cors");
const path = require("path");
const Database = require("better-sqlite3");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 3000;

// Persistent data dir (Render disk or local)
const DATA_DIR = process.env.DATA_DIR || __dirname;

// ── SQLite DBs (single source of truth) ──────────────────────────────────────
const db = new Database(path.join(DATA_DIR, "questions.db")); // Q&A
const userDB = new Database(path.join(DATA_DIR, "users.db")); // Users

// CORS + parsers — BEFORE routes/static
const allowed = new Set([
  "http://localhost:3000",
  "http://127.0.0.1:5500",
  "http://localhost:5173",             // common Vite port (optional)
  "https://novustuk.netlify.app"
  // add your custom domain here when ready, e.g. "https://novust.com"
]);

//debug tool
/*app.use((req, res, next) => {
  console.log("CORS check — Origin:", req.headers.origin, " Referer:", req.headers.referer);
  next();
});*/
//end debug

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server / curl / Postman (no Origin)
    if (!origin) return cb(null, true);

    // Allow local file:// (some browsers send "null")
    if (origin === "null") return cb(null, true);

    try {
      const { hostname } = new URL(origin);

      // Allow any localhost or 127.0.0.1 (any port)
      if (hostname === "localhost" || hostname === "127.0.0.1") {
        return cb(null, true);
      }

      // Allow any Netlify preview or main domain
      if (hostname.endsWith(".netlify.app")) return cb(null, true);
      if (hostname === "novustuk.netlify.app") return cb(null, true);

      // Optional: add your custom prod domain here later
      // if (hostname === "novust.com") return cb(null, true);

      return cb(new Error("Not allowed by CORS"));
    } catch {
      return cb(new Error("Bad origin"));
    }
  },
  credentials: true
}));


app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Static (optional; keep after parsers)
app.use(express.static(path.join(__dirname, "docs")));

// OpenAI
const OpenAI = require("openai");
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

console.log("✅ Connected to both databases.");

// Tables
db.prepare(`
  CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    email TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

userDB.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fname TEXT NOT NULL,
    lname TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    dob TEXT NOT NULL,
    password TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ── Health ──────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  return res.json({ ok: true, service: "novust-api" });
});


app.get("/health/openai", async (_req, res) => {
  try {
    const r = await openai.models.list();
    res.json({ ok: true, count: r.data?.length || 0 });
  } catch (e) {
    console.error("OPENAI health fail:", {
      status: e.status,
      code: e.code,
      msg: e.message,
      data: e.response?.data,
    });
    res.status(500).json({
      ok: false,
      status: e.status,
      code: e.code,
      msg: e.message,
    });
  }
});


// ── ASK (UK tax system prompt) ───────────────────────────────────────────────
app.post("/api/ask", async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) {
      console.warn("[ASK] Missing question in request body");
      return res.status(400).json({ error: "Question is required" });
    }

    console.log("[ASK] Received question:", question);

    const messages = [
      {
        role: "system",
        content: [
          "You are a UK chartered tax adviser. Assume the user is in the United Kingdom.",
          "Use HMRC terminology and current UK thresholds; give amounts in GBP (£).",
          "Avoid US rules unless explicitly asked to compare.",
          "Include a short non-advice disclaimer for complex cases."
        ].join(" ")
      },
      { role: "user", content: `UK context — ${question}` }
    ];

    console.log("[ASK] Sending to OpenAI with model:", process.env.NOVUST_MODEL || "gpt-4o-mini");

    let answer;
    try {
      const completion = await openai.chat.completions.create({
        model: process.env.NOVUST_MODEL || "gpt-4o-mini",
        messages
      });

      answer = completion.choices?.[0]?.message?.content?.trim();
      console.log("[ASK] OpenAI answer length:", answer?.length || 0);
    } catch (e) {
      console.error("[ASK] OpenAI API error:", {
        status: e.status,
        code: e.code,
        msg: e.message,
        data: e.response?.data
      });
      throw e; // bubble to outer catch
    }

    if (!answer) answer = "Sorry — I couldn’t generate an answer.";
    return res.json({ answer });

  } catch (err) {
    console.error("[ASK] Outer error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});


// Optional alias so older frontend hitting /ask still works:
app.post("/ask", (req, res) => {
  req.url = "/api/ask";
  return app._router.handle(req, res);
});

// ── LOG Q&A (store into questions table) ─────────────────────────────────────
app.post("/log", (req, res) => {
  try {
    const { question, answer, email } = req.body;
    if (!question || !answer)
      return res.status(400).json({ error: "question and answer are required" });

    db.prepare(`
      INSERT INTO questions (question, answer, email)
      VALUES (?, ?, ?)
    `).run(question, answer, email || null);

    return res.json({ message: "Log saved" });
  } catch (err) {
    console.error("log error:", err);
    return res.status(500).json({ error: "Failed to save log" });
  }
});

// ── SIGNUP (use userDB) ─────────────────────────────────────────────────────
app.post("/signup", (req, res) => {
  try {
    const { fname, lname, email, dob, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const insert = userDB.prepare(`
      INSERT INTO users (email, fname, lname, dob, password)
      VALUES (?, ?, ?, ?, ?)
    `);

    try {
      insert.run(email, fname || "", lname || "", dob || "", password);
    } catch (e) {
      if (String(e).includes("UNIQUE")) {
        return res.status(409).json({ error: "Email already registered" });
      }
      throw e;
    }

    console.log("🟢 /signup:", email);
    return res.json({ success: true, message: "Signup successful" });
  } catch (err) {
    console.error("signup error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ── LOGIN (use userDB) ──────────────────────────────────────────────────────
app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const row = userDB.prepare(`
      SELECT email, fname, password
      FROM users
      WHERE email = ?
    `).get(email);

    if (!row) return res.json({ success: false });

    // If hashing, replace with bcrypt.compareSync(...)
    if (row.password !== password) return res.json({ success: false });

    console.log("🟢 /login:", email);
    return res.json({ success: true, fname: row.fname || "" });
  } catch (err) {
    console.error("login error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ── UPDATE DETAILS (use userDB, also update questions.email) ─────────────────
app.post("/update-details", (req, res) => {
  try {
    const { currentEmail, password, newEmail, newPassword } = req.body;
    if (!currentEmail || !password) {
      return res.status(400).send("Missing credentials");
    }

    const user = userDB.prepare(`
      SELECT email, password
      FROM users
      WHERE email = ?
    `).get(currentEmail);

    if (!user) return res.status(404).send("Account not found");

    // If hashing, use bcrypt.compareSync(password, user.password)
    if (user.password !== password) return res.status(401).send("Incorrect password");

    const updates = [];
    const params = [];

    if (newEmail && newEmail !== currentEmail) {
      updates.push("email = ?");
      params.push(newEmail);
    }
    if (newPassword) {
      updates.push("password = ?");
      params.push(newPassword);
    }
    params.push(currentEmail);

    if (updates.length) {
      userDB.prepare(`UPDATE users SET ${updates.join(", ")} WHERE email = ?`).run(...params);

      // also update historical questions email in the Q&A DB
      if (newEmail && newEmail !== currentEmail) {
        db.prepare(`UPDATE questions SET email = ? WHERE email = ?`).run(newEmail, currentEmail);
      }
    }

    return res.send("Update success");
  } catch (err) {
    console.error("update-details error:", err);
    return res.status(500).send("Server error");
  }
});

// ── HISTORY (read from questions table) ──────────────────────────────────────
app.get("/history", (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ error: "email is required" });

    const rows = db.prepare(`
      SELECT question, answer, timestamp
      FROM questions
      WHERE email = ?
      ORDER BY datetime(timestamp) DESC
      LIMIT 200
    `).all(email);

    return res.json(rows);
  } catch (err) {
    console.error("history error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ── USER INFO (use userDB) ──────────────────────────────────────────────────
app.get("/user-info", (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ error: "email is required" });

    const row = userDB.prepare(`
      SELECT email, fname, lname
      FROM users
      WHERE email = ?
    `).get(email);

    if (!row) return res.status(404).json({ error: "Not found" });
    return res.json(row);
  } catch (err) {
    console.error("user-info error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ── Central error handler (last) ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("🔥 Unhandled error:", err);
  if (res.headersSent) return next(err);
  return res.status(500).json({ error: "Server error" });
});

// ── Start ───────────────────────────────────────────────────────────────────
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
