// ─────────────────────────────────────────────────────────────────────────────
// server.js (Novust) — cleaned + fixed
// model selector rows 200 & 205
// ─────────────────────────────────────────────────────────────────────────────
const express = require("express");
const cors = require("cors");
const path = require("path");
const Database = require("better-sqlite3");
const isProd = process.env.NODE_ENV === "production";
const RSSParser = require('rss-parser');
const rss = new RSSParser();

if (!isProd) {
  require("dotenv").config();
  console.log("dotenv loaded (dev)");
} else {
  console.log("dotenv NOT loaded (prod)");
}
const effectiveKey = process.env.FORCE_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
const mask = v => (v ? `${v.slice(0,8)}...${v.slice(-6)}` : "(none)");
console.log("🔐 Keys at boot:", {
  OPENAI_API_KEY: mask(process.env.OPENAI_API_KEY),
  FORCE_OPENAI_API_KEY: mask(process.env.FORCE_OPENAI_API_KEY),
  effective: mask(effectiveKey)
});


// use effectiveKey to init client
//const openai = new OpenAI({ apiKey: effectiveKey });

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
    if (!origin) return cb(null, true);             // curl/postman/file://
    if (origin === "null") return cb(null, true);   // some webviews
    try {
      const { hostname } = new URL(origin);
      if (hostname === "localhost" || hostname === "127.0.0.1") return cb(null, true);
      if (hostname.endsWith(".netlify.app")) return cb(null, true);
      if (hostname === "novustuk.netlify.app") return cb(null, true);
      // add custom domains here later, e.g.: if (hostname === "novust.com") return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    } catch {
      return cb(new Error("Bad origin"));
    }
  },
  credentials: false,               // you’re not using cookies; avoids stricter preflight
  optionsSuccessStatus: 204,        // older browsers/Safari quirk
  preflightContinue: false
}));


// --- CORS: explicit preflight handler (fixes Safari "Preflight response is not successful") ---
const allowHeaders = "Content-Type, Authorization, X-Requested-With";
const allowMethods = "GET,POST,OPTIONS";


// ✅ use regex catch‑all instead
app.options(/.*/, (req, res) => {
  const origin = req.headers.origin || "*";
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    req.headers["access-control-request-headers"] || "Content-Type, Authorization, X-Requested-With"
  );
  return res.sendStatus(204);
});


app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Static (optional; keep after parsers)
app.use(express.static(path.join(__dirname, "docs")));

const OpenAI = require("openai");
const openai = new OpenAI({ apiKey: effectiveKey });

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


app.get("/debug/env", (_req, res) => {
  const mask = v => (v ? `${v.slice(0,8)}...${v.slice(-6)}` : null);
  res.json({
    OPENAI_API_KEY: mask(process.env.OPENAI_API_KEY),
    FORCE_OPENAI_API_KEY: mask(process.env.FORCE_OPENAI_API_KEY),
    NODE_ENV: process.env.NODE_ENV || null,
    RENDER_SERVICE_NAME: process.env.RENDER_SERVICE_NAME || null,
    RENDER_GIT_BRANCH: process.env.RENDER_GIT_BRANCH || null,
    RENDER_GIT_COMMIT: process.env.RENDER_GIT_COMMIT || null,
    uptime_seconds: Math.round(process.uptime())
  });
});


app.post("/api/ask", async (req, res) => {
  try {
    const { question } = req.body;
    if (!question) {
      console.warn("[ASK] Missing question in request body");
      return res.status(400).json({ error: "Question is required" });
    }

    console.log("[ASK] Received question:", question);

   const system = `
You are a UK chartered tax adviser for tax year 2025/26 unless the user specifies another year.
- Always use current UK thresholds/rates for 2025/26; amounts in GBP (£).
- If the question is missing a total income figure, state the assumption you're making.
- Prefer HMRC terminology. Avoid US rules unless a comparison is requested.
- Respond conversationally, like a friendly accountant.
- Format answers as:
  1) Short answer (1–20 lines),
  2) Calculation / reasoning steps (bullets with numbers),
  3) What to watch out for,
  4) Sources (GOV.UK links).
- End with: "Please note your total income impacts the level of tax on each income stream, please ensure you provide this for a more accurate response".
Do NOT add generic AI disclaimers.
`;

const messages = [
  { role: "system", content: system },
  { role: "user", content: `UK context — ${question}` }
];


    //MODEL SELECTOR
    console.log("[ASK] Sending to OpenAI with model:", process.env.NOVUST_MODEL || "gpt-4o-mini"); //MODELSELECTOR HERE

    let answer;
    try {
      const completion = await openai.chat.completions.create({
        model: process.env.NOVUST_MODEL || "gpt-4o-mini", //MODELSELECTOR HERE
        messages
      });

      answer = completion.choices?.[0]?.message?.content?.trim() || "";
    } catch (e) {
      console.error("[ASK] OpenAI API error:", {
        status: e.status,
        code: e.code,
        msg: e.message,
        data: e.response?.data
      });
      throw e;
    }

    // Remove ChatGPT's default disclaimer if present
    answer = answer.replace(/\*\*Disclaimer\*\*:.*$/is, "").trim();

    // Prepend your custom blurb
    const intro = "Hi there, thanks for choosing me to help. Please note I am a working model for testing purposes only right now. Exciting news however, the team behind me are working hard to update me to provide a more tailored and individual response as an actual boring accountant in the future, well not that exciting but is to me.\n\nBelow is the answer you need:\n\n";
    answer = intro + answer;

    if (!answer.trim()) answer = "Sorry — I couldn’t generate an answer.";
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

// ── NEWS LINKS ──────────────────────────────────────────────────────────────

app.get('/news', async (req, res) => {
  try {
    const feeds = [
      'https://www.gov.uk/government/organisations/hm-revenue-customs.atom',
      'https://www.icaew.com/rss',                 // hub page; you can swap for specific feeds you like
      'https://www.accountingweb.co.uk/rss',
      'https://www.gov.uk/government/organisations/hm-treasury.atom'
    ];
    const all = [];
    for (const url of feeds) {
      try {
        const f = await rss.parseURL(url);
        (f.items || []).slice(0, 5).forEach(i => {
          all.push({ title: i.title, link: i.link, date: i.isoDate || i.pubDate, source: f.title });
        });
      } catch (e) { /* skip failing feed */ }
    }
    // sort newest first
    all.sort((a,b)=> new Date(b.date||0)-new Date(a.date||0));
    res.json(all.slice(0, 12));
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch news' });
  }
});
