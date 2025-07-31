const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const Database = require("better-sqlite3");

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "docs")));

// SQLite databases
//const db = new Database("./questions.db");
const db = new Database(path.join(__dirname, "questions.db"));
//old users line deleteed.
const userDB = new Database(path.join(__dirname, "users.db"));




console.log("✅ Connected to both databases.");

// Create tables if not exists
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

//CONSOLE LOG now included
app.post('/log', (req, res) => {
  const { question, answer, email } = req.body;

  console.log("🟡 Incoming log body:", { question, answer, email });

  if (!question || !answer) {
    console.log("⚠️ Missing question or answer");
    return res.status(400).send("Missing data");
  }

  try {
    const stmt = db.prepare("INSERT INTO questions (question, answer, email) VALUES (?, ?, ?)");
    
    // Force email to be null or string
    const safeEmail = typeof email === "string" ? email : null;

    stmt.run(question, answer, safeEmail);

    console.log("✅ Question logged:", question);
    console.log("✅ Answer received:", answer);
    res.status(200).send("Logged successfully");

  } catch (err) {
    console.error("❌ DB error:", err.message);
    res.status(500).send("Database error");
  }
});



/*REPLACED with above console log for testing
// POST /log — store Q&A
app.post('/log', (req, res) => {
  const { question, answer, email } = req.body;

  if (!question || !answer) {
    console.log("⚠️ Missing question or answer");
    return res.status(400).send("Missing data");
  }

  try {
    const stmt = db.prepare("INSERT INTO questions (question, answer, email) VALUES (?, ?, ?)");
    stmt.run(
      question,
      answer,
      typeof email === "string" ? email : null, // ✅ ensures email is a string or null
      function (err) {
        if (err) {
          console.error("❌ DB insert error:", err.message);
          return res.status(500).send("Database error");
        }
        console.log("✅ Question logged:", question);
        console.log("✅ Answer received:", answer);
        res.status(200).send("Logged successfully");
      }
    );
  } catch (err) {
    console.error("❌ DB error:", err.message);
    res.status(500).send("Database error");
  }
});
*/

// POST /signup — store user
app.post("/signup", (req, res) => {
  const { fname, lname, email, dob, password } = req.body;

  if (!fname || !lname || !email || !dob || !password) {
    console.log("⚠️ Incomplete sign-up data");
    return res.status(400).send("All fields required");
  }

  try {
    const stmt = userDB.prepare(`
      INSERT INTO users (fname, lname, email, dob, password)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(fname, lname, email, dob, password);
    console.log(`✅ New user signed up: ${email}`);
    res.status(200).send("Signup successful");
  } catch (err) {
    console.error("❌ Sign-up error:", err.message);
    res.status(500).send("User already exists or DB error");
  }
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Missing fields" });
  }

  const query = "SELECT * FROM users WHERE email = ? AND password = ?";
  const row = userDB.prepare(query).get(email, password);

  if (row) {
    res.json({ success: true, fname: row.fname });

  } else {
    res.json({ success: false });
  }
  res.json({ success: true, fname: row.fname });


});

// POST /update-email — change user's email
app.post('/update-details', (req, res) => {
  const { currentEmail, password, newEmail, newPassword } = req.body;
  if (!currentEmail || !password) {
    return res.status(400).send("Missing current credentials");
  }

  const stmt = userDB.prepare("SELECT * FROM users WHERE email = ? AND password = ?");
  const user = stmt.get(currentEmail, password);
  if (!user) {
    return res.status(401).send("Invalid current email or password");
  }

  // Update email if provided
  if (newEmail) {
    userDB.prepare("UPDATE users SET email = ? WHERE email = ?").run(newEmail, currentEmail);
    db.prepare("UPDATE questions SET email = ? WHERE email = ?").run(newEmail, currentEmail);
  }

  // Update password if provided
  if (newPassword) {
    const emailToUse = newEmail || currentEmail;
    userDB.prepare("UPDATE users SET password = ? WHERE email = ?").run(newPassword, emailToUse);
  }

  res.send("Account update successful");
});


// GET /history — fetch questions by email
app.get('/history', (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).send("Missing email");

  const stmt = db.prepare("SELECT question, answer, timestamp FROM questions WHERE email = ? ORDER BY timestamp DESC");
  const rows = stmt.all(email);
  res.json(rows);
});


