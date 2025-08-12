// ─────────────────────────────────────────────────────────────────────────────
// server.js (Novust) — cleaned, secured, and RAG-ready
// ─────────────────────────────────────────────────────────────────────────────
const express = require('express');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const RSSParser = require('rss-parser');
const rss = new RSSParser();

const isProd = process.env.NODE_ENV === 'production';
if (!isProd) { require('dotenv').config(); }

const app = express();
const port = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;

// ── OpenAI client ───────────────────────────────────────────────────────────
const { OpenAI } = require('openai');
const effectiveKey = process.env.FORCE_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
const openai = new OpenAI({ apiKey: effectiveKey });
const DEFAULT_MODEL = process.env.NOVUST_MODEL || 'gpt-5-thinking';

// ── DBs ─────────────────────────────────────────────────────────────────────
const db = new Database(path.join(DATA_DIR, 'questions.db')); // Q&A
const userDB = new Database(path.join(DATA_DIR, 'users.db')); // Users

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
    password_hash TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const ALLOW = (process.env.ALLOW_ORIGINS || 'http://localhost:3000,https://novustuk.netlify.app')
  .split(',').map(s=>s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb){
    if (!origin) return cb(null, true); // curl/file://
    const ok = ALLOW.includes(origin);
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true
}));

// Serve static site locally from /docs
app.use(express.static(path.join(__dirname, 'docs')));

// Attach user from JWT if present (so /log can capture email)
const JWT_SECRET = process.env.NOVUST_JWT_SECRET || 'dev-secret-change-me';
const TOKEN_COOKIE = 'novust_token';
function attachUserIfPresent(req, _res, next){
  try {
    const t = req.cookies?.[TOKEN_COOKIE];
    if (t) {
      const payload = jwt.verify(t, JWT_SECRET);
      req.user = { email: payload.email };
    }
  } catch {}
  next();
}
app.use(attachUserIfPresent);

function requireAuth(req, res, next){
  try {
    const t = req.cookies?.[TOKEN_COOKIE];
    if (!t) return res.status(401).json({ error: 'Auth required' });
    const payload = jwt.verify(t, JWT_SECRET);
    req.user = { email: payload.email };
    next();
  } catch {
    return res.status(401).json({ error: 'Auth required' });
  }
}

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/health', (_req,res)=> res.json({ ok:true, service:'novust-api' }));

// ── Ask API with prompt tightening + rates injection + guardrails ───────────
const SYSTEM_PROMPT = `
You are a UK chartered tax adviser for tax year 2025/26 unless the user specifies another year.
- Always use current UK thresholds/rates for 2025/26; amounts in GBP (£).
- If the question is missing a total income figure, state the assumption you're making.
- Prefer HMRC terminology. Avoid US rules unless a comparison is requested.
- Respond conversationally, like a friendly accountant.
- Format answers as:
  1) Short answer (1–10 lines),
  2) Calculation / reasoning steps (bullets with numbers),
  3) What to watch out for,
  4) Sources (GOV.UK links).
- End with: "Please note your total income impacts the level of tax on each income stream, please ensure you provide this for a more accurate response".
Do NOT add generic AI disclaimers.
`;

let RATES = {};
try {
  RATES = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/uk_tax_rates_2025_26.json'), 'utf8'));
} catch { RATES = {}; }

const GOLDEN = [
  { role:'user', content:'What is employer NIC on a £40,000 salary in 2025/26?' },
  { role:'assistant', content:'Short answer: approximately £4,635 before any Employment Allowance.\n\n1) Calculation\n- Secondary threshold ~ £9,100 (approx; confirm latest)\n- Employer NIC = (40,000 - 9,100) × 15% = 30,900 × 0.15 = £4,635.\n- Employment Allowance may reduce this by up to £5,000 for eligible employers.\n\nWhat to watch out for\n- Pro-rata for part-year.\n- Check if Employment Allowance applies.\n\nSources\n- https://www.gov.uk/national-insurance-rates-letters\n- https://www.gov.uk/claim-employment-allowance' },

  { role:'user', content:'As a director taking £12,570 salary and £40,000 dividends in 2025/26, what tax will I pay?' },
  { role:'assistant', content:'Short answer: Salary uses the personal allowance; dividends are taxed after the £500 allowance using 2025/26 dividend bands.\n\n1) Steps\n- Salary £12,570 uses personal allowance → no income tax on salary.\n- Dividend allowance £500.\n- Remaining dividends taxed at 8.75% (basic) / 33.75% (higher) depending on total income.\n\nWatchouts\n- Student loan/child benefit if total income is higher.\n\nSources\n- https://www.gov.uk/tax-on-dividends\n- https://www.gov.uk/income-tax-rates' },

  { role:'user', content:'When do I have to register for VAT?' },
  { role:'assistant', content:'Short answer: When taxable turnover exceeds the £90,000 rolling 12-month threshold.\n\n1) Steps\n- Monitor any rolling 12-month period (not the tax year).\n- If you expect to exceed it in the next 30 days, register now.\n\nWatchouts\n- Voluntary registration pros/cons.\n\nSources\n- https://www.gov.uk/vat-registration/when-to-register' },

  { role:'user', content:'What is the Benefit-in-Kind on a new electric company car (0g/km) priced £40,000 in 2025/26?' },
  { role:'assistant', content:'Short answer: Use the 2% BiK band (confirm HMRC table for the year).\n\n1) Steps\n- P11D value £40,000 × 2% = £800 taxable benefit.\n\nWhat to watch out for\n- Scheduled increases in later years.\n\nSources\n- https://www.gov.uk/government/publications/company-car-benefit-in-kind-appropriate-percentages' },

  { role:'user', content:'How do CIS deductions work for a subcontractor?' },
  { role:'assistant', content:'Short answer: Contractors deduct 20% (registered) or 30% (unverified) from labour, not materials.\n\n1) Steps\n- Deduction shown on CIS statements.\n- Offset on Self Assessment tax return.\n\nSources\n- https://www.gov.uk/what-you-must-do-as-a-cis-subcontractor' },

  { role:'user', content:'Capital gains allowance and rates for 2025/26?' },
  { role:'assistant', content:'Short answer: Use the current annual exempt amount and CGT rates by asset type.\n\nWhat to watch out for\n- Residential property surcharge; Business Asset Disposal Relief criteria.\n\nSources\n- https://www.gov.uk/capital-gains-tax' }
];

function postProcess(text){
  text = text.replace(/\b(2024\/25|2024-25)\b/g, '2025/26');             // normalize year
  if (/employer (?:NI|NIC|national insurance)/i.test(text) && /\b13\.8 ?%/i.test(text)) {
    text = text.replace(/\b13\.8 ?%/gi, '15%');                          // defensive NIC fix
  }
  if (!/gov\.uk/i.test(text)) {                                          // ensure sources
    text += `\n\nSources: https://www.gov.uk/national-insurance, https://www.gov.uk/income-tax-rates`;
  }
  return text;
}

app.post('/api/ask', async (req, res) => {
  try {
    const q = String(req.body?.question || '').slice(0, 4000);
    if (!q) return res.status(400).json({ error: 'Question is required' });

    const messages = [
      { role:'system', content: SYSTEM_PROMPT },
      { role:'system', content: `Rates 2025/26 (source of truth):\n${JSON.stringify(RATES)}` },
      ...GOLDEN,
      { role:'user', content: `UK context — ${q}` }
    ];

    let answer = '';
    try {
      const completion = await openai.chat.completions.create({ model: DEFAULT_MODEL, messages });
      answer = completion.choices?.[0]?.message?.content?.trim() || '';
    } catch (err) {
      // Safe fallback if your key doesn't have access to the reasoning tier
      if (String(err).includes('does not exist') || String(err).includes('404')) {
        const fallback = 'gpt-4o-mini';
        const completion = await openai.chat.completions.create({ model: fallback, messages });
        answer = completion.choices?.[0]?.message?.content?.trim() || '';
      } else {
        throw err;
      }
    }

    answer = answer.replace(/\*\*Disclaimer\*\*:.*$/is, '').trim();
    answer = 'Below is the answer you need:\n\n' + postProcess(answer);
    if (!answer.trim()) answer = 'Sorry — I couldn’t generate an answer.';
    return res.json({ answer });
  } catch (err) {
    console.error('[ASK] error:', err.message);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Legacy alias
app.post('/ask', (req,res)=>{ req.url='/api/ask'; return app._router.handle(req,res); });

// ── Log Q&A (captures email if logged in) ────────────────────────────────────
app.post('/log', (req, res) => {
  try {
    const { question, answer } = req.body;
    if (!question || !answer) return res.status(400).json({ error: 'question and answer are required' });
    const email = req.user?.email || null;
    db.prepare('INSERT INTO questions (question, answer, email) VALUES (?,?,?)').run(question, answer, email);
    res.json({ message: 'Log saved' });
  } catch (e) {
    console.error('log error:', e);
    res.status(500).json({ error: 'Failed to save log' });
  }
});

// ── Auth ────────────────────────────────────────────────────────────────────
app.post('/signup', async (req, res) => {
  try {
    const { fname, lname, email, dob, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    const pwHash = await bcrypt.hash(password, 12);
    try {
      userDB.prepare('INSERT INTO users (email, fname, lname, dob, password_hash) VALUES (?,?,?,?,?)')
        .run(email, fname||'', lname||'', dob||'', pwHash);
    } catch (e) {
      if (String(e).includes('UNIQUE')) return res.status(409).json({ success:false, error:'Email already registered' });
      throw e;
    }
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn:'30d' });
    res.cookie(TOKEN_COOKIE, token, { httpOnly:true, secure:isProd, sameSite:isProd?'lax':'lax', maxAge:30*24*3600*1000 });
    res.json({ success:true, message:'Signup successful' });
  } catch (e) { console.error('signup error:', e); res.status(500).json({ error: 'Server error' }); }
});

app.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error:'Email and password are required' });
    const row = userDB.prepare('SELECT email, fname, password_hash FROM users WHERE email=?').get(email);
    if (!row) return res.json({ success:false });
    const ok = bcrypt.compareSync(password, row.password_hash);
    if (!ok) return res.json({ success:false });
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn:'30d' });
    res.cookie(TOKEN_COOKIE, token, { httpOnly:true, secure:isProd, sameSite:isProd?'lax':'lax', maxAge:30*24*3600*1000 });
    res.json({ success:true, fname: row.fname || '' });
  } catch (e) { console.error('login error:', e); res.status(500).json({ error:'Server error' }); }
});

app.post('/logout', (req, res)=>{
  res.clearCookie(TOKEN_COOKIE, { httpOnly:true, secure:isProd, sameSite:isProd?'lax':'lax' });
  res.json({ ok:true });
});

app.post('/update-details', requireAuth, async (req, res) => {
  try {
    const { password, newEmail, newPassword } = req.body;
    const user = userDB.prepare('SELECT email, password_hash FROM users WHERE email=?').get(req.user.email);
    if (!user) return res.status(404).send('Account not found');
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).send('Incorrect password');

    const updates = []; const params = []; let updatedEmail = user.email;
    if (newEmail && newEmail !== user.email) { updates.push('email=?'); params.push(newEmail); updatedEmail = newEmail; }
    if (newPassword) { const hash = await bcrypt.hash(newPassword, 12); updates.push('password_hash=?'); params.push(hash); }
    params.push(user.email);

    if (updates.length) {
      userDB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE email = ?`).run(...params);
      if (newEmail && newEmail !== user.email) db.prepare('UPDATE questions SET email=? WHERE email=?').run(newEmail, user.email);
    }
    if (newEmail && newEmail !== user.email) {
      const token = jwt.sign({ email:newEmail }, JWT_SECRET, { expiresIn:'30d' });
      res.cookie(TOKEN_COOKIE, token, { httpOnly:true, secure:isProd, sameSite:isProd?'lax':'lax', maxAge:30*24*3600*1000 });
    }
    res.send('Update success');
  } catch (e) { console.error('update-details error:', e); res.status(500).send('Server error'); }
});

app.delete('/account', requireAuth, (req, res) => {
  try {
    const email = req.user.email;
    db.prepare('DELETE FROM questions WHERE email=?').run(email);
    userDB.prepare('DELETE FROM users WHERE email=?').run(email);
    res.clearCookie(TOKEN_COOKIE, { httpOnly:true, secure:isProd, sameSite:isProd?'lax':'lax' });
    res.json({ ok:true });
  } catch (e) { res.status(500).json({ error:'Failed to delete account' }); }
});

// ── History & User Info (protected) ─────────────────────────────────────────
app.get('/history', requireAuth, (req, res) => {
  try {
    const rows = db.prepare('SELECT question, answer, timestamp FROM questions WHERE email=? ORDER BY datetime(timestamp) DESC LIMIT 200').all(req.user.email);
    res.json(rows);
  } catch (e) { console.error('history error:', e); res.status(500).json({ error:'Server error' }); }
});

app.get('/user-info', requireAuth, (req, res) => {
  try {
    const row = userDB.prepare('SELECT email, fname, lname FROM users WHERE email=?').get(req.user.email);
    if (!row) return res.status(404).json({ error:'Not found' });
    res.json(row);
  } catch (e) { console.error('user-info error:', e); res.status(500).json({ error:'Server error' }); }
});

// ── News ────────────────────────────────────────────────────────────────────
app.get('/news', async (_req, res) => {
  try {
    const feeds = [
      'https://www.gov.uk/government/organisations/hm-revenue-customs.atom',
      'https://www.icaew.com/rss',
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
      } catch { /* ignore individual feed errors */ }
    }
    all.sort((a,b)=> new Date(b.date||0) - new Date(a.date||0));
    res.json(all.slice(0, 12));
  } catch (e) { res.status(500).json({ error: 'Failed to fetch news' }); }
});

// ── Start ───────────────────────────────────────────────────────────────────
app.use((err, req, res, next)=>{ console.error('🔥 Unhandled error:', err); if (res.headersSent) return next(err); res.status(500).json({ error:'Server error' }); });
app.listen(port, ()=> console.log(`🚀 Server running on http://localhost:${port}`));
