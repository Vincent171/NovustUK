// ─────────────────────────────────────────────────────────────────────────────
// server.js — Novust (secure, RAG-ready, “Novust voice”) + Beta Wait List
// ─────────────────────────────────────────────────────────────────────────────

/* ============================== CORE IMPORTS ============================== */
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

/* ============================ OPENAI / LLM CLIENT ========================= */
const { OpenAI } = require('openai');
const effectiveKey = process.env.FORCE_OPENAI_API_KEY || process.env.OPENAI_API_KEY;
const openai = new OpenAI({ apiKey: effectiveKey });
const DEFAULT_MODEL = process.env.NOVUST_MODEL || 'gpt-5-thinking';
const FALLBACK_MODEL = 'gpt-4o-mini';

/* ============================== EMAIL (RESEND) ============================ */
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const MAIL_FROM = process.env.MAIL_FROM || 'Novust <hello@send.novust.co.uk>';
const MAIL_TO   = process.env.MAIL_TO   || 'hello@novust.co.uk'; // optional, not used directly

// HTML escape helper (used in templates)
const esc = s => String(s || '').replace(/[&<>"]/g, c => (
  { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;' }[c]
));

// Logo header used by all emails
const EMAIL_HEADER = `
  <div style="text-align:left;margin:0 0 12px 0;font-family:Arial,Helvetica,sans-serif;font-size:16px;font-weight:bold;">
    <a href="https://novust.co.uk" target="_blank" style="text-decoration:none;color:#0a6cf1;display:block;margin-bottom:6px;">
      <img src="https://novust.co.uk/logo.png"
           alt="Novust" width="140" height="auto"
           style="display:block;height:auto;border:0;outline:none;text-decoration:none"/>
    </a>
    <a href="https://novust.co.uk" target="_blank" style="text-decoration:none;color:#0a6cf1;">
      Novust
    </a>
  </div>
`;





// Email templates (with logo header)
const welcomeTpl         = (name = '') =>
  `${EMAIL_HEADER}<h2>Welcome to Novust${name ? `, ${esc(name)}` : ''}!</h2><p>Thanks for signing up. You can save history, email answers to yourself and manage your account anytime.</p>`;

const emailChangedOldTpl = (oldE, newE) =>
  `${EMAIL_HEADER}<p>Your Novust login email was changed from <b>${esc(oldE)}</b> to <b>${esc(newE)}</b>.</p><p>If this wasn’t you, reply to this email.</p>`;

const emailChangedNewTpl = (newE) =>
  `${EMAIL_HEADER}<p>Hi ${esc(newE)}, your email has been updated successfully on Novust.</p>`;

const passwordChangedTpl = () =>
  `${EMAIL_HEADER}<p>Your Novust password was changed successfully.</p><p>If this wasn’t you, reply to this email.</p>`;

// NEW: wait list confirmation template
const waitlistConfirmTpl = (email) =>
  `${EMAIL_HEADER}<h3>You're on the Beta Wait List</h3><p>Thanks for your interest, <b>${esc(email)}</b>! We’ll notify you as soon as the beta is ready.</p>`;

const resetCodeTpl = (email, code) =>
  `${EMAIL_HEADER}
   <h3>Password reset</h3>
   <p>We received a request to reset your Novust password for <b>${esc(email)}</b>.</p>
   <p><b>Your reset code is: ${esc(code)}</b></p>
   <p>This code will expire in 15 minutes.</p>
   <p>If you didn’t request this, you can ignore this email.</p>`;

/* ============================== STATE FLAGS =============================== */
// Track whether this is the first question since process boot
let firstAnswerServed = false;


/* --------------------------- SENDMAIL IMPLEMENTATION ---------------------- */
async function sendMail({ to, subject, text, html, replyTo }) {
  if (!process.env.RESEND_API_KEY) {
    console.warn('[mail] RESEND_API_KEY not set — skipping send');
    return { ok:false, reason:'no_api_key' };
  }
  try {
    const resp = await resend.emails.send({
      from: MAIL_FROM,
      to,
      subject,
      text: text || html?.replace(/<[^>]+>/g,''),
      html,
      reply_to: replyTo
    });
    console.log('[mail] sent', { id: resp?.id, to, subject });
    return { ok:true, id: resp?.id };
  } catch (e) {
    console.error('[mail] ERROR', {
      name: e?.name,
      message: e?.message,
      status: e?.status,
      data: e?.response?.data || e?.body || null
    });
    throw e;
  }
}

/* ================================ DATABASES =============================== */
const db = new Database(path.join(DATA_DIR, 'questions.db')); // Q&A
const userDB = new Database(path.join(DATA_DIR, 'users.db')); // Users

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

// Password reset codes (6-digit) with expiry
userDB.prepare(`
  CREATE TABLE IF NOT EXISTS password_resets (
    email   TEXT NOT NULL,
    code    TEXT NOT NULL,
    expires DATETIME NOT NULL
  )
`).run();


/* ====================== NEW: BETA WAIT LIST DATABASE ====================== */
// STORAGE: Separate DB for wait list (simple & clean separation)
const waitDB = new Database(path.join(DATA_DIR, 'waitlist.db'));
waitDB.prepare(`
  CREATE TABLE IF NOT EXISTS waitlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    source TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`).run();

/* ================================ MIDDLEWARE ============================== */
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const ALLOW = (process.env.ALLOW_ORIGINS || 'http://localhost:3000,https://novustuk.netlify.app')
  .split(',').map(s=>s.trim()).filter(Boolean);

// CORS with visibility
console.log('[CORS] Allow list:', ALLOW);
app.use((req, res, next) => {
  res.setHeader('Vary', 'Origin');
  next();
});

app.use(cors({
  origin(origin, cb){
    if (!origin) { console.log('[CORS] (no origin) → allow'); return cb(null, true); }
    const ok = ALLOW.includes(origin);
    console.log(`[CORS] Origin: ${origin} → ${ok ? 'ALLOW' : 'BLOCK'}`);
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true
}));

app.use((req, _res, next) => {
  if (req.method === 'OPTIONS') {
    console.log(`[CORS] Preflight for ${req.headers.origin} → ${req.headers['access-control-request-method'] || ''}`);
  }
  next();
});

// Serve static site locally from /docs (harmless on Render)
app.use(express.static(path.join(__dirname, 'docs')));

/* ============================= AUTH HELPERS =============================== */
const JWT_SECRET = process.env.NOVUST_JWT_SECRET || 'dev-secret-change-me';
const TOKEN_COOKIE = 'novust_token';

function logSetCookieContext(email) {
  console.log(`[AUTH] Setting cookie for ${email} | secure=${isProd} sameSite=${isProd ? 'none' : 'lax'}`);
}

function setAuthCookie(res, payload){
  logSetCookieContext(payload.email);
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
  res.cookie(TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    maxAge: 30*24*3600*1000
  });
}

// Attach user if cookie present (so /log captures email)
function attachUserIfPresent(req, _res, next){
  try {
    const t = req.cookies?.[TOKEN_COOKIE];
    if (t) {
      const { email } = jwt.verify(t, JWT_SECRET);
      req.user = { email };
    }
  } catch {}
  next();
}
app.use(attachUserIfPresent);

function requireAuth(req, res, next){
  try {
    const t = req.cookies?.[TOKEN_COOKIE];
    if (!t) return res.status(401).json({ error: 'Auth required' });
    const { email } = jwt.verify(t, JWT_SECRET);
    req.user = { email };
    next();
  } catch {
    return res.status(401).json({ error: 'Auth required' });
  }
}

/* =========================== PASSWORD VALIDATION ========================== */
// Minimum 8 characters, must include at least one number
function validatePassword(pw) {
  return typeof pw === 'string' && /^(?=.*\d).{8,}$/.test(pw);
}

/* ============================== EMAIL NORMALISER ========================== */ // ★ NEW
function normEmail(s) {
  return String(s || '').trim().toLowerCase();
}


/* ================================ HEALTH ================================== */
// CALL ROUTES: Health / Diagnostics
app.get('/health', (_req,res)=> res.json({ ok:true, service:'novust-api' }));
app.get('/health/openai', async (_req,res)=>{
  try { const r = await openai.models.list(); res.json({ ok:true, count:r.data?.length||0 }); }
  catch (e){ res.status(500).json({ ok:false, status:e.status, code:e.code, msg:e.message }); }
});

/* ============================ DEBUG / INTROSPECTION ======================= */
app.get('/debug/cors', (req, res) => {
  const origin = req.headers.origin || null;
  const allowed = origin ? ALLOW.includes(origin) : true;
  const hasToken = !!req.cookies?.[TOKEN_COOKIE];
  res.json({
    now: new Date().toISOString(),
    origin,
    allowed,
    allowList: ALLOW,
    cookieNames: Object.keys(req.cookies || {}),
    hasTokenCookie: hasToken,
    nodeEnv: process.env.NODE_ENV || 'development',
    dataDir: DATA_DIR
  });
});

/* ===================== PROMPTS, VOICE, RATES & LIGHT RAG =================== */
const SYSTEM_PROMPT = `
You are a UK chartered tax adviser for tax year 2025/26 unless the user specifies another year.

Novust client-letter style (copy exactly):
- Start with a brief greeting if a recipient name is provided (e.g. "Hi Daniel,").
- First line: "Note your <topic>: <one-line conclusion>."
- Be concise and practical. Use GBP (£) with commas (e.g., £30,000).
- Use bullets for calculations; break down the tax by component.
- If a key input is missing (e.g., total income), state the assumption in one short line.

Format every answer:
1) Short answer (1–3 lines)
2) Steps / calc (3–6 bullets with numbers and one formula if needed)
3) Watch out (2–5 bullets)
4) Sources (at least one GOV.UK link)

House rules:
- Default to 2025/26 rates unless user names a different year (then say so and use it).
- Prefer HMRC terminology; avoid US rules unless asked to compare.
- Essentials to consider:
  • Self-employed: ask about assets for AIA, note Class 2 NI counts towards State Pension, check Payments on Account.
  • Rental: mention mortgage-interest tax credit at 20%; all interest is allowable for the reducer but relief capped at 20%.
  • Limited company: CT due 9m+1d; CT600 to HMRC; accounts to Companies House (auth code); personal expenses paid on behalf can be claimed.

Close with: "Please note your total income impacts the level of tax on each income stream, please ensure you provide this for a more accurate response".
Do NOT add generic AI disclaimers.
`;

/* ------------ VOICE PACK (REPLACED with the upgraded version) ------------- */
const VOICE_PACK = `
Tone: friendly, concise, and professional; sound like a human adviser.
Open with one short, personal line using their first name if provided.
Always give a one-line conclusion first ("Note your …: …").
Prefer bullets and short sentences. Show £ with commas, % once.
Ask for one missing key input if it blocks accuracy.
Avoid filler like "as an AI" or generic disclaimers.
`;

/* -------------------- SYSTEM_FORMAT (NEW: enforce layout) ------------------ */
const SYSTEM_FORMAT = `
Format:
1) Short answer (1–2 lines, no hedging; start with "Note your …: …")
2) What this means for you (3–6 bullets; include quick numbers)
3) Next steps (2–4 bullets; practical)
4) Sources (at least one GOV.UK link; show as full URLs)
`;

// Rates (source of truth)
let RATES = {};
try {
  RATES = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/uk_tax_rates_2025_26.json'), 'utf8'));
} catch { RATES = {}; }

/* ---------------------- LIGHTWEIGHT RAG: FAQ NOTES (NEW) ------------------ */
const NOTES_PATH = path.join(DATA_DIR, 'data/notes_faq_uk_tax.json');
function loadNotes() {
  try {
    const raw = fs.readFileSync(NOTES_PATH, 'utf8');
    const json = JSON.parse(raw);
    const arr = Array.isArray(json) ? json : [];
    return arr
      .map(n => {
        if (typeof n === 'string') return n;
        if (n == null || typeof n !== 'object') return null;
        return n.short || n.note || n.fact || n.title || n.text || null;
      })
      .filter(Boolean)
      .slice(0, 15);
  } catch {
    return [];
  }
}
const NOTES_LITE = loadNotes(); // loaded once at boot; hot-reload if you prefer

/* ---------------------- PERSONALISATION (GREETING NAME) ------------------- */
function getRecipientName(req){
  try {
    if (!req.user?.email) return null;
    const row = userDB.prepare('SELECT fname FROM users WHERE email=?').get(req.user.email);
    return row?.fname || null;
  } catch { return null; }
}

/* -------------------------- GOLDEN EXEMPLARS (KEPT) ----------------------- */
const GOLDEN = [
  { role:'user', content:'What is employer NIC on a £40,000 salary in 2025/26?' },
  { role:'assistant', content:
'Short answer: Employer NIC ≈ £4,635 before any Employment Allowance.\n\n\
Steps / calc\n- Secondary threshold ~ £9,100 (confirm current).\n- (40,000 − 9,100) × 15% = £30,900 × 0.15 = £4,635.\n- Employment Allowance may reduce liability by up to £5,000.\n\n\
Watch out\n- Pro-rata for part-year.\n\n\
Sources\n- https://www.gov.uk/national-insurance-rates-letters\n- https://www.gov.uk/claim-employment-allowance' },

  { role:'user', content:'As a director taking £12,570 salary and £40,000 dividends in 2025/26, what tax will I pay?' },
  { role:'assistant', content:
'Short answer: Salary covered by allowance; dividends taxed after £500 allowance using 2025/26 bands.\n\n\
Steps / calc\n- Salary £12,570 uses personal allowance → no income tax on salary.\n- £500 dividend allowance.\n- Remaining dividends at 8.75%/33.75% depending on total income.\n\n\
Watch out\n- Student loan and child benefit if income higher.\n\n\
Sources\n- https://www.gov.uk/tax-on-dividends\n- https://www.gov.uk/income-tax-rates' },

  { role:'user', content:'When do I have to register for VAT?' },
  { role:'assistant', content:
'Short answer: When taxable turnover exceeds £90,000 in any rolling 12-month period, or if it will in the next 30 days.\n\n\
Steps / calc\n- Monitor rolling 12 months (not tax year).\n\n\
Watch out\n- Flat Rate vs Standard; voluntary registration pros/cons.\n\n\
Sources\n- https://www.gov.uk/vat-registration/when-to-register' },

  // … (remaining exemplars kept as in your file)
];

/* =============================== POST-PROCESS ============================== */
// PUSH FUNCTIONS: answer massaging
function postProcess(text, recipientName){
  // strip any leading "Hi <name>,"
  text = text.replace(/^\s*hi\s+[a-z' -]+,\s*\n*/i, '');

  // normalize year mentions
  text = text.replace(/\b(2024\/25|2024-25)\b/g, '2025/26');

  // defensive NIC fix
  if (/employer (?:NI|NIC|national insurance)/i.test(text) && /\b13\.8 ?%/i.test(text)) {
    text = text.replace(/\b13\.8 ?%/gi, '15%');
  }

  // prepend our greeting
  const name = (recipientName && String(recipientName).trim()) ? String(recipientName).trim() : 'there';
  text = `Hi ${name},\n\n` + text;

  // ensure at least one GOV.UK source
  if (!/gov\.uk/i.test(text)) {
    text += `\n\nSources\n- https://www.gov.uk/`;
  }
  return text.trim();
}

/* ================================== API =================================== */
// CALL ROUTES: /api/ask (LLM) + legacy alias
app.post('/api/ask', async (req, res) => {
  try {
    const q = String(req.body?.question || '').slice(0, 4000);
    if (!q) return res.status(400).json({ error: 'Question is required' });

    const recipientName = getRecipientName(req); // personalise greeting

    // === MESSAGE STACK (ORDER MATTERS) ===
    const messages = [
      { role:'system', content: SYSTEM_PROMPT },
      { role:'system', content: VOICE_PACK },
      { role:'system', content: SYSTEM_FORMAT },                               // NEW: enforce final layout
      { role:'system', content: `Rates 2025/26 (source of truth):\n${JSON.stringify(RATES)}` },

      // RAG — short facts to ground the model's bullets
      { role:'system', content: `Reference notes (short facts):\n${JSON.stringify(NOTES_LITE)}` }, // NEW
      { role:'system', content: 'When certain, paraphrase the relevant note inline in the bullets. Do not paste JSON. If a note conflicts with GOV.UK, prefer GOV.UK.' }, // NEW

      // Small greeting nudge (post-processor still enforces)
      { role:'system', content: `Begin with "Hi ${recipientName || 'there'}," then answer as instructed.` },

      ...GOLDEN,
      { role:'user', content: `UK context — ${q}` }
    ];

    let answer = '';
    try {
      const r = await openai.chat.completions.create({ model: DEFAULT_MODEL, messages });
      answer = r.choices?.[0]?.message?.content?.trim() || '';
    } catch (e) {
      if (String(e).includes('does not exist') || e?.status === 404) {
        const r2 = await openai.chat.completions.create({ model: FALLBACK_MODEL, messages });
        answer = r2.choices?.[0]?.message?.content?.trim() || '';
      } else {
        throw e;
      }
    }

    // Remove any generic disclaimer
    answer = answer.replace(/\*\*Disclaimer\*\*:.*$/is, '').trim();

    // Intro + post-process (adds greeting correctly)
// Only show long intro once per server process (first Q after page load)
if (!firstAnswerServed) {
  answer = 'Thanks for choosing me to help. I am a working model for testing purposes only right now. Exciting news however, the team behind me are working hard to update me to provide a more tailored and individual response as an actual boring accountant in the future, well not that exciting but is to me.\n\nFor now below is the answer you need:\n\n' 
         + postProcess(answer, recipientName);
  firstAnswerServed = true;
} else {
  answer = 'Novust Model Version - Alpha 1.6.4\n\n' + postProcess(answer, recipientName);
}

    if (!answer.trim()) answer = 'Sorry — I couldn’t generate an answer.';
    return res.json({ answer });
  } catch (err) {
    console.error('[ASK] error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Legacy alias
app.post('/ask', (req,res)=>{ req.url='/api/ask'; return app._router.handle(req,res); });

/* ============================= LOGGING / HISTORY ========================== */
// CALL ROUTES: Save Q&A log (optional auth; attaches email if present)
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

/* ================================== AUTH ================================== */
// CALL ROUTES: Signup / Login / Logout / Update details / Delete account
app.post('/signup', async (req, res) => {
  try {
    const { fname, lname, email:rawEmail, dob, password } = req.body; // ★ normalise
    const email = normEmail(rawEmail); // ★
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
    if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters and include a number.' });
    }

    const pwHash = await bcrypt.hash(password, 12);
    try {
      userDB.prepare('INSERT INTO users (email, fname, lname, dob, password_hash) VALUES (?,?,?,?,?)')
        .run(email, fname||'', lname||'', dob||'', pwHash); // ★ email
    } catch (e) {
      if (String(e).includes('UNIQUE')) return res.status(409).json({ success:false, error:'Email already registered' });
      throw e;
    }
    setAuthCookie(res, { email }); // ★ email
    res.json({ success:true, message:'Signup successful' });

    // Welcome email — fire-and-forget
    sendMail({ to: email, subject: 'Welcome to Novust 👋', html: welcomeTpl(fname||'') }).catch(err => console.error('[mail] send failed', err));
  } catch (e) {
    console.error('signup error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', (req, res) => {
  try {
    const email = normEmail(req.body?.email); // ★
    const password = req.body?.password;      // ★
    if (!email || !password) return res.status(400).json({ error:'Email and password are required' });
    const row = userDB.prepare('SELECT email, fname, password_hash FROM users WHERE email=?').get(email);
    if (!row) return res.json({ success:false });
    const ok = bcrypt.compareSync(password, row.password_hash);
    if (!ok) return res.json({ success:false });
    setAuthCookie(res, { email });
    res.json({ success:true, fname: row.fname || '' });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error:'Server error' });
  }
});

app.post('/logout', (req, res)=>{
  res.clearCookie(TOKEN_COOKIE, { httpOnly:true, secure:isProd, sameSite: isProd ? 'none' : 'lax' });
  res.json({ ok:true });
});

app.post('/update-details', requireAuth, async (req, res) => {
  try {
    const password = req.body?.password;
    const newEmail = normEmail(req.body?.newEmail || ''); // ★
    const newPassword = req.body?.newPassword;

    const user = userDB.prepare('SELECT email, password_hash FROM users WHERE email=?').get(req.user.email);
    if (!user) return res.status(404).send('Account not found');
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).send('Incorrect password');

    const updates = []; const params = []; let updatedEmail = user.email;
    let emailChanged = false, pwChanged = false;

    if (newEmail && newEmail !== user.email) { updates.push('email=?'); params.push(newEmail); updatedEmail = newEmail; emailChanged = true; }
    if (newPassword) {
      if (!validatePassword(newPassword)) {
      return res.status(400).send('New password must be at least 8 characters and include a number.');
    }
    const hash = await bcrypt.hash(newPassword, 12);
    updates.push('password_hash=?'); params.push(hash); pwChanged = true;
    }

    params.push(user.email);

    if (updates.length) {
      userDB.prepare(`UPDATE users SET ${updates.join(', ')} WHERE email = ?`).run(...params);
      if (emailChanged) db.prepare('UPDATE questions SET email=? WHERE email=?').run(newEmail, user.email);
    }

    if (emailChanged) {
      setAuthCookie(res, { email: updatedEmail });
      Promise.allSettled([
        sendMail({ to: user.email,  subject:'Your Novust email was changed', html: emailChangedOldTpl(user.email, updatedEmail) }),
        sendMail({ to: updatedEmail, subject:'Your Novust email is updated', html: emailChangedNewTpl(updatedEmail) })
      ]).catch(err => console.error('[mail] send failed', err));
    }

    if (pwChanged) {
      sendMail({ to: updatedEmail, subject:'Your Novust password was changed', html: passwordChangedTpl() })
        .catch(err => console.error('[mail] send failed', err));
    }

    res.send('Update success');
  } catch (e) {
    console.error('update-details error:', e);
    res.status(500).send('Server error');
  }
});

app.delete('/account', requireAuth, (req, res) => {
  try {
    const email = req.user.email;
    db.prepare('DELETE FROM questions WHERE email=?').run(email);
    userDB.prepare('DELETE FROM users WHERE email=?').run(email);
    res.clearCookie(TOKEN_COOKIE, { httpOnly:true, secure:isProd, sameSite: isProd ? 'none' : 'lax' });
    res.json({ ok:true });
  } catch (e) {
    res.status(500).json({ error:'Failed to delete account' });
  }
});

// CALL ROUTES: Request password reset code (logged-out OK)
app.post('/auth/forgot', async (req, res) => {
  try {
    const email = normEmail(req.body?.email || ''); // ★
    if (!email) return res.status(400).json({ ok:false, error: 'Email is required' });

    // Only proceed if user exists (avoid enumeration in response content)
    const exists = userDB.prepare('SELECT 1 FROM users WHERE email=?').get(email);
    if (exists) {
      // purge expired (housekeeping) ★
      userDB.prepare('DELETE FROM password_resets WHERE expires < ?').run(new Date().toISOString());

      const code = String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
      const expires = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      // Clear any prior codes for this email
      userDB.prepare('DELETE FROM password_resets WHERE email=?').run(email);
      userDB.prepare('INSERT INTO password_resets (email, code, expires) VALUES (?,?,?)').run(email, code, expires);

      // fire-and-forget email
      sendMail({
        to: email,
        subject: 'Your Novust password reset code',
        html: resetCodeTpl(email, code)
      }).catch(err => console.error('[mail] reset code send failed', err));
    }
    // Always say OK to avoid email enumeration
    return res.json({ ok:true });
  } catch (e) {
    console.error('/auth/forgot error', e);
    return res.status(500).json({ ok:false, error:'Server error' });
  }
});

// CALL ROUTES: Complete password reset (logged-out OK)
// Body: { email, code, newPassword }
app.post('/auth/reset', async (req, res) => {
  try {
    const email = normEmail(req.body?.email || ''); // ★
    const code = String(req.body?.code || '').trim();
    const newPassword = String(req.body?.newPassword || '');

    if (!email || !code || !newPassword) {
      return res.status(400).json({ ok:false, error: 'Email, code and new password are required' });
    }
    if (!validatePassword(newPassword)) {
      return res.status(400).json({ ok:false, error: 'Password must be at least 8 characters and include a number.' });
    }

    const row = userDB.prepare('SELECT expires FROM password_resets WHERE email=? AND code=?').get(email, code);
    if (!row) return res.status(400).json({ ok:false, error: 'Invalid code' });
    if (new Date(row.expires).getTime() < Date.now()) {
      userDB.prepare('DELETE FROM password_resets WHERE email=?').run(email);
      return res.status(400).json({ ok:false, error: 'Code expired' });
    }

    const hash = await bcrypt.hash(newPassword, 12);
    userDB.prepare('UPDATE users SET password_hash=? WHERE email=?').run(hash, email);
    userDB.prepare('DELETE FROM password_resets WHERE email=?').run(email);

    // Notify user
    sendMail({ to: email, subject: 'Your Novust password was changed', html: passwordChangedTpl() })
      .catch(err => console.error('[mail] send failed', err));

    return res.json({ ok:true });
  } catch (e) {
    console.error('/auth/reset error', e);
    return res.status(500).json({ ok:false, error:'Server error' });
  }
});



/* ============================ PROTECTED DATA APIS ========================= */
// CALL ROUTES: History & User Info
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

/* ============================ “EMAIL ME ANSWER” =========================== */
// CALL ROUTES: Email the current answer to the logged-in user
app.post('/email/me-answer', requireAuth, async (req, res) => {
  try {
    const { question='', answer='' } = req.body || {};
    if (!answer.trim()) return res.status(400).json({ error: 'answer required' });
    const html = `
      <p><b>Your question</b></p>
      <pre style="white-space:pre-wrap;font-family:Inter,Arial,system-ui">${esc(question)}</pre>
      <hr style="border:none;border-top:1px solid #eee;margin:12px 0">
      <p><b>Novust answer</b></p>
      <pre style="white-space:pre-wrap;font-family:Inter,Arial,system-ui">${esc(answer)}</pre>
    `;
    await sendMail({ to: req.user.email, subject: 'Your Novust answer', html });
    res.json({ ok:true });
  } catch (e) {
    console.error('email/me-answer', e);
    res.status(500).json({ error: 'send failed' });
  }
});

/* ============================== BETA WAIT LIST ============================ */
// CALL ROUTES: Add email to Beta Wait List (logged-in OR logged-out)
// Body: { email: string, source?: string }
app.post('/beta-waitlist', async (req, res) => {
  try {
    const bodyEmail = normEmail(req.body?.email || '');     // ★
    const userEmail = normEmail(req.user?.email || '');     // ★
    const email = bodyEmail || userEmail || '';             // ★
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok:false, error:'Valid email is required' });
    }
    const source = (req.body?.source || 'answer_blurb').slice(0, 80);

    waitDB.prepare('INSERT INTO waitlist (email, source) VALUES (?, ?)').run(email, source);

    // Fire-and-forget confirmation (if configured)
    sendMail({
      to: email,
      subject: 'Novust Beta — You’re on the Wait List',
      html: waitlistConfirmTpl(email)
    }).catch(err => console.error('[mail] waitlist send failed', err));

    res.json({ ok:true });
  } catch (e) {
    console.error('waitlist error:', e);
    res.status(500).json({ ok:false, error:'Server error' });
  }
});

/* ================================= NEWS =================================== */
// CALL ROUTES: Aggregated RSS news
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

/* =============================== DEBUG MAIL =============================== */
// CALL ROUTES: Debugging email setup
app.get('/debug/mail-status', (req, res) => {
  const key = process.env.RESEND_API_KEY || '';
  res.json({
    hasKey: !!key,
    keyPreview: key ? key.slice(0,6) + '…' + key.slice(-4) : null,
    from: MAIL_FROM,
    to: MAIL_TO,
    nodeEnv: process.env.NODE_ENV || 'development'
  });
});

app.get('/debug/test-mail', async (req, res) => {
  try {
    const to = req.query.to || MAIL_TO;
    const r = await sendMail({
      to,
      subject: 'Novust debug email',
      html: '<p>If you can read this, Render → Resend works.</p>'
    });
    res.json({ ok:true, result:r });
  } catch (e) {
    res.status(500).json({
      ok:false,
      error: e?.message,
      data: e?.response?.data || e?.body || null
    });
  }
});

/* ================================ STARTUP ================================ */
app.use((err, req, res, next)=>{ console.error('🔥 Unhandled error:', err); if (res.headersSent) return next(err); res.status(500).json({ error:'Server error' }); });
app.listen(port, ()=> console.log(`🚀 Server running on http://localhost:${port}`));
