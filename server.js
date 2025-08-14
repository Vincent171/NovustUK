// ─────────────────────────────────────────────────────────────────────────────
// server.js — Novust (secure, RAG-ready, “Novust voice”)
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
const FALLBACK_MODEL = 'gpt-4o-mini';

// ── Email (Resend) — NEW ────────────────────────────────────────────────────
const { Resend } = require('resend');                      // NEW
const resend = new Resend(process.env.RESEND_API_KEY);     // NEW
const MAIL_FROM = process.env.MAIL_FROM || 'Novust <hello@send.novust.co.uk>'; // NEW
const MAIL_TO   = process.env.MAIL_TO   || 'hello@novust.co.uk';               // NEW
const esc = s => String(s||'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); // NEW
async function sendMail({ to, subject, text, html, replyTo }) {  // NEW
  if (!process.env.RESEND_API_KEY) return; // no-op locally if not configured
  await resend.emails.send({
    from: MAIL_FROM,
    to,
    subject,
    text: text || html?.replace(/<[^>]+>/g,''),
    html,
    reply_to: replyTo
  });
}
// simple templates — NEW
const welcomeTpl         = (name) => `<h2>Welcome to Novust${name?`, ${esc(name)}`:''}!</h2><p>Thanks for signing up. You can save history, email answers to yourself and manage your account anytime.</p>`;
const emailChangedOldTpl = (oldE, newE) => `<p>Your Novust login email was changed from <b>${esc(oldE)}</b> to <b>${esc(newE)}</b>.</p><p>If this wasn’t you, reply to this email.</p>`;
const emailChangedNewTpl = (newE) => `<p>Hi ${esc(newE)}, your email has been updated successfully on Novust.</p>`;
const passwordChangedTpl = () => `<p>Your Novust password was changed successfully.</p><p>If this wasn’t you, reply to this email.</p>`;

// ── DBs ─────────────────────────────────────────────────────────────────────
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

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

const ALLOW = (process.env.ALLOW_ORIGINS || 'http://localhost:3000,https://novustuk.netlify.app')
  .split(',').map(s=>s.trim()).filter(Boolean);

app.use(cors({
  origin(origin, cb){
    if (!origin) return cb(null, true);               // allow curl/file://
    const ok = ALLOW.includes(origin);
    cb(ok ? null : new Error('Not allowed by CORS'), ok);
  },
  credentials: true
}));

// Serve static site locally from /docs (harmless on Render)
app.use(express.static(path.join(__dirname, 'docs')));

// ── Auth helpers ────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.NOVUST_JWT_SECRET || 'dev-secret-change-me';
const TOKEN_COOKIE = 'novust_token';

function setAuthCookie(res, payload){
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
  res.cookie(TOKEN_COOKIE, token, {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',  // 'none' so Netlify → Render works
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
  } catch {} // ignore
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

// ── Health ──────────────────────────────────────────────────────────────────
app.get('/health', (_req,res)=> res.json({ ok:true, service:'novust-api' }));
app.get('/health/openai', async (_req,res)=>{
  try { const r = await openai.models.list(); res.json({ ok:true, count:r.data?.length||0 }); }
  catch (e){ res.status(500).json({ ok:false, status:e.status, code:e.code, msg:e.message }); }
});

// ── Prompt, notes (RAG), and style ──────────────────────────────────────────
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

const VOICE_PACK = `
Tone: professional, plain-English, direct; no fluff.
Phrasing: "Note your …", "This means …", "Watch out …".
Formatting: bullets <= 1 line; money like £12,345; show % once.
`;

// Rates (source of truth)
let RATES = {};
try {
  RATES = JSON.parse(fs.readFileSync(path.join(__dirname, 'data/uk_tax_rates_2025_26.json'), 'utf8'));
} catch { RATES = {}; }

// (You can add NOTES/RAG later if you like)

// Recipient greeting (NEW)
function getRecipientName(req){
  try {
    if (!req.user?.email) return null;
    const row = userDB.prepare('SELECT fname FROM users WHERE email=?').get(req.user.email);
    return row?.fname || null;
  } catch { return null; }
}

// Golden exemplars (short + your 3 style samples)
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

  // Your 3 “Daniel” style samples
  { role:'user', content:'Self-employed profit £30,000 — what tax is due for 2025/26?' },
  { role:'assistant', content:
'Hi Daniel,\n\nShort answer: Note your profit is £30,000; expect basic-rate income tax plus Class 4 and Class 2 NI.\n\n\
Steps / calc\n- Income tax: 20% basic rate on taxable profits after allowance (assume full £12,570 unless told otherwise).\n- Class 4 NI: apply current thresholds and rate to £30,000.\n- Class 2 NI: flat weekly amount if applicable (counts towards State Pension).\n\n\
Watch out\n- Bought any capital assets (computer/tools/office furniture)? AIA may give 100% relief and reduce tax.\n- Payments on account: any made last year reduce the balancing payment; new POAs likely if liability > £1,000.\n\n\
Sources\n- https://www.gov.uk/self-employed-national-insurance-rates\n- https://www.gov.uk/capital-allowances/annual-investment-allowance' },

  { role:'user', content:'Employment income plus £30,000 rental profit — how is the rental taxed?' },
  { role:'assistant', content:
'Hi Daniel,\n\nShort answer: Rental is split across bands after your employment income; part at 20% and the rest at 40%, then a 20% mortgage-interest tax credit applies.\n\n\
Steps / calc\n- Combine employment and rental to see how much rental sits in basic vs higher rate.\n- Compute tax at 20%/40%.\n- Apply mortgage interest relief as a tax credit at 20% of allowable interest.\n\n\
Watch out\n- All qualifying mortgage interest counts for the reducer, but relief is capped at 20%.\n\n\
Sources\n- https://www.gov.uk/guidance/changes-to-tax-relief-for-residential-landlords-how-its-worked-out\n- https://www.gov.uk/income-tax-rates' },

  { role:'user', content:'Limited company profit before tax £X — what’s the CT and what filings are needed?' },
  { role:'assistant', content:
'Hi Daniel,\n\nShort answer: If within small profits, CT is 19% (adjust thresholds for associated companies). Tax due 9 months + 1 day after year end.\n\n\
Steps / calc\n- Apply correct CT band (small, main, or marginal) to taxable profits.\n- CT payment due 9m+1d after period end.\n\n\
Watch out\n- File CT600 to HMRC and accounts to Companies House (auth code).\n- Include any business expenses you paid personally; they reduce profit.\n- Capital assets may qualify for AIA.\n\n\
Sources\n- https://www.gov.uk/guidance/corporation-tax-2023\n- https://www.gov.uk/company-filing-and-accounts' }
];

// Post-processor (UPDATED: greet correctly + strip model greeting)
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

// ── Ask API ─────────────────────────────────────────────────────────────────
app.post('/api/ask', async (req, res) => {
  try {
    const q = String(req.body?.question || '').slice(0, 4000);
    if (!q) return res.status(400).json({ error: 'Question is required' });

    const recipientName = getRecipientName(req); // NEW

    const messages = [
      { role:'system', content: SYSTEM_PROMPT },
      { role:'system', content: VOICE_PACK },
      { role:'system', content: `Rates 2025/26 (source of truth):\n${JSON.stringify(RATES)}` },
      // small nudge (we still enforce in postProcess)
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
    answer = 'Below is the answer you need:\n\n' + postProcess(answer, recipientName);

    if (!answer.trim()) answer = 'Sorry — I couldn’t generate an answer.';
    return res.json({ answer });
  } catch (err) {
    console.error('[ASK] error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Legacy alias
app.post('/ask', (req,res)=>{ req.url='/api/ask'; return app._router.handle(req,res); });

// ── Log Q&A ─────────────────────────────────────────────────────────────────
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
    setAuthCookie(res, { email });
    res.json({ success:true, message:'Signup successful' });

    // Welcome email — fire-and-forget
    sendMail({ to: email, subject: 'Welcome to Novust 👋', html: welcomeTpl(fname||'') }).catch(()=>{});
  } catch (e) {
    console.error('signup error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/login', (req, res) => {
  try {
    const { email, password } = req.body;
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
    const { password, newEmail, newPassword } = req.body;
    const user = userDB.prepare('SELECT email, password_hash FROM users WHERE email=?').get(req.user.email);
    if (!user) return res.status(404).send('Account not found');
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).send('Incorrect password');

    const updates = []; const params = []; let updatedEmail = user.email;
    let emailChanged = false, pwChanged = false;

    if (newEmail && newEmail !== user.email) { updates.push('email=?'); params.push(newEmail); updatedEmail = newEmail; emailChanged = true; }
    if (newPassword) { const hash = await bcrypt.hash(newPassword, 12); updates.push('password_hash=?'); params.push(hash); pwChanged = true; }
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
      ]).catch(()=>{});
    }
    if (pwChanged) {
      sendMail({ to: updatedEmail, subject:'Your Novust password was changed', html: passwordChangedTpl() }).catch(()=>{});
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

// ── Email: “Email me this answer” (auth required) ───────────────────────────
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
