/**
 * Nex API — single-file backend for Render
 * Start: node nex-server.js | Health: GET /health
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const nodemailer = require('nodemailer');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const emptyDb = () => ({
  users: {}, emails: {}, usernames: {}, otps: {}, ledger: [], gifts: {},
});

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(emptyDb(), null, 2));
}
function load() {
  ensureDb();
  try { return JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch { return emptyDb(); }
}
function save(db) {
  ensureDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}
function balanceOf(db, userId) {
  return db.ledger.filter((e) => e.userId === userId).reduce((s, e) => s + e.delta, 0);
}

let transporter = null;
function getTransporter() {
  if (transporter) return transporter;
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST) return null;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: Number(SMTP_PORT) === 465,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
  });
  return transporter;
}
async function sendOtp(email, code) {
  const from = process.env.MAIL_FROM || 'Nex <noreply@nex.app>';
  const text = `Ваш код Nex: ${code}\nДействует 10 минут.`;
  const html = `<div style="font-family:sans-serif"><h2 style="color:#2AABEE">Nex</h2>
    <p>Код:</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${code}</p>
    <p style="color:#666;font-size:13px">10 минут</p></div>`;
  const tx = getTransporter();
  if (!tx) {
    console.log(`[Nex mail:dev] OTP for ${email}: ${code}`);
    return { dev: true, code };
  }
  await tx.sendMail({ from, to: email, subject: 'Код входа в Nex', text, html });
  return { sent: true };
}

const normEmail = (e) => String(e || '').trim().toLowerCase();
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const validUsername = (u) => /^[a-z0-9_]{3,24}$/.test(u);

function publicUser(u, balance) {
  return { id: u.id, name: u.name, username: u.username, createdAt: u.createdAt, balance };
}
function mePayload(u, balance) {
  return { ...publicUser(u, balance), email: u.email, emailHidden: true };
}
function signToken(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'unauthorized' });
  try {
    req.userId = jwt.verify(token, JWT_SECRET).sub;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '256kb' }));

app.get('/health', (_req, res) => res.json({ ok: true, service: 'nex', ts: Date.now() }));
app.get('/', (_req, res) => res.json({ name: 'Nex API', version: '1.0.0', health: '/health' }));

app.post('/auth/email', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    if (!validEmail(email)) return res.status(400).json({ error: 'invalid_email' });
    const code = String(crypto.randomInt(100000, 999999));
    const hash = await bcrypt.hash(code, 8);
    const db = load();
    db.otps[email] = { hash, exp: Date.now() + OTP_TTL_MS, attempts: 0 };
    save(db);
    const result = await sendOtp(email, code);
    const out = { ok: true, expiresIn: OTP_TTL_MS / 1000 };
    if (result.dev && process.env.NODE_ENV !== 'production') out.devCode = code;
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/verify', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    const code = String(req.body.code || '');
    if (!validEmail(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const db = load();
    const otp = db.otps[email];
    if (!otp) return res.status(400).json({ error: 'otp_not_found' });
    if (Date.now() > otp.exp) return res.status(400).json({ error: 'otp_expired' });
    if (otp.attempts >= OTP_MAX_ATTEMPTS) return res.status(429).json({ error: 'otp_locked' });
    otp.attempts += 1;
    const ok = await bcrypt.compare(code, otp.hash);
    if (!ok) {
      save(db);
      return res.status(400).json({ error: 'otp_invalid' });
    }
    delete db.otps[email];

    let userId = db.emails[email];
    let user = userId ? db.users[userId] : null;
    if (!user) {
      userId = nanoid(12);
      const base = email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16) || 'user';
      let username = base;
      let n = 0;
      while (db.usernames[username]) {
        n += 1;
        username = `${base}${n}`.slice(0, 24);
      }
      user = { id: userId, email, name: base, username, createdAt: Date.now() };
      db.users[userId] = user;
      db.emails[email] = userId;
      db.usernames[username] = userId;
      db.gifts[userId] = [];
    }
    save(db);
    res.json({ token: signToken(userId), user: mePayload(user, balanceOf(db, userId)) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/me', auth, (req, res) => {
  const db = load();
  const u = db.users[req.userId];
  if (!u) return res.status(404).json({ error: 'not_found' });
  res.json(mePayload(u, balanceOf(db, req.userId)));
});

app.patch('/me', auth, (req, res) => {
  const db = load();
  const u = db.users[req.userId];
  if (!u) return res.status(404).json({ error: 'not_found' });
  if (req.body.name != null) {
    const n = String(req.body.name).trim();
    if (n.length < 2 || n.length > 32) return res.status(400).json({ error: 'invalid_name' });
    u.name = n;
  }
  if (req.body.username != null) {
    const un = String(req.body.username).trim().toLowerCase();
    if (!validUsername(un)) return res.status(400).json({ error: 'invalid_username' });
    const taken = db.usernames[un];
    if (taken && taken !== req.userId) return res.status(409).json({ error: 'username_taken' });
    delete db.usernames[u.username];
    u.username = un;
    db.usernames[un] = req.userId;
  }
  save(db);
  res.json(mePayload(u, balanceOf(db, req.userId)));
});

app.get('/users/search', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/^@/, '').trim();
  if (q.length < 2) return res.json({ users: [] });
  const db = load();
  const users = Object.values(db.users)
    .filter((u) => u.username.includes(q) || u.name.toLowerCase().includes(q))
    .slice(0, 20)
    .map((u) => publicUser(u, undefined));
  res.json({ users });
});

app.get('/users/:username', auth, (req, res) => {
  const db = load();
  const id = db.usernames[String(req.params.username || '').toLowerCase()];
  if (!id) return res.status(404).json({ error: 'not_found' });
  res.json(publicUser(db.users[id], undefined));
});

app.get('/wallet', auth, (req, res) => {
  res.json({ balance: balanceOf(load(), req.userId) });
});

app.get('/wallet/ledger', auth, (req, res) => {
  const db = load();
  const entries = db.ledger.filter((e) => e.userId === req.userId).slice(-50).reverse();
  res.json({ entries });
});

app.post('/wallet/topup-test', auth, (req, res) => {
  const delta = Math.min(Math.max(Number(req.body.amount) || 500, 1), 500);
  const db = load();
  if (!db.users[req.userId]) return res.status(404).json({ error: 'not_found' });
  const recent = db.ledger.filter((e) => e.userId === req.userId && e.reason === 'test_topup').slice(-1)[0];
  if (recent && Date.now() - recent.ts < 10000) return res.status(429).json({ error: 'rate_limited' });
  const entry = { id: nanoid(10), userId: req.userId, delta, reason: 'test_topup', ts: Date.now() };
  db.ledger.push(entry);
  save(db);
  res.json({ balance: balanceOf(db, req.userId), entry });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'server_error' });
});

app.listen(PORT, () => {
  console.log(`Nex API on :${PORT}`);
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET === 'dev-secret-change-me') {
    console.warn('[warn] Set JWT_SECRET in production');
  }

  // Self-ping every 10 min — uses Render's RENDER_EXTERNAL_URL when available
  const selfBase = process.env.RENDER_EXTERNAL_URL || process.env.SELF_URL || '';
  if (selfBase) {
    const pingUrl = selfBase.replace(/\/$/, '') + '/health';
    console.log('[self-ping] enabled →', pingUrl);
    setInterval(async () => {
      try {
        const r = await fetch(pingUrl, { signal: AbortSignal.timeout(10000) });
        console.log('[self-ping]', r.status);
      } catch (e) {
        console.log('[self-ping] fail', e.message);
      }
    }, 10 * 60 * 1000);
  } else {
    console.log('[self-ping] skipped (no RENDER_EXTERNAL_URL / SELF_URL)');
  }
});
