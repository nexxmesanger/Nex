
/**
 * Nex API — backend for Render
 * Start: node nex-server.js
 * Health: GET /health
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
  users: {},
  emails: {},
  usernames: {},
  otps: {},
  ledger: [],
  gifts: {},
  numbers: {},
  numOtps: {},
  msgs: [],
  seq: 0,
});

function fill(db) {
  const e = emptyDb();
  for (const k of Object.keys(e)) if (db[k] == null) db[k] = e[k];
  return db;
}

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(emptyDb(), null, 2)
    );
  }
}

function load() {
  ensureDb();

  try {
    return fill(JSON.parse(fs.readFileSync(DB_FILE, 'utf8')));
  } catch {
    return emptyDb();
  }
}

function save(db) {
  ensureDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function balanceOf(db, userId) {
  return db.ledger
    .filter((e) => e.userId === userId)
    .reduce((sum, e) => sum + e.delta, 0);
}

// ==========================================
// EMAIL
// ==========================================

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;

  const {
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
  } = process.env;

  if (!SMTP_HOST) return null;

  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(SMTP_PORT || 587),
    secure: Number(SMTP_PORT) === 465,
    auth: SMTP_USER
      ? {
          user: SMTP_USER,
          pass: SMTP_PASS,
        }
      : undefined,
  });

  return transporter;
}

async function sendOtp(email, code) {
  const from =
    process.env.MAIL_FROM || 'Nex <noreply@nex.app>';

  const subject = 'Your Nex verification code';

  const text =
    `Your Nex verification code is: ${code}\n\n` +
    'This code expires in 10 minutes.';

  const html = `
    <div style="
      font-family:Arial,sans-serif;
      max-width:480px;
      margin:auto;
      padding:24px;
      color:#222;
    ">
      <h2 style="color:#2AABEE">Nex</h2>

      <p>Your verification code:</p>

      <div style="
        font-size:32px;
        font-weight:bold;
        letter-spacing:8px;
        padding:16px 0;
      ">
        ${code}
      </div>

      <p style="color:#777;font-size:13px">
        This code expires in 10 minutes.
      </p>

      <p style="color:#999;font-size:12px">
        If you did not request this code, ignore this email.
      </p>
    </div>
  `;

  // 1. RESEND
  if (process.env.RESEND_API_KEY) {
    const response = await fetch(
      'https://api.resend.com/emails',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from,
          to: [email],
          subject,
          text,
          html,
        }),
        signal: AbortSignal.timeout(15000),
      }
    );

    if (!response.ok) {
      const error = await response.text();

      console.error(
        'Resend error:',
        response.status,
        error.slice(0, 500)
      );

      throw new Error('Email delivery failed');
    }

    const result = await response.json();

    console.log('[Nex mail] Sent through Resend');

    return {
      sent: true,
      provider: 'resend',
      messageId: result.id,
    };
  }

  // 2. SMTP FALLBACK
  const tx = getTransporter();

  if (tx) {
    await tx.sendMail({
      from,
      to: email,
      subject,
      text,
      html,
    });

    console.log('[Nex mail] Sent through SMTP');

    return {
      sent: true,
      provider: 'smtp',
    };
  }

  // 3. LOCAL DEVELOPMENT ONLY
  if (process.env.NODE_ENV !== 'production') {
    console.log(`[Nex mail:dev] OTP for ${email}: ${code}`);

    return {
      dev: true,
      code,
    };
  }

  // 4. PRODUCTION WITHOUT EMAIL PROVIDER
  throw new Error('Email provider is not configured');
}

// ==========================================
// VALIDATION
// ==========================================

const normEmail = (e) =>
  String(e || '').trim().toLowerCase();

const validEmail = (e) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

const validUsername = (u) =>
  /^[a-z0-9_]{3,24}$/.test(u);

// ==========================================
// USERS
// ==========================================

function publicUser(u, balance) {
  return {
    id: u.id,
    name: u.name,
    username: u.username,
    createdAt: u.createdAt,
    balance,
  };
}

function mePayload(u, balance) {
  const db = load();
  return {
    ...publicUser(u, balance),
    email: u.email,
    emailHidden: true,
    guest: !!u.guest,
    exp: u.exp || null,
    numbers: numList(u),
    gifts: db.gifts[u.id] || [],
  };
}

// ==========================================
// JWT AUTH
// ==========================================

function signToken(userId) {
  return jwt.sign(
    { sub: userId },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';

  const token = h.startsWith('Bearer ')
    ? h.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      error: 'unauthorized',
    });
  }

  try {
    req.userId = jwt.verify(token, JWT_SECRET).sub;
    next();
  } catch {
    return res.status(401).json({
      error: 'invalid_token',
    });
  }
}

// ==========================================
// EXPRESS
// ==========================================

const app = express();

app.use(cors({
  origin: true,
  credentials: true,
}));

app.use(express.json({
  limit: '256kb',
}));

// ==========================================
// HEALTH
// ==========================================

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'nex',
    ts: Date.now(),
  });
});

app.get('/', (_req, res) => {
  res.json({
    name: 'Nex API',
    version: '1.0.0',
    health: '/health',
  });
});

// ==========================================
// AUTH: REQUEST EMAIL CODE
// ==========================================

app.post('/auth/email', async (req, res) => {
  try {
    const email = normEmail(req.body.email);

    if (!validEmail(email)) {
      return res.status(400).json({
        error: 'invalid_email',
      });
    }

    const code = String(
      crypto.randomInt(100000, 999999)
    );

    const hash = await bcrypt.hash(code, 8);

    const db = load();

    db.otps[email] = {
      hash,
      exp: Date.now() + OTP_TTL_MS,
      attempts: 0,
    };

    save(db);

    const result = await sendOtp(email, code);

    const out = {
      ok: true,
      expiresIn: OTP_TTL_MS / 1000,
    };

    if (
      result.dev &&
      process.env.NODE_ENV !== 'production'
    ) {
      out.devCode = code;
    }

    res.json(out);

  } catch (e) {
    console.error('[auth/email]', e);

    res.status(500).json({
      error: 'server_error',
    });
  }
});

// ==========================================
// AUTH: VERIFY EMAIL CODE
// ==========================================

app.post('/auth/verify', async (req, res) => {
  try {
    const email = normEmail(req.body.email);
    const code = String(req.body.code || '');

    if (
      !validEmail(email) ||
      !/^\d{6}$/.test(code)
    ) {
      return res.status(400).json({
        error: 'invalid_request',
      });
    }

    const db = load();
    const otp = db.otps[email];

    if (!otp) {
      return res.status(400).json({
        error: 'otp_not_found',
      });
    }

    if (Date.now() > otp.exp) {
      delete db.otps[email];
      save(db);

      return res.status(400).json({
        error: 'otp_expired',
      });
    }

    if (otp.attempts >= OTP_MAX_ATTEMPTS) {
      return res.status(429).json({
        error: 'otp_locked',
      });
    }

    otp.attempts += 1;

    const ok = await bcrypt.compare(
      code,
      otp.hash
    );

    if (!ok) {
      save(db);

      return res.status(400).json({
        error: 'otp_invalid',
      });
    }

    delete db.otps[email];

    let userId = db.emails[email];

    let user = userId
      ? db.users[userId]
      : null;

    if (!user) {
      userId = nanoid(12);

      const base = email
        .split('@')[0]
        .toLowerCase()
        .replace(/[^a-z0-9_]/g, '')
        .slice(0, 16) || 'user';

      let username = base;
      let n = 0;

      while (db.usernames[username]) {
        n += 1;
        username = `${base}${n}`.slice(0, 24);
      }

      user = {
        id: userId,
        email,
        name: base,
        username,
        createdAt: Date.now(),
      };

      db.users[userId] = user;
      db.emails[email] = userId;
      db.usernames[username] = userId;
      db.gifts[userId] = [];
      svcMsg(db, userId, 'Добро пожаловать в Nex! Сюда приходят коды входа и уведомления.');
    }

    save(db);

    res.json({
      token: signToken(userId),
      user: mePayload(
        user,
        balanceOf(db, userId)
      ),
    });

  } catch (e) {
    console.error('[auth/verify]', e);

    res.status(500).json({
      error: 'server_error',
    });
  }
});

// ==========================================
// GET CURRENT USER
// ==========================================

app.get('/me', auth, (req, res) => {
  const db = load();
  const u = db.users[req.userId];

  if (!u) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  res.json(
    mePayload(u, balanceOf(db, req.userId))
  );
});

// ==========================================
// UPDATE PROFILE
// ==========================================

app.patch('/me', auth, (req, res) => {
  const db = load();
  const u = db.users[req.userId];

  if (!u) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  if (req.body.name != null) {
    const n = String(req.body.name).trim();

    if (n.length < 2 || n.length > 32) {
      return res.status(400).json({
        error: 'invalid_name',
      });
    }

    u.name = n;
  }

  if (req.body.username != null) {
    const un = String(req.body.username)
      .trim()
      .toLowerCase();

    if (!validUsername(un)) {
      return res.status(400).json({
        error: 'invalid_username',
      });
    }

    const taken = db.usernames[un];

    if (taken && taken !== req.userId) {
      return res.status(409).json({
        error: 'username_taken',
      });
    }

    delete db.usernames[u.username];

    u.username = un;
    db.usernames[un] = req.userId;
  }

  save(db);

  res.json(
    mePayload(u, balanceOf(db, req.userId))
  );
});

// ==========================================
// SEARCH USERS
// ==========================================

app.get('/users/search', auth, (req, res) => {
  const q = String(req.query.q || '')
    .toLowerCase()
    .replace(/^@/, '')
    .trim();

  if (q.length < 2) {
    return res.json({
      users: [],
    });
  }

  const db = load();

  const users = Object.values(db.users)
    .filter((u) => !u.guest && (
      u.username.includes(q) ||
      u.name.toLowerCase().includes(q)
    ))
    .slice(0, 20)
    .map((u) => publicUser(u, undefined));

  res.json({
    users,
  });
});

// ==========================================
// GET USER BY USERNAME
// ==========================================

app.get('/users/:username', auth, (req, res) => {
  const db = load();

  const id = db.usernames[
    String(req.params.username || '').toLowerCase()
  ];

  if (!id) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  const t = db.users[id];
  res.json({
    ...publicUser(t, undefined),
    guest: !!t.guest,
    numbers: numList(t),
    gifts: (db.gifts[id] || []).map((g) => ({ k: g.k, num: g.num })),
  });
});

// ==========================================
// WALLET
// ==========================================

app.get('/wallet', auth, (req, res) => {
  res.json({
    balance: balanceOf(load(), req.userId),
  });
});

// ==========================================
// WALLET LEDGER
// ==========================================

app.get('/wallet/ledger', auth, (req, res) => {
  const db = load();

  const entries = db.ledger
    .filter((e) => e.userId === req.userId)
    .slice(-50)
    .reverse();

  res.json({
    entries,
  });
});

// ==========================================
// TEST TOPUP
// ==========================================

app.post('/wallet/topup-test', auth, (req, res) => {
  const delta = Math.min(
    Math.max(Number(req.body.amount) || 500, 1),
    500
  );

  const db = load();

  if (!db.users[req.userId]) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  const recent = db.ledger
    .filter(
      (e) =>
        e.userId === req.userId &&
        e.reason === 'test_topup'
    )
    .slice(-1)[0];

  if (
    recent &&
    Date.now() - recent.ts < 10000
  ) {
    return res.status(429).json({
      error: 'rate_limited',
    });
  }

  const entry = {
    id: nanoid(10),
    userId: req.userId,
    delta,
    reason: 'test_topup',
    ts: Date.now(),
  };

  db.ledger.push(entry);
  save(db);

  res.json({
    balance: balanceOf(db, req.userId),
    entry,
  });
});


// ==========================================
// NEX v2: GUEST, NUMBERS, GIFTS, MESSAGES
// ==========================================

const GUEST_TTL = 24 * 60 * 60 * 1000;

// Gift catalogue. Keep in sync with GIFTS in the client.
const GIFT_CAT = {
  heart: { n: 'Сердце', p: 25, s: 20000 },
};

// Anonymous number market (+888 and 8 digits).
const NUM_POOL = [
  ['+88804217788', 500],
  ['+88809132046', 500],
  ['+88800007777', 2400],
  ['+88808088080', 1200],
  ['+88803579246', 750],
  ['+88801000001', 3000],
];

const normNum = (n) => '+' + String(n || '').replace(/\D/g, '');
const fmtNum = (n) =>
  String(n).replace(/^\+888(\d{4})(\d{4})$/, '+888 $1 $2');
const numList = (u) =>
  (u.numbers || []).map((n) => ({
    number: n,
    display: fmtNum(n),
    main: u.mainNumber === n,
  }));

function nextSeq(db) {
  db.seq = (db.seq || 0) + 1;
  return db.seq;
}

function addMsg(db, m) {
  m.id = nanoid(10);
  m.ts = Date.now();
  m.seq = nextSeq(db);
  db.msgs.push(m);
  return m;
}

function svcMsg(db, to, text) {
  return addMsg(db, { from: 'nex', to, text });
}

function resolveUser(db, key) {
  const k = String(key || '').trim();
  return (
    db.users[k] ||
    db.users[db.usernames[k.toLowerCase().replace(/^@/, '')]] ||
    null
  );
}

function debit(db, u, amount, reason) {
  if (balanceOf(db, u.id) < amount) return false;
  db.ledger.push({
    id: nanoid(10),
    userId: u.id,
    delta: -amount,
    reason,
    ts: Date.now(),
  });
  return true;
}

function actor(req, res, { noGuest } = {}) {
  const db = load();
  const u = db.users[req.userId];
  if (!u) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }
  if (u.guest && u.exp && Date.now() > u.exp) {
    res.status(401).json({ error: 'guest_expired' });
    return null;
  }
  if (noGuest && u.guest) {
    res.status(403).json({ error: 'guest_forbidden' });
    return null;
  }
  return { db, u };
}

// ---------- guest ----------
const guestHits = new Map();

app.post('/auth/guest', (req, res) => {
  const ip = req.ip || 'x';
  const hits = (guestHits.get(ip) || []).filter(
    (t) => Date.now() - t < 3600000
  );
  if (hits.length >= 20) {
    return res.status(429).json({ error: 'rate_limited' });
  }
  hits.push(Date.now());
  guestHits.set(ip, hits);

  const db = load();
  const id = nanoid(12);
  let username;
  do {
    username =
      'guest_' +
      nanoid(6).toLowerCase().replace(/[^a-z0-9]/g, 'x');
  } while (db.usernames[username]);

  const u = {
    id,
    email: '',
    name: 'Гость',
    username,
    guest: true,
    createdAt: Date.now(),
    exp: Date.now() + GUEST_TTL,
  };
  db.users[id] = u;
  db.usernames[username] = id;
  db.gifts[id] = [];
  svcMsg(db, id, 'Вы вошли как гость на 24 часа. Покупки и подарки недоступны.');
  save(db);

  res.json({
    token: jwt.sign({ sub: id }, JWT_SECRET, { expiresIn: '24h' }),
    user: mePayload(u, 0),
  });
});

setInterval(() => {
  const db = load();
  const dead = Object.values(db.users).filter(
    (u) => u.guest && u.exp && Date.now() > u.exp
  );
  if (!dead.length) return;
  for (const u of dead) {
    delete db.users[u.id];
    delete db.usernames[u.username];
    delete db.gifts[u.id];
  }
  const ids = new Set(dead.map((u) => u.id));
  db.msgs = db.msgs.filter((m) => !ids.has(m.from) && !ids.has(m.to));
  save(db);
}, 60 * 60 * 1000);

// ---------- login by anonymous number ----------
app.post('/auth/number', async (req, res) => {
  try {
    const n = normNum(req.body.number);
    if (!/^\+888\d{8}$/.test(n)) {
      return res.status(400).json({ error: 'invalid_number' });
    }
    const db = load();
    const owner = db.users[db.numbers[n]];
    if (!owner) {
      return res.status(404).json({ error: 'number_not_found' });
    }
    const prev = db.numOtps[n];
    if (prev && Date.now() - prev.ts < 30000) {
      return res.status(429).json({ error: 'rate_limited' });
    }
    const code = String(crypto.randomInt(100000, 999999));
    db.numOtps[n] = {
      hash: await bcrypt.hash(code, 8),
      exp: Date.now() + OTP_TTL_MS,
      attempts: 0,
      ts: Date.now(),
    };
    // The code goes to the owner's Nex service chat.
    svcMsg(
      db,
      owner.id,
      `Код входа по номеру ${fmtNum(n)}: ${code}\nНикому его не сообщайте. Действует 10 минут.`
    );
    save(db);
    res.json({ ok: true, expiresIn: OTP_TTL_MS / 1000 });
  } catch (e) {
    console.error('[auth/number]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/auth/number/verify', async (req, res) => {
  try {
    const n = normNum(req.body.number);
    const code = String(req.body.code || '');
    if (!/^\+888\d{8}$/.test(n) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const db = load();
    const otp = db.numOtps[n];
    if (!otp) return res.status(400).json({ error: 'otp_not_found' });
    if (Date.now() > otp.exp) {
      delete db.numOtps[n];
      save(db);
      return res.status(400).json({ error: 'otp_expired' });
    }
    if (otp.attempts >= OTP_MAX_ATTEMPTS) {
      return res.status(429).json({ error: 'otp_locked' });
    }
    otp.attempts += 1;
    if (!(await bcrypt.compare(code, otp.hash))) {
      save(db);
      return res.status(400).json({ error: 'otp_invalid' });
    }
    delete db.numOtps[n];
    const u = db.users[db.numbers[n]];
    save(db);
    if (!u) return res.status(404).json({ error: 'number_not_found' });
    res.json({
      token: signToken(u.id),
      user: mePayload(u, balanceOf(db, u.id)),
    });
  } catch (e) {
    console.error('[auth/number/verify]', e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---------- market / inventory ----------
app.get('/market', auth, (_req, res) => {
  const db = load();
  res.json({
    gifts: Object.entries(GIFT_CAT).map(([k, g]) => ({ k, ...g })),
    numbers: NUM_POOL.filter(([n]) => !db.numbers[n]).map(
      ([n, p]) => ({ number: n, display: fmtNum(n), price: p })
    ),
  });
});

app.post('/numbers/buy', auth, (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;
  const { db, u } = c;
  const n = normNum(req.body.number);
  const item = NUM_POOL.find(([x]) => x === n);
  if (!item) return res.status(404).json({ error: 'number_not_found' });
  if (db.numbers[n]) return res.status(409).json({ error: 'number_taken' });
  const to = req.body.to ? resolveUser(db, req.body.to) : u;
  if (!to) return res.status(404).json({ error: 'recipient_not_found' });
  if (to.guest) return res.status(400).json({ error: 'recipient_guest' });
  if (!debit(db, u, item[1], 'number_buy')) {
    return res.status(402).json({ error: 'insufficient_funds' });
  }
  db.numbers[n] = to.id;
  to.numbers = [...(to.numbers || []), n];
  if (!to.mainNumber) to.mainNumber = n;
  if (to.id !== u.id) {
    addMsg(db, { from: u.id, to: to.id, numgift: fmtNum(n) });
  }
  save(db);
  res.json({ balance: balanceOf(db, u.id), numbers: numList(u) });
});

app.post('/numbers/main', auth, (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;
  const n = normNum(req.body.number);
  if (!(c.u.numbers || []).includes(n)) {
    return res.status(404).json({ error: 'number_not_owned' });
  }
  c.u.mainNumber = n;
  save(c.db);
  res.json({ numbers: numList(c.u) });
});

app.post('/numbers/give', auth, (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;
  const { db, u } = c;
  const n = normNum(req.body.number);
  const to = resolveUser(db, req.body.to);
  if (!(u.numbers || []).includes(n)) {
    return res.status(404).json({ error: 'number_not_owned' });
  }
  if (!to || to.id === u.id) {
    return res.status(404).json({ error: 'recipient_not_found' });
  }
  if (to.guest) return res.status(400).json({ error: 'recipient_guest' });
  u.numbers = u.numbers.filter((x) => x !== n);
  if (u.mainNumber === n) u.mainNumber = u.numbers[0] || null;
  to.numbers = [...(to.numbers || []), n];
  if (!to.mainNumber) to.mainNumber = n;
  db.numbers[n] = to.id;
  addMsg(db, { from: u.id, to: to.id, numgift: fmtNum(n) });
  save(db);
  res.json({ numbers: numList(u) });
});

// Buy a gift (for yourself or someone else) or pass one from inventory.
app.post('/gifts/send', auth, (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;
  const { db, u } = c;
  const to = resolveUser(db, req.body.to || u.id);
  if (!to) return res.status(404).json({ error: 'recipient_not_found' });
  if (to.guest) return res.status(400).json({ error: 'recipient_guest' });

  const inv = (db.gifts[u.id] = db.gifts[u.id] || []);
  let item;
  if (req.body.itemId) {
    const i = inv.findIndex((x) => x.id === req.body.itemId);
    if (i < 0) return res.status(404).json({ error: 'item_not_found' });
    if (to.id === u.id) return res.status(400).json({ error: 'same_user' });
    item = inv.splice(i, 1)[0];
  } else {
    const g = GIFT_CAT[req.body.key];
    if (!g) return res.status(400).json({ error: 'invalid_gift' });
    if (!debit(db, u, g.p, 'gift_buy')) {
      return res.status(402).json({ error: 'insufficient_funds' });
    }
    item = {
      id: nanoid(8),
      k: req.body.key,
      num: 1 + crypto.randomInt(g.s),
    };
  }
  item.ts = Date.now();
  item.from = to.id === u.id ? 'self' : u.username;
  (db.gifts[to.id] = db.gifts[to.id] || []).push(item);

  let msg = null;
  if (to.id !== u.id) {
    msg = addMsg(db, {
      from: u.id,
      to: to.id,
      gift: { k: item.k, num: item.num },
    });
  }
  save(db);
  res.json({ item, msg, balance: balanceOf(db, u.id) });
});

// ---------- messages ----------
app.post('/messages', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;
  const { db, u } = c;
  const b = req.body || {};
  const to = resolveUser(db, b.to);
  if (!to) return res.status(404).json({ error: 'recipient_not_found' });
  const self = to.id === u.id;
  const m = { from: u.id, to: to.id };

  const text = String(b.text || '').slice(0, 4000);
  if (text) m.text = text;
  if (b.file && typeof b.file === 'object') {
    m.file = {
      name: String(b.file.name || 'file').slice(0, 120),
      size: String(b.file.size || '').slice(0, 20),
    };
  }
  // Forwarding is only allowed into your own Saved chat.
  if (self && b.fwd) {
    m.fwd = String(b.fwd).slice(0, 60);
    if (b.gift && GIFT_CAT[b.gift.k]) {
      m.gift = { k: b.gift.k, num: Number(b.gift.num) || 0 };
    }
    if (b.numgift) m.numgift = String(b.numgift).slice(0, 20);
  }
  if (!m.text && !m.file && !m.gift && !m.numgift) {
    return res.status(400).json({ error: 'empty_message' });
  }
  addMsg(db, m);
  save(db);
  res.json({ msg: m });
});

app.get('/sync', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;
  const { db, u } = c;
  const since = Number(req.query.since) || 0;
  const msgs = db.msgs
    .filter((m) => m.seq > since && (m.from === u.id || m.to === u.id))
    .map((m) => ({ ...m, hid: (m.hid || []).includes(u.id) }))
    .filter((m) => since > 0 || (!m.hid && !m.del))
    .slice(-1000);
  const users = {};
  msgs.forEach((m) => {
    for (const id of [m.from, m.to]) {
      const p = db.users[id];
      if (p) users[id] = publicUser(p, undefined);
    }
  });
  res.json({ msgs, users, seq: db.seq || 0 });
});

app.delete('/messages/:id', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;
  const { db, u } = c;
  const m = db.msgs.find((x) => x.id === req.params.id);
  if (!m || (m.from !== u.id && m.to !== u.id)) {
    return res.status(404).json({ error: 'not_found' });
  }
  if (req.query.all === '1') {
    if (m.from !== u.id) return res.status(403).json({ error: 'forbidden' });
    m.del = true;
    delete m.text;
    delete m.file;
    delete m.gift;
    delete m.numgift;
    delete m.fwd;
  } else {
    m.hid = m.hid || [];
    if (!m.hid.includes(u.id)) m.hid.push(u.id);
  }
  m.seq = nextSeq(db);
  save(db);
  res.json({ ok: true });
});

app.post('/chats/clear', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;
  const { db, u } = c;
  const peer = String(req.body.to || '');
  let n = 0;
  for (const m of db.msgs) {
    const inChat =
      (m.from === u.id && m.to === peer) ||
      (m.to === u.id && m.from === peer);
    if (inChat && !(m.hid || []).includes(u.id)) {
      (m.hid = m.hid || []).push(u.id);
      m.seq = nextSeq(db);
      n += 1;
    }
  }
  save(db);
  res.json({ ok: true, n });
});

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((err, _req, res, _next) => {
  console.error('[Nex error]', err);

  res.status(500).json({
    error: 'server_error',
  });
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
  console.log(`Nex API on :${PORT}`);

  if (
    !process.env.JWT_SECRET ||
    process.env.JWT_SECRET === 'dev-secret-change-me'
  ) {
    console.warn('[warn] Set JWT_SECRET in production');
  }

  // Render self-ping every 10 minutes
  const selfBase =
    process.env.RENDER_EXTERNAL_URL ||
    process.env.SELF_URL ||
    '';

  if (selfBase) {
    const pingUrl =
      selfBase.replace(/\/$/, '') + '/health';

    console.log('[self-ping] enabled');

    setInterval(async () => {
      try {
        const r = await fetch(pingUrl, {
          signal: AbortSignal.timeout(10000),
        });

        console.log('[self-ping]', r.status);

      } catch (e) {
        console.log('[self-ping] fail', e.message);
      }
    }, 10 * 60 * 1000);

  } else {
    console.log(
      '[self-ping] skipped (no RENDER_EXTERNAL_URL / SELF_URL)'
    );
  }
});
