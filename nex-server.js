/**
 * Nex API — Render + Neon PostgreSQL
 * Start: node nex-server.js
 * Health: GET /health
 *
 * Persistent data: Neon PostgreSQL
 * Messages: RAM ONLY — never stored in database
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
const { Pool } = require('pg');

// ==========================================
// CONFIG
// ==========================================

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

const OTP_TTL_MS = 10 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

if (!process.env.DATABASE_URL) {
  console.error('[Nex DB] DATABASE_URL is missing');
  process.exit(1);
}

if (!process.env.JWT_SECRET || JWT_SECRET === 'dev-secret-change-me') {
  console.warn('[Nex] WARNING: Set a strong JWT_SECRET in Render');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 15000,
});

// ==========================================
// DATABASE STATE
// ==========================================

const emptyDb = () => ({
  users: {},
  emails: {},
  usernames: {},
  otps: {},
  ledger: [],
  gifts: {},
  numbers: {},
  numOtps: {},

  // Messages are deliberately RAM-only.
  msgs: [],
  seq: 0,
});

function fill(data) {
  const result = emptyDb();

  if (data && typeof data === 'object') {
    for (const key of Object.keys(result)) {
      if (data[key] != null) {
        result[key] = data[key];
      }
    }
  }

  if (!Array.isArray(result.ledger)) result.ledger = [];
  if (!Array.isArray(result.msgs)) result.msgs = [];

  if (!result.users || typeof result.users !== 'object') result.users = {};
  if (!result.emails || typeof result.emails !== 'object') result.emails = {};
  if (!result.usernames || typeof result.usernames !== 'object') result.usernames = {};
  if (!result.otps || typeof result.otps !== 'object') result.otps = {};
  if (!result.gifts || typeof result.gifts !== 'object') result.gifts = {};
  if (!result.numbers || typeof result.numbers !== 'object') result.numbers = {};
  if (!result.numOtps || typeof result.numOtps !== 'object') result.numOtps = {};

  if (!Number.isSafeInteger(result.seq) || result.seq < 0) {
    result.seq = 0;
  }

  return result;
}

let db = emptyDb();
let dbReady = false;

// Serialize writes so snapshots are not written out of order.
let saveQueue = Promise.resolve();

function persistentSnapshot(source) {
  return {
    users: source.users || {},
    emails: source.emails || {},
    usernames: source.usernames || {},
    otps: source.otps || {},
    ledger: source.ledger || [],
    gifts: source.gifts || {},
    numbers: source.numbers || {},
    numOtps: source.numOtps || {},

    // Only the numeric cursor is persisted.
    // Message contents are NEVER included.
    seq: Number.isSafeInteger(source.seq) ? source.seq : 0,
  };
}

function load() {
  return db;
}

function save(source) {
  const snapshot = persistentSnapshot(source);

  const operation = saveQueue
    .catch(() => {})
    .then(async () => {
      const result = await pool.query(
        `UPDATE nex_app_state
         SET state = $1::jsonb,
             updated_at = NOW()
         WHERE id = 1`,
        [JSON.stringify(snapshot)]
      );

      if (result.rowCount !== 1) {
        throw new Error('Persistent state row is missing');
      }

      return true;
    });

  saveQueue = operation.catch((error) => {
    dbReady = false;
    console.error('[Nex DB] Save failed:', error.message);
    return false;
  });

  return saveQueue.then((saved) => {
    if (saved) dbReady = true;
    return saved;
  });
}

async function persistOrRespond(source, res) {
  const saved = await save(source);

  if (!saved) {
    res.status(503).json({
      error: 'database_unavailable',
    });
    return false;
  }

  return true;
}

function readLegacyDb() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      console.log('[Nex DB] No legacy db.json found');
      return null;
    }

    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);

    console.log('[Nex DB] Legacy db.json found');

    return fill(parsed);
  } catch (error) {
    console.error('[Nex DB] Could not read legacy db.json:', error.message);
    return null;
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS nex_app_state (
      id SMALLINT PRIMARY KEY CHECK (id = 1),
      state JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const existing = await pool.query(
    'SELECT state FROM nex_app_state WHERE id = 1'
  );

  if (existing.rows.length > 0) {
    db = fill(existing.rows[0].state);

    // Never restore messages from the database.
    db.msgs = [];

    console.log('[Nex DB] Existing Neon state loaded');
  } else {
    const legacy = readLegacyDb();

    if (legacy) {
      // Import persistent account and inventory data only.
      // Old messages are intentionally discarded.
      db = fill(persistentSnapshot(legacy));
      db.msgs = [];

      const imported = await pool.query(
        `INSERT INTO nex_app_state (id, state)
         VALUES (1, $1::jsonb)
         ON CONFLICT (id) DO NOTHING
         RETURNING id`,
        [JSON.stringify(persistentSnapshot(db))]
      );

      if (imported.rowCount > 0) {
        console.log('[Nex DB] Legacy data imported into Neon');
      } else {
        console.log('[Nex DB] Another instance initialized the database; loading Neon state');
      }

      const actual = await pool.query(
        'SELECT state FROM nex_app_state WHERE id = 1'
      );

      if (actual.rows.length) {
        db = fill(actual.rows[0].state);
        db.msgs = [];
      }
    } else {
      db = emptyDb();

      await pool.query(
        `INSERT INTO nex_app_state (id, state)
         VALUES (1, $1::jsonb)
         ON CONFLICT (id) DO NOTHING`,
        [JSON.stringify(persistentSnapshot(db))]
      );

      const actual = await pool.query(
        'SELECT state FROM nex_app_state WHERE id = 1'
      );

      if (actual.rows.length) {
        db = fill(actual.rows[0].state);
        db.msgs = [];
      }

      console.log('[Nex DB] New empty state initialized');
    }
  }

  dbReady = true;

  console.log('[Nex DB] Connected to Neon PostgreSQL');
  console.log('[Nex DB] Messages are RAM-only');
}

function balanceOf(source, userId) {
  return source.ledger
    .filter((entry) => entry.userId === userId)
    .reduce((sum, entry) => sum + Number(entry.delta || 0), 0);
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
  const from = process.env.MAIL_FROM || 'Nex <noreply@nex.app>';

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
      ">${code}</div>
      <p style="color:#777;font-size:13px">
        This code expires in 10 minutes.
      </p>
      <p style="color:#999;font-size:12px">
        If you did not request this code, ignore this email.
      </p>
    </div>
  `;

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
        '[Nex mail] Resend error:',
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

  if (process.env.NODE_ENV !== 'production') {
    console.log(`[Nex mail:dev] OTP for ${email}: ${code}`);

    return {
      dev: true,
      code,
    };
  }

  throw new Error('Email provider is not configured');
}

// ==========================================
// VALIDATION
// ==========================================

const normEmail = (email) =>
  String(email || '').trim().toLowerCase();

const validEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const validUsername = (username) =>
  /^[a-z0-9_]{3,24}$/.test(username);

// ==========================================
// USERS
// ==========================================

function publicUser(user, balance) {
  return {
    id: user.id,
    name: user.name,
    username: user.username,
    createdAt: user.createdAt,
    balance,
  };
}

function mePayload(user, balance) {
  const source = load();

  return {
    ...publicUser(user, balance),
    email: user.email,
    emailHidden: true,
    guest: !!user.guest,
    exp: user.exp || null,
    numbers: numList(user),
    gifts: source.gifts[user.id] || [],
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
  const header = req.headers.authorization || '';

  const token = header.startsWith('Bearer ')
    ? header.slice(7)
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
    database: dbReady ? 'connected' : 'starting',
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

    const source = load();

    source.otps[email] = {
      hash,
      exp: Date.now() + OTP_TTL_MS,
      attempts: 0,
    };

    if (!(await persistOrRespond(source, res))) return;

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
  } catch (error) {
    console.error('[auth/email]', error);

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

    if (!validEmail(email) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: 'invalid_request',
      });
    }

    const source = load();
    const otp = source.otps[email];

    if (!otp) {
      return res.status(400).json({
        error: 'otp_not_found',
      });
    }

    if (Date.now() > otp.exp) {
      delete source.otps[email];

      if (!(await persistOrRespond(source, res))) return;

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

    const ok = await bcrypt.compare(code, otp.hash);

    if (!ok) {
      if (!(await persistOrRespond(source, res))) return;

      return res.status(400).json({
        error: 'otp_invalid',
      });
    }

    delete source.otps[email];

    let userId = source.emails[email];

    let user = userId
      ? source.users[userId]
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

      while (source.usernames[username]) {
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

      source.users[userId] = user;
      source.emails[email] = userId;
      source.usernames[username] = userId;
      source.gifts[userId] = [];

      svcMsg(
        source,
        userId,
        'Добро пожаловать в Nex! Сюда приходят коды входа и уведомления.'
      );
    }

    if (!(await persistOrRespond(source, res))) return;

    res.json({
      token: signToken(userId),
      user: mePayload(
        user,
        balanceOf(source, userId)
      ),
    });
  } catch (error) {
    console.error('[auth/verify]', error);

    res.status(500).json({
      error: 'server_error',
    });
  }
});

// ==========================================
// GET CURRENT USER
// ==========================================

app.get('/me', auth, (req, res) => {
  const source = load();
  const user = source.users[req.userId];

  if (!user) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  res.json(
    mePayload(user, balanceOf(source, req.userId))
  );
});

// ==========================================
// UPDATE PROFILE
// ==========================================

app.patch('/me', auth, async (req, res) => {
  const source = load();
  const user = source.users[req.userId];

  if (!user) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  if (req.body.name != null) {
    const name = String(req.body.name).trim();

    if (name.length < 2 || name.length > 32) {
      return res.status(400).json({
        error: 'invalid_name',
      });
    }

    user.name = name;
  }

  if (req.body.username != null) {
    const username = String(req.body.username)
      .trim()
      .toLowerCase();

    if (!validUsername(username)) {
      return res.status(400).json({
        error: 'invalid_username',
      });
    }

    const taken = source.usernames[username];

    if (taken && taken !== req.userId) {
      return res.status(409).json({
        error: 'username_taken',
      });
    }

    delete source.usernames[user.username];

    user.username = username;
    source.usernames[username] = req.userId;
  }

  if (!(await persistOrRespond(source, res))) return;

  res.json(
    mePayload(user, balanceOf(source, req.userId))
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
    return res.json({ users: [] });
  }

  const source = load();

  const users = Object.values(source.users)
    .filter((user) => !user.guest && (
      user.username.includes(q) ||
      user.name.toLowerCase().includes(q)
    ))
    .slice(0, 20)
    .map((user) => publicUser(user, undefined));

  res.json({ users });
});

// ==========================================
// GET USER BY USERNAME
// ==========================================

app.get('/users/:username', auth, (req, res) => {
  const source = load();

  const id = source.usernames[
    String(req.params.username || '').toLowerCase()
  ];

  if (!id) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  const user = source.users[id];

  if (!user) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  res.json({
    ...publicUser(user, undefined),
    guest: !!user.guest,
    numbers: numList(user),
    gifts: (source.gifts[id] || []).map((gift) => ({
      k: gift.k,
      num: gift.num,
    })),
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
  const source = load();

  const entries = source.ledger
    .filter((entry) => entry.userId === req.userId)
    .slice(-50)
    .reverse();

  res.json({ entries });
});

// ==========================================
// TEST TOPUP — KEEP ENABLED FOR NOW
// ==========================================

app.post('/wallet/topup-test', auth, async (req, res) => {
  const delta = Math.min(
    Math.max(Number(req.body.amount) || 500, 1),
    500
  );

  const source = load();

  if (!source.users[req.userId]) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  const recent = source.ledger
    .filter((entry) =>
      entry.userId === req.userId &&
      entry.reason === 'test_topup'
    )
    .slice(-1)[0];

  if (recent && Date.now() - recent.ts < 10000) {
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

  source.ledger.push(entry);

  if (!(await persistOrRespond(source, res))) return;

  res.json({
    balance: balanceOf(source, req.userId),
    entry,
  });
});

// ==========================================
// NEX V2: GUEST, NUMBERS, GIFTS, MESSAGES
// ==========================================

const GUEST_TTL = 24 * 60 * 60 * 1000;

const GIFT_CAT = {
  heart: {
    n: 'Сердце',
    p: 25,
    s: 20000,
  },
};

const NUM_POOL = [
  ['+88804217788', 500],
  ['+88809132046', 500],
  ['+88800007777', 2400],
  ['+88808088080', 1200],
  ['+88803579246', 750],
  ['+88801000001', 3000],
];

const normNum = (n) =>
  '+' + String(n || '').replace(/\D/g, '');

const fmtNum = (n) =>
  String(n).replace(/^\+888(\d{4})(\d{4})$/, '+888 $1 $2');

const numList = (user) =>
  (user.numbers || []).map((number) => ({
    number,
    display: fmtNum(number),
    main: user.mainNumber === number,
  }));

function nextSeq(source) {
  const previous = Number.isSafeInteger(source.seq) ? source.seq : 0;

  // Timestamp-based cursor avoids resetting to zero after a restart.
  // It stores no message content.
  source.seq = Math.max(previous + 1, Date.now());

  return source.seq;
}

function addMsg(source, message) {
  message.id = nanoid(10);
  message.ts = Date.now();
  message.seq = nextSeq(source);

  // RAM ONLY. Never passed to persistentSnapshot().
  source.msgs.push(message);

  return message;
}

function svcMsg(source, to, text) {
  return addMsg(source, {
    from: 'nex',
    to,
    text,
  });
}

function resolveUser(source, key) {
  const k = String(key || '').trim();

  return (
    source.users[k] ||
    source.users[
      source.usernames[k.toLowerCase().replace(/^@/, '')]
    ] ||
    null
  );
}

function debit(source, user, amount, reason) {
  if (balanceOf(source, user.id) < amount) {
    return false;
  }

  source.ledger.push({
    id: nanoid(10),
    userId: user.id,
    delta: -amount,
    reason,
    ts: Date.now(),
  });

  return true;
}

function actor(req, res, { noGuest } = {}) {
  const source = load();
  const user = source.users[req.userId];

  if (!user) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }

  if (user.guest && user.exp && Date.now() > user.exp) {
    res.status(401).json({ error: 'guest_expired' });
    return null;
  }

  if (noGuest && user.guest) {
    res.status(403).json({ error: 'guest_forbidden' });
    return null;
  }

  return {
    db: source,
    u: user,
  };
}

// ==========================================
// GUEST
// ==========================================

const guestHits = new Map();

app.post('/auth/guest', async (req, res) => {
  const ip = req.ip || 'x';

  const hits = (guestHits.get(ip) || []).filter(
    (time) => Date.now() - time < 3600000
  );

  if (hits.length >= 20) {
    return res.status(429).json({
      error: 'rate_limited',
    });
  }

  hits.push(Date.now());
  guestHits.set(ip, hits);

  const source = load();
  const id = nanoid(12);

  let username;

  do {
    username =
      'guest_' +
      nanoid(6).toLowerCase().replace(/[^a-z0-9]/g, 'x');
  } while (source.usernames[username]);

  const user = {
    id,
    email: '',
    name: 'Гость',
    username,
    guest: true,
    createdAt: Date.now(),
    exp: Date.now() + GUEST_TTL,
  };

  source.users[id] = user;
  source.usernames[username] = id;
  source.gifts[id] = [];

  svcMsg(
    source,
    id,
    'Вы вошли как гость на 24 часа. Покупки и подарки недоступны.'
  );

  if (!(await persistOrRespond(source, res))) return;

  res.json({
    token: jwt.sign(
      { sub: id },
      JWT_SECRET,
      { expiresIn: '24h' }
    ),
    user: mePayload(user, 0),
  });
});

// ==========================================
// CLEAN EXPIRED GUESTS
// ==========================================

setInterval(async () => {
  const source = load();

  const dead = Object.values(source.users).filter(
    (user) => user.guest && user.exp && Date.now() > user.exp
  );

  if (!dead.length) return;

  for (const user of dead) {
    delete source.users[user.id];
    delete source.usernames[user.username];
    delete source.gifts[user.id];
  }

  const ids = new Set(dead.map((user) => user.id));

  source.msgs = source.msgs.filter(
    (message) => !ids.has(message.from) && !ids.has(message.to)
  );

  // Background task: no HTTP response to send.
  await save(source);
}, 60 * 60 * 1000);

// ==========================================
// LOGIN BY ANONYMOUS NUMBER
// ==========================================

app.post('/auth/number', async (req, res) => {
  try {
    const number = normNum(req.body.number);

    if (!/^\+888\d{8}$/.test(number)) {
      return res.status(400).json({
        error: 'invalid_number',
      });
    }

    const source = load();
    const owner = source.users[source.numbers[number]];

    if (!owner) {
      return res.status(404).json({
        error: 'number_not_found',
      });
    }

    const previous = source.numOtps[number];

    if (previous && Date.now() - previous.ts < 30000) {
      return res.status(429).json({
        error: 'rate_limited',
      });
    }

    const code = String(
      crypto.randomInt(100000, 999999)
    );

    source.numOtps[number] = {
      hash: await bcrypt.hash(code, 8),
      exp: Date.now() + OTP_TTL_MS,
      attempts: 0,
      ts: Date.now(),
    };

    svcMsg(
      source,
      owner.id,
      `Код входа по номеру ${fmtNum(number)}: ${code}\nНикому его не сообщайте. Действует 10 минут.`
    );

    if (!(await persistOrRespond(source, res))) return;

    res.json({
      ok: true,
      expiresIn: OTP_TTL_MS / 1000,
    });
  } catch (error) {
    console.error('[auth/number]', error);

    res.status(500).json({
      error: 'server_error',
    });
  }
});

app.post('/auth/number/verify', async (req, res) => {
  try {
    const number = normNum(req.body.number);
    const code = String(req.body.code || '');

    if (!/^\+888\d{8}$/.test(number) || !/^\d{6}$/.test(code)) {
      return res.status(400).json({
        error: 'invalid_request',
      });
    }

    const source = load();
    const otp = source.numOtps[number];

    if (!otp) {
      return res.status(400).json({
        error: 'otp_not_found',
      });
    }

    if (Date.now() > otp.exp) {
      delete source.numOtps[number];

      if (!(await persistOrRespond(source, res))) return;

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

    if (!(await bcrypt.compare(code, otp.hash))) {
      if (!(await persistOrRespond(source, res))) return;

      return res.status(400).json({
        error: 'otp_invalid',
      });
    }

    delete source.numOtps[number];

    const user = source.users[source.numbers[number]];

    if (!(await persistOrRespond(source, res))) return;

    if (!user) {
      return res.status(404).json({
        error: 'number_not_found',
      });
    }

    res.json({
      token: signToken(user.id),
      user: mePayload(user, balanceOf(source, user.id)),
    });
  } catch (error) {
    console.error('[auth/number/verify]', error);

    res.status(500).json({
      error: 'server_error',
    });
  }
});

// ==========================================
// MARKET / INVENTORY
// ==========================================

app.get('/market', auth, (_req, res) => {
  const source = load();

  res.json({
    gifts: Object.entries(GIFT_CAT).map(([key, gift]) => ({
      k: key,
      ...gift,
    })),

    numbers: NUM_POOL
      .filter(([number]) => !source.numbers[number])
      .map(([number, price]) => ({
        number,
        display: fmtNum(number),
        price,
      })),
  });
});

// ==========================================
// BUY NUMBER
// ==========================================

app.post('/numbers/buy', auth, async (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;

  const { db: source, u: user } = c;

  const number = normNum(req.body.number);

  const item = NUM_POOL.find(([n]) => n === number);

  if (!item) {
    return res.status(404).json({
      error: 'number_not_found',
    });
  }

  if (source.numbers[number]) {
    return res.status(409).json({
      error: 'number_taken',
    });
  }

  const recipient = req.body.to
    ? resolveUser(source, req.body.to)
    : user;

  if (!recipient) {
    return res.status(404).json({
      error: 'recipient_not_found',
    });
  }

  if (recipient.guest) {
    return res.status(400).json({
      error: 'recipient_guest',
    });
  }

  if (!debit(source, user, item[1], 'number_buy')) {
    return res.status(402).json({
      error: 'insufficient_funds',
    });
  }

  source.numbers[number] = recipient.id;

  recipient.numbers = [
    ...(recipient.numbers || []),
    number,
  ];

  if (!recipient.mainNumber) {
    recipient.mainNumber = number;
  }

  if (recipient.id !== user.id) {
    addMsg(source, {
      from: user.id,
      to: recipient.id,
      numgift: fmtNum(number),
    });
  }

  if (!(await persistOrRespond(source, res))) return;

  res.json({
    balance: balanceOf(source, user.id),
    numbers: numList(user),
  });
});

// ==========================================
// SET MAIN NUMBER
// ==========================================

app.post('/numbers/main', auth, async (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;

  const number = normNum(req.body.number);

  if (!(c.u.numbers || []).includes(number)) {
    return res.status(404).json({
      error: 'number_not_owned',
    });
  }

  c.u.mainNumber = number;

  if (!(await persistOrRespond(c.db, res))) return;

  res.json({
    numbers: numList(c.u),
  });
});

// ==========================================
// GIVE NUMBER
// ==========================================

app.post('/numbers/give', auth, async (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;

  const { db: source, u: user } = c;

  const number = normNum(req.body.number);
  const recipient = resolveUser(source, req.body.to);

  if (!(user.numbers || []).includes(number)) {
    return res.status(404).json({
      error: 'number_not_owned',
    });
  }

  if (!recipient || recipient.id === user.id) {
    return res.status(404).json({
      error: 'recipient_not_found',
    });
  }

  if (recipient.guest) {
    return res.status(400).json({
      error: 'recipient_guest',
    });
  }

  user.numbers = user.numbers.filter(
    (item) => item !== number
  );

  if (user.mainNumber === number) {
    user.mainNumber = user.numbers[0] || null;
  }

  recipient.numbers = [
    ...(recipient.numbers || []),
    number,
  ];

  if (!recipient.mainNumber) {
    recipient.mainNumber = number;
  }

  source.numbers[number] = recipient.id;

  addMsg(source, {
    from: user.id,
    to: recipient.id,
    numgift: fmtNum(number),
  });

  if (!(await persistOrRespond(source, res))) return;

  res.json({
    numbers: numList(user),
  });
});

// ==========================================
// GIFTS
// ==========================================

app.post('/gifts/send', auth, async (req, res) => {
  const c = actor(req, res, { noGuest: true });
  if (!c) return;

  const { db: source, u: user } = c;

  const recipient = resolveUser(
    source,
    req.body.to || user.id
  );

  if (!recipient) {
    return res.status(404).json({
      error: 'recipient_not_found',
    });
  }

  if (recipient.guest) {
    return res.status(400).json({
      error: 'recipient_guest',
    });
  }

  const inventory = (
    source.gifts[user.id] = source.gifts[user.id] || []
  );

  let item;

  if (req.body.itemId) {
    const index = inventory.findIndex(
      (gift) => gift.id === req.body.itemId
    );

    if (index < 0) {
      return res.status(404).json({
        error: 'item_not_found',
      });
    }

    if (recipient.id === user.id) {
      return res.status(400).json({
        error: 'same_user',
      });
    }

    item = inventory.splice(index, 1)[0];
  } else {
    const gift = GIFT_CAT[req.body.key];

    if (!gift) {
      return res.status(400).json({
        error: 'invalid_gift',
      });
    }

    if (!debit(source, user, gift.p, 'gift_buy')) {
      return res.status(402).json({
        error: 'insufficient_funds',
      });
    }

    item = {
      id: nanoid(8),
      k: req.body.key,
      num: 1 + crypto.randomInt(gift.s),
    };
  }

  item.ts = Date.now();
  item.from = recipient.id === user.id
    ? 'self'
    : user.username;

  (
    source.gifts[recipient.id] =
    source.gifts[recipient.id] || []
  ).push(item);

  let msg = null;

  if (recipient.id !== user.id) {
    msg = addMsg(source, {
      from: user.id,
      to: recipient.id,
      gift: {
        k: item.k,
        num: item.num,
      },
    });
  }

  if (!(await persistOrRespond(source, res))) return;

  res.json({
    item,
    msg,
    balance: balanceOf(source, user.id),
  });
});

// ==========================================
// MESSAGES — RAM ONLY
// ==========================================

app.post('/messages', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;

  const { db: source, u: user } = c;
  const body = req.body || {};

  const recipient = resolveUser(source, body.to);

  if (!recipient) {
    return res.status(404).json({
      error: 'recipient_not_found',
    });
  }

  const self = recipient.id === user.id;

  const message = {
    from: user.id,
    to: recipient.id,
  };

  const text = String(body.text || '').slice(0, 4000);

  if (text) {
    message.text = text;
  }

  if (body.file && typeof body.file === 'object') {
    message.file = {
      name: String(body.file.name || 'file').slice(0, 120),
      size: String(body.file.size || '').slice(0, 20),
    };
  }

  if (self && body.fwd) {
    message.fwd = String(body.fwd).slice(0, 60);

    if (body.gift && GIFT_CAT[body.gift.k]) {
      message.gift = {
        k: body.gift.k,
        num: Number(body.gift.num) || 0,
      };
    }

    if (body.numgift) {
      message.numgift = String(body.numgift).slice(0, 20);
    }
  }

  if (
    !message.text &&
    !message.file &&
    !message.gift &&
    !message.numgift
  ) {
    return res.status(400).json({
      error: 'empty_message',
    });
  }

  addMsg(source, message);

  // No database write here.
  res.json({ msg: message });
});

app.get('/sync', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;

  const { db: source, u: user } = c;
  const since = Number(req.query.since) || 0;

  const msgs = source.msgs
    .filter((message) =>
      message.seq > since &&
      (message.from === user.id || message.to === user.id)
    )
    .map((message) => ({
      ...message,
      hid: (message.hid || []).includes(user.id),
    }))
    .filter((message) =>
      since > 0 || (!message.hid && !message.del)
    )
    .slice(-1000);

  const users = {};

  msgs.forEach((message) => {
    for (const id of [message.from, message.to]) {
      const profile = source.users[id];

      if (profile) {
        users[id] = publicUser(profile, undefined);
      }
    }
  });

  res.json({
    msgs,
    users,
    seq: source.seq || 0,
  });
});

app.delete('/messages/:id', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;

  const { db: source, u: user } = c;

  const message = source.msgs.find(
    (item) => item.id === req.params.id
  );

  if (
    !message ||
    (message.from !== user.id && message.to !== user.id)
  ) {
    return res.status(404).json({
      error: 'not_found',
    });
  }

  if (req.query.all === '1') {
    if (message.from !== user.id) {
      return res.status(403).json({
        error: 'forbidden',
      });
    }

    message.del = true;

    delete message.text;
    delete message.file;
    delete message.gift;
    delete message.numgift;
    delete message.fwd;
  } else {
    message.hid = message.hid || [];

    if (!message.hid.includes(user.id)) {
      message.hid.push(user.id);
    }
  }

  message.seq = nextSeq(source);

  res.json({ ok: true });
});

app.post('/chats/clear', auth, (req, res) => {
  const c = actor(req, res);
  if (!c) return;

  const { db: source, u: user } = c;
  const peer = String(req.body.to || '');

  let n = 0;

  for (const message of source.msgs) {
    const inChat =
      (message.from === user.id && message.to === peer) ||
      (message.to === user.id && message.from === peer);

    if (inChat && !(message.hid || []).includes(user.id)) {
      message.hid = message.hid || [];
      message.hid.push(user.id);
      message.seq = nextSeq(source);
      n += 1;
    }
  }

  res.json({
    ok: true,
    n,
  });
});

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((error, _req, res, _next) => {
  console.error('[Nex error]', error);

  res.status(500).json({
    error: 'server_error',
  });
});

// ==========================================
// START SERVER AFTER DATABASE INITIALIZATION
// ==========================================

async function start() {
  try {
    await initDatabase();

    app.listen(PORT, () => {
      console.log(`[Nex] API listening on port ${PORT}`);
      console.log('[Nex] Neon database ready');
      console.log('[Nex] Messages are stored in RAM only');

      const selfBase =
        process.env.RENDER_EXTERNAL_URL ||
        process.env.SELF_URL ||
        '';

      if (selfBase) {
        const pingUrl =
          selfBase.replace(/\/$/, '') + '/health';

        console.log('[Nex] Self-ping enabled');

        setInterval(async () => {
          try {
            const response = await fetch(pingUrl, {
              signal: AbortSignal.timeout(10000),
            });

            console.log('[Nex self-ping]', response.status);
          } catch (error) {
            console.log('[Nex self-ping] Failed:', error.message);
          }
        }, 10 * 60 * 1000);
      } else {
        console.log('[Nex] Self-ping skipped');
      }
    });
  } catch (error) {
    console.error('[Nex] Startup failed:', error);
    process.exit(1);
  }
}

start();

// ==========================================
// GRACEFUL SHUTDOWN
// ==========================================

async function shutdown(signal) {
  console.log(`[Nex] ${signal} received`);

  try {
    await saveQueue;
    await pool.end();
  } catch (error) {
    console.error('[Nex] Shutdown error:', error.message);
  }

  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
