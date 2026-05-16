import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import path from 'path';
import { fileURLToPath } from 'url';
import db from './db.js';
import { sign, genKey } from './crypto.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH
  || bcrypt.hashSync(process.env.ADMIN_PASS || 'admin', 10);
const SESSION_SECRET = process.env.SESSION_SECRET || 'change_me_session';

app.set('trust proxy', 1);
app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: 'auto', maxAge: 86400000 }
}));

app.get('/health', (_, res) => res.json({ ok: true }));

// ====== Public auth endpoint called by the .so ======
app.post('/api/v1/auth', (req, res) => {
  const { key, hwid, nonce } = req.body || {};
  const ip = req.ip;
  const now = Date.now();
  const log = (key_id, status) =>
    db.prepare('INSERT INTO auth_log(key_id,hwid,ip,status,ts) VALUES (?,?,?,?,?)').run(key_id, hwid || null, ip, status, now);

  if (!key || !hwid || !nonce || typeof key !== 'string' || typeof hwid !== 'string' || typeof nonce !== 'string'
      || key.length > 128 || hwid.length > 256 || nonce.length > 128) {
    log(null, 'bad_request');
    return res.status(400).json({ ok: false, error: 'bad_request' });
  }

  const row = db.prepare('SELECT * FROM license_keys WHERE key = ?').get(key);
  if (!row) { log(null, 'invalid_key'); return res.json({ ok: false, error: 'invalid_key' }); }
  if (!row.is_active) { log(row.id, 'revoked'); return res.json({ ok: false, error: 'revoked' }); }

  // Activate on first use
  if (!row.activated_at) {
    const expires = now + row.duration_days * 86400000;
    db.prepare('UPDATE license_keys SET activated_at=?, expires_at=? WHERE id=?').run(now, expires, row.id);
    row.activated_at = now; row.expires_at = expires;
  }
  if (row.expires_at && now > row.expires_at) { log(row.id, 'expired'); return res.json({ ok: false, error: 'expired' }); }

  // Device binding
  const existing = db.prepare('SELECT * FROM key_devices WHERE key_id=? AND hwid=?').get(row.id, hwid);
  if (existing) {
    db.prepare('UPDATE key_devices SET last_seen=? WHERE id=?').run(now, existing.id);
  } else {
    const count = db.prepare('SELECT COUNT(*) c FROM key_devices WHERE key_id=?').get(row.id).c;
    if (count >= row.device_limit) {
      log(row.id, 'device_limit'); return res.json({ ok: false, error: 'device_limit' });
    }
    db.prepare('INSERT INTO key_devices(key_id,hwid,first_seen,last_seen) VALUES (?,?,?,?)').run(row.id, hwid, now, now);
  }

  log(row.id, 'ok');
  const payload = { ok: true, key, hwid, nonce, exp: row.expires_at, ts: now };
  res.json({ ok: true, token: sign(payload), exp: row.expires_at });
});

// ====== Admin auth ======
function requireAuth(req, res, next) {
  if (req.session?.admin) return next();
  if (req.path.startsWith('/admin/api')) return res.status(401).json({ error: 'unauthorized' });
  res.redirect('/login');
}

app.get('/login', (_, res) => res.sendFile(path.join(__dirname, '..', 'public', 'login.html')));
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USER && bcrypt.compareSync(password || '', ADMIN_PASS_HASH)) {
    req.session.admin = true; return res.redirect('/');
  }
  res.redirect('/login?e=1');
});
app.post('/logout', (req, res) => { req.session.destroy(() => res.redirect('/login')); });

// ====== Admin pages ======
app.get('/', requireAuth, (_, res) => res.sendFile(path.join(__dirname, '..', 'public', 'index.html')));

// ====== Admin API ======
app.get('/admin/api/keys', requireAuth, (_, res) => {
  const keys = db.prepare(`SELECT k.*, (SELECT COUNT(*) FROM key_devices d WHERE d.key_id=k.id) AS device_count
                           FROM license_keys k ORDER BY k.created_at DESC`).all();
  res.json({ keys });
});

app.post('/admin/api/keys', requireAuth, (req, res) => {
  const duration = parseInt(req.body.duration_days, 10);
  const limit = parseInt(req.body.device_limit, 10);
  const note = String(req.body.note || '').slice(0, 200);
  const count = Math.min(Math.max(parseInt(req.body.count, 10) || 1, 1), 100);
  if (!Number.isFinite(duration) || duration < 1 || duration > 36500) return res.status(400).json({ error: 'bad_duration' });
  if (!Number.isFinite(limit) || limit < 1 || limit > 100) return res.status(400).json({ error: 'bad_limit' });
  const stmt = db.prepare('INSERT INTO license_keys(key,note,duration_days,device_limit,created_at) VALUES (?,?,?,?,?)');
  const created = [];
  for (let i = 0; i < count; i++) {
    const k = genKey();
    stmt.run(k, note, duration, limit, Date.now());
    created.push(k);
  }
  res.json({ created });
});

app.post('/admin/api/keys/:id/toggle', requireAuth, (req, res) => {
  db.prepare('UPDATE license_keys SET is_active = 1 - is_active WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/admin/api/keys/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM license_keys WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

app.post('/admin/api/keys/:id/reset-devices', requireAuth, (req, res) => {
  db.prepare('DELETE FROM key_devices WHERE key_id=?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/admin/api/keys/:id/devices', requireAuth, (req, res) => {
  const devices = db.prepare('SELECT * FROM key_devices WHERE key_id=? ORDER BY first_seen DESC').all(req.params.id);
  res.json({ devices });
});

app.get('/admin/api/log', requireAuth, (_, res) => {
  const log = db.prepare('SELECT * FROM auth_log ORDER BY ts DESC LIMIT 200').all();
  res.json({ log });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Panel running on ${PORT}`));
