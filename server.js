// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'vira-data.json');

// ===== ذخیره‌سازی ساده در فایل JSON =====
let store = { kv: {}, auth: {}, tokens: {} };
try {
  if (fs.existsSync(DATA_FILE)) {
    store = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  }
} catch (e) { console.error('load err', e); }

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.writeFileSync(DATA_FILE, JSON.stringify(store));
    } catch (e) { console.error('save err', e); }
  }, 500);
}

// ===== Middleware =====
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ===== Health =====
app.get('/api/health', (req, res) => res.json({ ok: true, time: Date.now() }));

// ===== Auth =====
function makeToken() {
  return 'v_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 12);
}
function getAuth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  const t = h.slice(7);
  for (const u in store.tokens) {
    if (store.tokens[u] === t) return u;
  }
  return null;
}

// ثبت‌نام / ورود
app.post('/api/auth', (req, res) => {
  const { username, password, mode } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  const u = String(username).toLowerCase().trim();
  const key = 'user_' + u;
  const existing = store.auth[key];
  if (mode === 'register' || !existing) {
    if (existing && existing.password !== password) {
      return res.status(401).json({ error: 'wrong password' });
    }
    store.auth[key] = { username, password, createdAt: Date.now() };
    save();
  } else {
    if (existing.password !== password) return res.status(401).json({ error: 'wrong password' });
  }
  const token = makeToken();
  store.tokens[u] = token;
  save();
  res.json({ ok: true, username, token });
});

// بررسی توکن فعلی
app.get('/api/me', (req, res) => {
  const u = getAuth(req);
  if (!u) return res.status(401).json({ error: 'unauthorized' });
  res.json({ ok: true, username: u });
});

// ===== Login / Register (همون چیزی که کلاینت ویرا صدا می‌زند) =====
app.set('trust proxy', 1);

const failLog = {};
function tooMany(req) {
  const now = Date.now();
  const a = (failLog[req.ip] || []).filter(t => now - t < 10 * 60 * 1000);
  failLog[req.ip] = a;
  return a.length >= 30;
}
function noteFail(req) { (failLog[req.ip] = failLog[req.ip] || []).push(Date.now()); }

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(pw), salt, 32).toString('hex');
  return { salt, hash };
}
function checkPw(rec, pw) {
  if (!rec) return false;
  if (rec.hash) {
    try {
      const h = crypto.scryptSync(String(pw), rec.salt, 32);
      return crypto.timingSafeEqual(h, Buffer.from(rec.hash, 'hex'));
    } catch (e) { return false; }
  }
  return rec.password === pw;
}

// نام کاربری/رمز مدیر: پیش‌فرض dev / 1؛ اگر مدیر از داخل اپ عوضش کرده باشد از admin-profile خوانده می‌شود
function adminCreds() {
  let u = 'dev', p = '1';
  try {
    const raw = store.kv['admin-profile'];
    if (raw) {
      const o = JSON.parse(raw);
      if (o.username) u = String(o.username);
      if (o.password) p = String(o.password);
    }
  } catch (e) {}
  return { u, p };
}
function isSuspended(name) {
  try {
    const raw = store.kv['users:' + name];
    return !!(raw && JSON.parse(raw).suspended);
  } catch (e) { return false; }
}

app.post('/api/register', (req, res) => {
  if (tooMany(req)) return res.status(429).json({ error: 'too many attempts' });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  const u = String(username).toLowerCase().trim();
  if (!/^[a-z0-9_]{3,20}$/.test(u)) return res.status(400).json({ error: 'bad username' });
  if (String(password).length < 4) return res.status(400).json({ error: 'password too short' });
  if (store.auth['user_' + u] || u === adminCreds().u.toLowerCase()) {
    return res.status(409).json({ error: 'username taken' });
  }
  store.auth['user_' + u] = Object.assign({ username: u, createdAt: Date.now() }, hashPw(password));
  const token = makeToken();
  store.tokens[u] = token;
  save();
  res.json({ ok: true, username: u, token });
});

app.post('/api/login', (req, res) => {
  if (tooMany(req)) return res.status(429).json({ error: 'too many attempts' });
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username/password required' });
  const u = String(username).toLowerCase().trim();
  const pw = String(password);
  const ac = adminCreds();

  if (u === ac.u.toLowerCase()) {
    if (pw !== ac.p) { noteFail(req); return res.status(401).json({ error: 'wrong password' }); }
    const token = makeToken();
    store.tokens[u] = token;
    save();
    return res.json({ ok: true, username: ac.u, token, isAdmin: true });
  }

  const rec = store.auth['user_' + u];
  if (!checkPw(rec, pw)) { noteFail(req); return res.status(401).json({ error: 'wrong username or password' }); }
  if (isSuspended(u)) return res.status(403).json({ error: 'suspended' });
  const token = makeToken();
  store.tokens[u] = token;
  save();
  res.json({ ok: true, username: rec.username || u, token, isAdmin: false });
});

// ===== KV Storage (همون چیزی که کلاینت انتظار داره) =====
app.get('/api/kv/:key', (req, res) => {
  const key = req.params.key;
  const v = store.kv[key];
  if (v === undefined) return res.status(404).json({ error: 'not found' });
  res.json({ key, value: v });
});

app.put('/api/kv/:key', (req, res) => {
  const key = req.params.key;
  const value = (req.body || {}).value;
  if (value === undefined) return res.status(400).json({ error: 'value required' });
  store.kv[key] = String(value);
  save();
  res.json({ ok: true, key });
});

app.delete('/api/kv/:key', (req, res) => {
  const key = req.params.key;
  delete store.kv[key];
  save();
  res.json({ ok: true, deleted: true });
});

app.get('/api/kv', (req, res) => {
  const prefix = req.query.prefix || '';
  const values = req.query.values === '1';
  const keys = Object.keys(store.kv).filter(k => k.startsWith(prefix));
  const items = {};
  if (values) keys.forEach(k => { items[k] = store.kv[k]; });
  res.json({ keys, items, prefix });
});

// ===== سرو کردن خود HTML =====
// فایل index.html رو کنار همین server.js بذار
app.get('/', (req, res) => {
  const file = path.join(__dirname, 'index.html');
  if (fs.existsSync(file)) res.sendFile(file);
  else res.send('<h1>index.html not found next to server.js</h1>');
});
app.get('/index.html', (req, res) => {
  const file = path.join(__dirname, 'index.html');
  if (fs.existsSync(file)) res.sendFile(file);
  else res.status(404).send('not found');
});

app.listen(PORT, () => {
  console.log('✅ Vira server running on port ' + PORT);
});