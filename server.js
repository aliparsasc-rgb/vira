// server.js
const express = require('express');
const fs = require('fs');
const path = require('path');

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