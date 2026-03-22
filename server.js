const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'eliza-secret-2024';

// Инициализация БД
const dbPath = path.join(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath);

// Создание таблиц
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL,
    activated_at TEXT,
    request_count INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  // Создаём админа
  db.get('SELECT COUNT(*) as c FROM admins', (err, row) => {
    if (err || row.c > 0) return;
    bcrypt.hash('admin123', 10, (err, hash) => {
      if (err) return;
      db.run('INSERT INTO admins (username, password_hash) VALUES (?, ?)', ['admin', hash], () => {
        console.log('✅ Админ создан: admin / admin123');
      });
    });
  });
});

// Middleware
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// Статика
app.use('/admin', express.static(path.join(__dirname, 'public')));

// ============ API ============

// Активация ключа
app.post('/api/auth/activate', (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ valid: false, error: 'Ключ не предоставлен' });

  const k = key.toUpperCase().trim();
  const match = k.match(/^ELIZA-(\d{8})-([A-Z0-9]{4})-([A-Z0-9]{4})$/);
  if (!match) return res.status(400).json({ valid: false, error: 'Неверный формат' });

  const datePart = match[1];
  const year = +datePart.substring(0,4), month = +datePart.substring(4,6)-1, day = +datePart.substring(6,8);
  const expires = new Date(year, month, day);
  const today = new Date(); today.setHours(0,0,0,0);
  if (expires < today) return res.status(400).json({ valid: false, error: 'Ключ истёк', expired: true });

  db.get('SELECT * FROM licenses WHERE key = ?', [k], (err, license) => {
    if (err) return res.status(500).json({ valid: false, error: 'Ошибка БД' });
    if (!license) return res.status(404).json({ valid: false, error: 'Ключ не найден' });
    if (license.is_active) return res.status(400).json({ valid: false, error: 'Ключ активирован' });

    db.run('UPDATE licenses SET is_active = 1, activated_at = ? WHERE key = ?', [new Date().toISOString(), k], function(err) {
      if (err) return res.status(500).json({ valid: false, error: 'Ошибка' });
      const token = jwt.sign({ licenseId: license.id }, JWT_SECRET, { expiresIn: '365d' });
      res.json({ valid: true, token, expiresAt: datePart });
    });
  });
});

// Проверка лицензии
app.get('/api/auth/check', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ valid: false, error: 'Нет токена' });
  try {
    const payload = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    db.get('SELECT * FROM licenses WHERE id = ?', [payload.licenseId], (err, license) => {
      if (err || !license || !license.is_active) return res.status(401).json({ valid: false, error: 'Не активна' });
      const today = new Date(); today.setHours(0,0,0,0);
      const exp = new Date(license.expires_at);
      if (exp < today) return res.status(401).json({ valid: false, error: 'Истёк', expired: true });
      db.run('UPDATE licenses SET request_count = request_count + 1 WHERE id = ?', [payload.licenseId]);
      res.json({ valid: true, expiresAt: license.expires_at, requestCount: license.request_count });
    });
  } catch(e) { res.status(401).json({ valid: false, error: 'Неверный токен' }); }
});

// Вход админа
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM admins WHERE username = ?', [username], async (err, admin) => {
    if (err || !admin) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) return res.status(401).json({ error: 'Неверный логин или пароль' });
    const token = jwt.sign({ adminId: admin.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, username: admin.username });
  });
});

// Генерация ключей
app.post('/api/admin/generate', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Нет токена' });
  try { jwt.verify(auth.split(' ')[1], JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Неверный токен' }); }
  const { expiresDate, count = 1 } = req.body;
  if (!expiresDate) return res.status(400).json({ error: 'Нет даты' });
  const crypto = require('crypto');
  const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const keys = [];
  let done = 0;

  const insert = (i) => {
    if (i >= count) { res.json({ success: true, keys }); return; }
    const datePart = expiresDate.replace(/-/g, '');
    let crc = 0xFFFF;
    for (let j = 0; j < datePart.length; j++) crc = ((crc >>> 8) ^ (0xA001 & (crc ^ datePart.charCodeAt(j)) & 0xFF) ^ (((crc ^ datePart.charCodeAt(j)) & 0xFF) >>> 1)) & 0xFFFF;
    const checksum = crc.toString(16).padStart(4, '0').toUpperCase();
    let suffix = '';
    const rnd = crypto.randomBytes(4);
    for (let j = 0; j < 4; j++) suffix += charset[rnd[j] % charset.length];
    const key = `ELIZA-${datePart}-${checksum}-${suffix}`;
    db.run('INSERT INTO licenses (key, expires_at) VALUES (?, ?)', [key, datePart], function(err) {
      if (!err) keys.push({ key, expiresAt: `${datePart[6]}${datePart[7]}.${datePart[4]}${datePart[5]}.${datePart.substring(0,4)}`, id: this.lastID });
      insert(i + 1);
    });
  };
  insert(0);
});

// Список ключей
app.get('/api/admin/keys', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Нет токена' });
  try { jwt.verify(auth.split(' ')[1], JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Неверный токен' }); }
  db.all('SELECT * FROM licenses ORDER BY created_at DESC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Ошибка' });
    const today = new Date(); today.setHours(0,0,0,0);
    const keys = rows.map(k => {
      const exp = new Date(k.expires_at);
      const status = k.is_active ? (exp < today ? 'expired' : 'active') : (exp < today ? 'expired' : 'pending');
      return { ...k, status };
    });
    res.json({ keys });
  });
});

// Деактивация
app.post('/api/admin/keys/:id/deactivate', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Нет токена' });
  try { jwt.verify(auth.split(' ')[1], JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Неверный токен' }); }
  db.run('UPDATE licenses SET is_active = 0, activated_at = NULL WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Ошибка' });
    res.json({ success: true });
  });
});

// Удаление
app.delete('/api/admin/keys/:id', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Нет токена' });
  try { jwt.verify(auth.split(' ')[1], JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Неверный токен' }); }
  db.run('DELETE FROM licenses WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Ошибка' });
    res.json({ success: true });
  });
});

// Статистика
app.get('/api/admin/stats', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Нет токена' });
  try { jwt.verify(auth.split(' ')[1], JWT_SECRET); } catch(e) { return res.status(401).json({ error: 'Неверный токен' }); }
  const s = {};
  db.get('SELECT COUNT(*) as v FROM licenses', (e,r) => { s.total = r?.v||0; d1(); });
  function d1() { db.get('SELECT COUNT(*) as v FROM licenses WHERE is_active = 1', (e,r) => { s.active = r?.v||0; d2(); }); }
  function d2() { db.get('SELECT COUNT(*) as v FROM licenses WHERE is_active = 0', (e,r) => { s.pending = r?.v||0; d3(); }); }
  function d3() { db.get("SELECT COUNT(*) as v FROM licenses WHERE expires_at < date('now')", (e,r) => { s.expired = r?.v||0; d4(); }); }
  function d4() { db.get('SELECT SUM(request_count) as v FROM licenses', (e,r) => { s.totalRequests = r?.v||0; res.json({ stats: s }); }); }
});

app.get('/', (req, res) => res.redirect('/admin'));

app.listen(PORT, () => {
  console.log(`🚀 Backend running on port ${PORT}`);
  console.log(`📌 Admin: http://localhost:${PORT}/admin`);
});
