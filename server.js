const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Data directory (use persistent disk on Render, local otherwise) ---
const DATA_DIR = process.env.NODE_ENV === 'production'
  ? '/opt/render/project/src/data'
  : __dirname;
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(path.join(UPLOAD_DIR, 'kml'), { recursive: true });
fs.mkdirSync(path.join(UPLOAD_DIR, 'images'), { recursive: true });

// --- Database Setup ---
const db = new Database(path.join(DATA_DIR, 'mapapp.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    parent_id INTEGER,
    user_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS pins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    folder_id INTEGER,
    user_id INTEGER NOT NULL,
    is_public INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS pin_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pin_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS kml_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );
`);

// Create default admin if not exists
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin = 1').get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin', 10);
  db.prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)').run('admin', hash);
  console.log('Default admin created: admin / admin');
}

// --- Middleware ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'map-app-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'ログインが必要です' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'ログインが必要です' });
  if (!req.session.isAdmin) return res.status(403).json({ error: '管理者権限が必要です' });
  next();
}

// --- File Upload Config ---
const kmlStorage = multer.diskStorage({
  destination: path.join(UPLOAD_DIR, 'kml'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const kmlUpload = multer({
  storage: kmlStorage,
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ext === '.kml' || ext === '.kmz') cb(null, true);
    else cb(new Error('KMLまたはKMZファイルのみアップロード可能です'));
  },
  limits: { fileSize: 50 * 1024 * 1024 }
});

const imageStorage = multer.diskStorage({
  destination: path.join(UPLOAD_DIR, 'images'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, uuidv4() + ext);
  }
});
const imageUpload = multer({
  storage: imageStorage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('画像ファイルのみアップロード可能です'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ==================== AUTH API ====================
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  if (username.length < 3) return res.status(400).json({ error: 'ユーザー名は3文字以上にしてください' });
  if (password.length < 4) return res.status(400).json({ error: 'パスワードは4文字以上にしてください' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'そのユーザー名は既に使われています' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);

  req.session.userId = result.lastInsertRowid;
  req.session.username = username;
  req.session.isAdmin = false;
  res.json({ id: result.lastInsertRowid, username, is_admin: false });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'ユーザー名またはパスワードが正しくありません' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.isAdmin = !!user.is_admin;
  res.json({ id: user.id, username: user.username, is_admin: !!user.is_admin });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json(null);
  res.json({
    id: req.session.userId,
    username: req.session.username,
    is_admin: req.session.isAdmin
  });
});

// ==================== KML API ====================
app.get('/api/kml', (req, res) => {
  const kml = db.prepare('SELECT * FROM kml_files ORDER BY created_at DESC LIMIT 1').get();
  res.json(kml || null);
});

app.post('/api/kml/upload', kmlUpload.single('kml'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'ファイルが選択されていません' });

  // Delete existing KML files
  const existing = db.prepare('SELECT * FROM kml_files').all();
  for (const f of existing) {
    const filePath = path.join(UPLOAD_DIR, 'kml', f.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  db.prepare('DELETE FROM kml_files').run();

  const userId = req.session.userId || null;
  const result = db.prepare('INSERT INTO kml_files (user_id, filename, original_name) VALUES (?, ?, ?)')
    .run(userId, req.file.filename, req.file.originalname);

  res.json({
    id: result.lastInsertRowid,
    filename: req.file.filename,
    original_name: req.file.originalname
  });
});

app.delete('/api/kml', (req, res) => {
  const existing = db.prepare('SELECT * FROM kml_files').all();
  for (const f of existing) {
    const filePath = path.join(UPLOAD_DIR, 'kml', f.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  db.prepare('DELETE FROM kml_files').run();
  res.json({ ok: true });
});

app.get('/api/kml/file/:filename', (req, res) => {
  const filePath = path.join(UPLOAD_DIR, 'kml', req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'ファイルが見つかりません' });
  res.sendFile(filePath);
});

// ==================== FOLDERS API ====================
app.get('/api/folders', requireAuth, (req, res) => {
  const folders = db.prepare('SELECT * FROM folders WHERE user_id = ? ORDER BY name').all(req.session.userId);
  res.json(folders);
});

app.post('/api/folders', requireAuth, (req, res) => {
  const { name, parent_id } = req.body;
  if (!name) return res.status(400).json({ error: 'フォルダ名を入力してください' });

  if (parent_id) {
    const parent = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(parent_id, req.session.userId);
    if (!parent) return res.status(404).json({ error: '親フォルダが見つかりません' });
  }

  const result = db.prepare('INSERT INTO folders (name, parent_id, user_id) VALUES (?, ?, ?)')
    .run(name, parent_id || null, req.session.userId);
  res.json({ id: result.lastInsertRowid, name, parent_id: parent_id || null, user_id: req.session.userId });
});

app.put('/api/folders/:id', requireAuth, (req, res) => {
  const { name, parent_id } = req.body;
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!folder) return res.status(404).json({ error: 'フォルダが見つかりません' });

  // Prevent circular reference
  if (parent_id) {
    let current = parent_id;
    while (current) {
      if (current == req.params.id) return res.status(400).json({ error: '循環参照になるため移動できません' });
      const p = db.prepare('SELECT parent_id FROM folders WHERE id = ?').get(current);
      current = p ? p.parent_id : null;
    }
  }

  db.prepare('UPDATE folders SET name = COALESCE(?, name), parent_id = ? WHERE id = ? AND user_id = ?')
    .run(name || folder.name, parent_id !== undefined ? parent_id : folder.parent_id, req.params.id, req.session.userId);
  res.json({ ok: true });
});

app.delete('/api/folders/:id', requireAuth, (req, res) => {
  const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(req.params.id, req.session.userId);
  if (!folder && !req.session.isAdmin) return res.status(404).json({ error: 'フォルダが見つかりません' });

  // Move pins in this folder to no folder
  db.prepare('UPDATE pins SET folder_id = NULL WHERE folder_id = ?').run(req.params.id);
  // Move child folders to parent
  db.prepare('UPDATE folders SET parent_id = ? WHERE parent_id = ? AND user_id = ?')
    .run(folder ? folder.parent_id : null, req.params.id, req.session.userId);
  db.prepare('DELETE FROM folders WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== PINS API ====================
app.get('/api/pins', (req, res) => {
  let pins;
  if (req.session.userId && req.session.isAdmin) {
    // Admin sees all pins
    pins = db.prepare(`
      SELECT p.*, u.username as author,
        (SELECT json_group_array(json_object('id', pi.id, 'filename', pi.filename, 'original_name', pi.original_name))
         FROM pin_images pi WHERE pi.pin_id = p.id) as images
      FROM pins p LEFT JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `).all();
  } else if (req.session.userId) {
    // Logged in user sees their own + public pins
    pins = db.prepare(`
      SELECT p.*, u.username as author,
        (SELECT json_group_array(json_object('id', pi.id, 'filename', pi.filename, 'original_name', pi.original_name))
         FROM pin_images pi WHERE pi.pin_id = p.id) as images
      FROM pins p LEFT JOIN users u ON p.user_id = u.id
      WHERE p.is_public = 1 OR p.user_id = ?
      ORDER BY p.created_at DESC
    `).all(req.session.userId);
  } else {
    // Anonymous sees only public pins
    pins = db.prepare(`
      SELECT p.*, u.username as author,
        (SELECT json_group_array(json_object('id', pi.id, 'filename', pi.filename, 'original_name', pi.original_name))
         FROM pin_images pi WHERE pi.pin_id = p.id) as images
      FROM pins p LEFT JOIN users u ON p.user_id = u.id
      WHERE p.is_public = 1
      ORDER BY p.created_at DESC
    `).all();
  }

  pins.forEach(p => {
    try { p.images = JSON.parse(p.images).filter(i => i.id !== null); } catch { p.images = []; }
  });
  res.json(pins);
});

app.post('/api/pins', requireAuth, (req, res) => {
  const { title, description, lat, lng, folder_id, is_public } = req.body;
  if (!title || lat == null || lng == null) return res.status(400).json({ error: 'タイトルと座標は必須です' });

  if (folder_id) {
    const folder = db.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?').get(folder_id, req.session.userId);
    if (!folder) return res.status(400).json({ error: 'フォルダが見つかりません' });
  }

  const result = db.prepare(
    'INSERT INTO pins (title, description, lat, lng, folder_id, user_id, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(title, description || '', lat, lng, folder_id || null, req.session.userId, is_public ? 1 : 0);

  res.json({
    id: result.lastInsertRowid, title, description: description || '',
    lat, lng, folder_id: folder_id || null, user_id: req.session.userId,
    is_public: is_public ? 1 : 0, images: []
  });
});

app.put('/api/pins/:id', requireAuth, (req, res) => {
  const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.id);
  if (!pin) return res.status(404).json({ error: 'ピンが見つかりません' });
  if (pin.user_id !== req.session.userId && !req.session.isAdmin) {
    return res.status(403).json({ error: '権限がありません' });
  }

  const { title, description, folder_id, is_public } = req.body;
  db.prepare(`UPDATE pins SET
    title = COALESCE(?, title),
    description = COALESCE(?, description),
    folder_id = ?,
    is_public = COALESCE(?, is_public)
    WHERE id = ?`
  ).run(
    title || pin.title,
    description !== undefined ? description : pin.description,
    folder_id !== undefined ? folder_id : pin.folder_id,
    is_public !== undefined ? (is_public ? 1 : 0) : null,
    req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/pins/:id', requireAuth, (req, res) => {
  const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.id);
  if (!pin) return res.status(404).json({ error: 'ピンが見つかりません' });
  if (pin.user_id !== req.session.userId && !req.session.isAdmin) {
    return res.status(403).json({ error: '権限がありません' });
  }

  // Delete associated images from disk
  const images = db.prepare('SELECT * FROM pin_images WHERE pin_id = ?').all(req.params.id);
  for (const img of images) {
    const imgPath = path.join(UPLOAD_DIR, 'images', img.filename);
    if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  }

  db.prepare('DELETE FROM pins WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== PIN IMAGES API ====================
app.post('/api/pins/:id/images', requireAuth, imageUpload.array('images', 10), (req, res) => {
  const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.id);
  if (!pin) return res.status(404).json({ error: 'ピンが見つかりません' });
  if (pin.user_id !== req.session.userId && !req.session.isAdmin) {
    return res.status(403).json({ error: '権限がありません' });
  }

  const insertStmt = db.prepare('INSERT INTO pin_images (pin_id, filename, original_name) VALUES (?, ?, ?)');
  const inserted = [];
  for (const file of (req.files || [])) {
    const result = insertStmt.run(req.params.id, file.filename, file.originalname);
    inserted.push({ id: result.lastInsertRowid, filename: file.filename, original_name: file.originalname });
  }
  res.json(inserted);
});

app.delete('/api/pins/:pinId/images/:imageId', requireAuth, (req, res) => {
  const pin = db.prepare('SELECT * FROM pins WHERE id = ?').get(req.params.pinId);
  if (!pin) return res.status(404).json({ error: 'ピンが見つかりません' });
  if (pin.user_id !== req.session.userId && !req.session.isAdmin) {
    return res.status(403).json({ error: '権限がありません' });
  }

  const img = db.prepare('SELECT * FROM pin_images WHERE id = ? AND pin_id = ?').get(req.params.imageId, req.params.pinId);
  if (!img) return res.status(404).json({ error: '画像が見つかりません' });

  const imgPath = path.join(UPLOAD_DIR, 'images', img.filename);
  if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
  db.prepare('DELETE FROM pin_images WHERE id = ?').run(req.params.imageId);
  res.json({ ok: true });
});

// ==================== START ====================
app.listen(PORT, () => {
  console.log(`Map app running at http://localhost:${PORT}`);
});
