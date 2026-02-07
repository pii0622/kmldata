import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { setCookie, getCookie } from 'hono/cookie';

const app = new Hono().basePath('/api');

// CORS middleware
app.use('*', cors());

// ==================== Utility Functions ====================
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return btoa(String.fromCharCode(...new Uint8Array(hash)));
}

async function verifyPassword(password, hash) {
  const computed = await hashPassword(password);
  return computed === hash;
}

async function createToken(payload, secret) {
  const encoder = new TextEncoder();
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadStr = btoa(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  const data = encoder.encode(`${header}.${payloadStr}`);
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const signature = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${payloadStr}.${signature}`;
}

async function verifyToken(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const encoder = new TextEncoder();
    const data = encoder.encode(`${header}.${payload}`);
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;
    const parsed = JSON.parse(atob(payload));
    if (parsed.exp < Date.now()) return null;
    return parsed;
  } catch { return null; }
}

// Auth middleware
async function authMiddleware(c, next) {
  const token = getCookie(c, 'auth');
  if (token) {
    const payload = await verifyToken(token, c.env.JWT_SECRET);
    if (payload) {
      c.set('user', payload);
    }
  }
  await next();
}

function requireAuth(c) {
  const user = c.get('user');
  if (!user) {
    return c.json({ error: 'ログインが必要です' }, 401);
  }
  return null;
}

function requireAdmin(c) {
  const user = c.get('user');
  if (!user) return c.json({ error: 'ログインが必要です' }, 401);
  if (!user.is_admin) return c.json({ error: '管理者権限が必要です' }, 403);
  return null;
}

// Convert Polygon to LineString in KML
function convertKmlPolygonToLine(kml) {
  return kml.replace(
    /<Polygon[^>]*>[\s\S]*?<outerBoundaryIs>\s*<LinearRing>\s*<coordinates>([\s\S]*?)<\/coordinates>\s*<\/LinearRing>\s*<\/outerBoundaryIs>[\s\S]*?<\/Polygon>/gi,
    '<LineString><coordinates>$1</coordinates></LineString>'
  );
}

app.use('*', authMiddleware);

// ==================== Auth API ====================
app.post('/auth/register', async (c) => {
  const { username, password, display_name } = await c.req.json();
  if (!username || !password) {
    return c.json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }
  if (username.length < 3) {
    return c.json({ error: 'ユーザー名は3文字以上にしてください' }, 400);
  }
  if (password.length < 4) {
    return c.json({ error: 'パスワードは4文字以上にしてください' }, 400);
  }

  const existing = await c.env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    return c.json({ error: 'そのユーザー名は既に使われています' }, 400);
  }

  const hash = await hashPassword(password);
  const result = await c.env.DB.prepare(
    'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)'
  ).bind(username, hash, display_name || username).run();

  const userId = result.meta.last_row_id;
  const token = await createToken({ id: userId, username, display_name: display_name || username, is_admin: false }, c.env.JWT_SECRET);
  setCookie(c, 'auth', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 });

  return c.json({ id: userId, username, display_name: display_name || username, is_admin: false });
});

app.post('/auth/login', async (c) => {
  const { username, password } = await c.req.json();
  if (!username || !password) {
    return c.json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }

  const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: 'ユーザー名またはパスワードが正しくありません' }, 401);
  }

  const token = await createToken({
    id: user.id, username: user.username,
    display_name: user.display_name || user.username,
    is_admin: !!user.is_admin
  }, c.env.JWT_SECRET);
  setCookie(c, 'auth', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 });

  return c.json({ id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin });
});

app.post('/auth/logout', (c) => {
  setCookie(c, 'auth', '', { maxAge: 0 });
  return c.json({ ok: true });
});

app.get('/auth/me', (c) => {
  const user = c.get('user');
  return c.json(user || null);
});

app.put('/auth/profile', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const { display_name } = await c.req.json();

  await c.env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?')
    .bind(display_name || user.username, user.id).run();

  // Update token with new display_name
  const token = await createToken({ ...user, display_name: display_name || user.username }, c.env.JWT_SECRET);
  setCookie(c, 'auth', token, { httpOnly: true, secure: true, sameSite: 'Strict', maxAge: 7 * 24 * 60 * 60 });

  return c.json({ ok: true, display_name: display_name || user.username });
});

// ==================== Users API (for sharing) ====================
app.get('/users', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');

  // Get all users except current user (for sharing dropdown)
  const users = await c.env.DB.prepare(
    'SELECT id, username, display_name FROM users WHERE id != ? ORDER BY display_name'
  ).bind(user.id).all();

  return c.json(users.results);
});

// ==================== KML Folders API ====================
app.get('/kml-folders', async (c) => {
  const user = c.get('user');

  let folders;
  if (user) {
    // Get own folders + shared folders + admin public folders
    folders = await c.env.DB.prepare(`
      SELECT kf.*, u.display_name as owner_name,
        CASE WHEN kf.user_id = ? THEN 1 ELSE 0 END as is_owner,
        (SELECT GROUP_CONCAT(shared_with_user_id) FROM kml_folder_shares WHERE kml_folder_id = kf.id) as shared_with,
        COALESCE(kfv.is_visible, 1) as is_visible
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      LEFT JOIN kml_folder_visibility kfv ON kf.id = kfv.kml_folder_id AND kfv.user_id = ?
      WHERE kf.user_id = ?
        OR kf.is_public = 1
        OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
      ORDER BY kf.name
    `).bind(user.id, user.id, user.id, user.id).all();
  } else {
    // Anonymous: only admin public folders
    folders = await c.env.DB.prepare(`
      SELECT kf.*, u.display_name as owner_name, 0 as is_owner, 1 as is_visible
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      WHERE kf.is_public = 1
      ORDER BY kf.name
    `).all();
  }

  return c.json(folders.results);
});

app.post('/kml-folders', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const { name, is_public } = await c.req.json();

  if (!name) return c.json({ error: 'フォルダ名を入力してください' }, 400);

  // Only admin can make public
  const publicFlag = user.is_admin && is_public ? 1 : 0;

  const result = await c.env.DB.prepare(
    'INSERT INTO kml_folders (name, user_id, is_public) VALUES (?, ?, ?)'
  ).bind(name, user.id, publicFlag).run();

  return c.json({ id: result.meta.last_row_id, name, user_id: user.id, is_public: publicFlag });
});

app.put('/kml-folders/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const { name, is_public } = await c.req.json();
  const publicFlag = user.is_admin && is_public ? 1 : 0;

  await c.env.DB.prepare('UPDATE kml_folders SET name = ?, is_public = ? WHERE id = ?')
    .bind(name || folder.name, publicFlag, folderId).run();

  return c.json({ ok: true });
});

app.delete('/kml-folders/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  // Delete KML files in folder from R2
  const files = await c.env.DB.prepare('SELECT r2_key FROM kml_files WHERE folder_id = ?').bind(folderId).all();
  for (const f of files.results) {
    await c.env.R2.delete(f.r2_key);
  }

  await c.env.DB.prepare('DELETE FROM kml_folders WHERE id = ?').bind(folderId).run();
  return c.json({ ok: true });
});

// Toggle KML folder visibility
app.post('/kml-folders/:id/visibility', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');
  const { is_visible } = await c.req.json();

  // Upsert visibility setting
  await c.env.DB.prepare(`
    INSERT INTO kml_folder_visibility (kml_folder_id, user_id, is_visible) VALUES (?, ?, ?)
    ON CONFLICT(kml_folder_id, user_id) DO UPDATE SET is_visible = excluded.is_visible
  `).bind(folderId, user.id, is_visible ? 1 : 0).run();

  return c.json({ ok: true });
});

// Share KML folder
app.post('/kml-folders/:id/share', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const { user_ids } = await c.req.json();

  // Clear existing shares and add new ones
  await c.env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id = ?').bind(folderId).run();

  for (const uid of (user_ids || [])) {
    await c.env.DB.prepare(
      'INSERT INTO kml_folder_shares (kml_folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(folderId, uid).run();
  }

  return c.json({ ok: true });
});

// ==================== KML Files API ====================
app.get('/kml-files', async (c) => {
  const user = c.get('user');
  const folderId = c.req.query('folder_id');

  let query, bindings;
  if (user) {
    if (folderId) {
      query = `
        SELECT kf.*, u.display_name as owner_name
        FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        WHERE kf.folder_id = ? AND (kf.user_id = ? OR kf.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?))
        ORDER BY kf.original_name
      `;
      bindings = [folderId, user.id, user.id];
    } else {
      query = `
        SELECT kf.*, u.display_name as owner_name
        FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        WHERE kf.user_id = ? OR kf.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
        ORDER BY kf.original_name
      `;
      bindings = [user.id, user.id];
    }
  } else {
    query = `
      SELECT kf.*, u.display_name as owner_name
      FROM kml_files kf
      LEFT JOIN users u ON kf.user_id = u.id
      WHERE kf.is_public = 1
      ORDER BY kf.original_name
    `;
    bindings = [];
  }

  const stmt = c.env.DB.prepare(query);
  const files = bindings.length > 0 ? await stmt.bind(...bindings).all() : await stmt.all();

  return c.json(files.results);
});

app.post('/kml-files/upload', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');

  const formData = await c.req.formData();
  const file = formData.get('kml');
  const folderId = formData.get('folder_id');
  const isPublic = formData.get('is_public');

  if (!file) return c.json({ error: 'ファイルが選択されていません' }, 400);

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'kml' && ext !== 'kmz') {
    return c.json({ error: 'KMLまたはKMZファイルのみアップロード可能です' }, 400);
  }

  // Generate unique key
  const r2Key = `kml/${crypto.randomUUID()}.${ext}`;

  // Read and convert KML
  let content = await file.text();
  if (ext === 'kml') {
    content = convertKmlPolygonToLine(content);
  }

  // Upload to R2
  await c.env.R2.put(r2Key, content, {
    httpMetadata: { contentType: ext === 'kml' ? 'application/vnd.google-earth.kml+xml' : 'application/vnd.google-earth.kmz' }
  });

  // Only admin can make public
  const publicFlag = user.is_admin && isPublic === 'true' ? 1 : 0;

  const result = await c.env.DB.prepare(
    'INSERT INTO kml_files (folder_id, user_id, r2_key, original_name, is_public) VALUES (?, ?, ?, ?, ?)'
  ).bind(folderId || null, user.id, r2Key, file.name, publicFlag).run();

  return c.json({
    id: result.meta.last_row_id,
    r2_key: r2Key,
    original_name: file.name,
    folder_id: folderId || null,
    is_public: publicFlag
  });
});

app.get('/kml-files/:key', async (c) => {
  const key = c.req.param('key');
  const obj = await c.env.R2.get(`kml/${key}`);
  if (!obj) return c.json({ error: 'ファイルが見つかりません' }, 404);

  const headers = new Headers();
  headers.set('Content-Type', obj.httpMetadata?.contentType || 'application/octet-stream');

  return new Response(obj.body, { headers });
});

app.delete('/kml-files/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const fileId = c.req.param('id');

  const file = await c.env.DB.prepare('SELECT * FROM kml_files WHERE id = ?').bind(fileId).first();
  if (!file) return c.json({ error: 'ファイルが見つかりません' }, 404);
  if (file.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  // Delete from R2
  await c.env.R2.delete(file.r2_key);

  // Delete from DB
  await c.env.DB.prepare('DELETE FROM kml_files WHERE id = ?').bind(fileId).run();

  return c.json({ ok: true });
});

// ==================== Pin Folders API ====================
app.get('/folders', async (c) => {
  const user = c.get('user');
  if (!user) return c.json([]);

  // Get own folders + shared folders
  const folders = await c.env.DB.prepare(`
    SELECT f.*, u.display_name as owner_name,
      CASE WHEN f.user_id = ? THEN 1 ELSE 0 END as is_owner,
      (SELECT GROUP_CONCAT(shared_with_user_id) FROM folder_shares WHERE folder_id = f.id) as shared_with
    FROM folders f
    LEFT JOIN users u ON f.user_id = u.id
    WHERE f.user_id = ?
      OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
    ORDER BY f.name
  `).bind(user.id, user.id, user.id).all();

  return c.json(folders.results);
});

app.post('/folders', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const { name, parent_id } = await c.req.json();

  if (!name) return c.json({ error: 'フォルダ名を入力してください' }, 400);

  if (parent_id) {
    const parent = await c.env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(parent_id, user.id).first();
    if (!parent) return c.json({ error: '親フォルダが見つかりません' }, 404);
  }

  const result = await c.env.DB.prepare(
    'INSERT INTO folders (name, parent_id, user_id) VALUES (?, ?, ?)'
  ).bind(name, parent_id || null, user.id).run();

  return c.json({ id: result.meta.last_row_id, name, parent_id: parent_id || null, user_id: user.id });
});

app.put('/folders/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const { name, parent_id } = await c.req.json();

  // Prevent circular reference
  if (parent_id) {
    let current = parent_id;
    while (current) {
      if (current == folderId) return c.json({ error: '循環参照になるため移動できません' }, 400);
      const p = await c.env.DB.prepare('SELECT parent_id FROM folders WHERE id = ?').bind(current).first();
      current = p ? p.parent_id : null;
    }
  }

  await c.env.DB.prepare('UPDATE folders SET name = COALESCE(?, name), parent_id = ? WHERE id = ?')
    .bind(name || folder.name, parent_id !== undefined ? parent_id : folder.parent_id, folderId).run();

  return c.json({ ok: true });
});

app.delete('/folders/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  // Move pins to "all" (no folder)
  await c.env.DB.prepare('UPDATE pins SET folder_id = NULL WHERE folder_id = ?').bind(folderId).run();
  // Move child folders to parent
  await c.env.DB.prepare('UPDATE folders SET parent_id = ? WHERE parent_id = ?')
    .bind(folder.parent_id, folderId).run();

  await c.env.DB.prepare('DELETE FROM folders WHERE id = ?').bind(folderId).run();

  return c.json({ ok: true });
});

// Share pin folder
app.post('/folders/:id/share', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const folderId = c.req.param('id');

  const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(folderId).first();
  if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const { user_ids } = await c.req.json();

  // Clear existing shares and add new ones
  await c.env.DB.prepare('DELETE FROM folder_shares WHERE folder_id = ?').bind(folderId).run();

  for (const uid of (user_ids || [])) {
    await c.env.DB.prepare(
      'INSERT INTO folder_shares (folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(folderId, uid).run();
  }

  return c.json({ ok: true });
});

// ==================== Pins API ====================
app.get('/pins', async (c) => {
  const user = c.get('user');

  let pins;
  if (user && user.is_admin) {
    // Admin sees all pins
    pins = await c.env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        (SELECT GROUP_CONCAT(id || ':' || r2_key || ':' || original_name, '|')
         FROM pin_images WHERE pin_id = p.id) as images_raw
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `).all();
  } else if (user) {
    // Logged in: own pins + public + shared folder pins
    pins = await c.env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        (SELECT GROUP_CONCAT(id || ':' || r2_key || ':' || original_name, '|')
         FROM pin_images WHERE pin_id = p.id) as images_raw
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.is_public = 1
        OR p.user_id = ?
        OR p.folder_id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      ORDER BY p.created_at DESC
    `).bind(user.id, user.id).all();
  } else {
    // Anonymous: only public pins
    pins = await c.env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        (SELECT GROUP_CONCAT(id || ':' || r2_key || ':' || original_name, '|')
         FROM pin_images WHERE pin_id = p.id) as images_raw
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.is_public = 1
      ORDER BY p.created_at DESC
    `).all();
  }

  // Parse images
  const result = pins.results.map(p => {
    const images = p.images_raw ? p.images_raw.split('|').map(s => {
      const [id, r2_key, original_name] = s.split(':');
      return { id: parseInt(id), r2_key, original_name };
    }) : [];
    delete p.images_raw;
    return { ...p, images };
  });

  return c.json(result);
});

app.post('/pins', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');

  const contentType = c.req.header('content-type') || '';
  let title, description, lat, lng, folder_id, is_public, imageFiles = [];

  if (contentType.includes('multipart/form-data')) {
    // Form data with images
    const formData = await c.req.formData();
    title = formData.get('title');
    description = formData.get('description') || '';
    lat = parseFloat(formData.get('lat'));
    lng = parseFloat(formData.get('lng'));
    folder_id = formData.get('folder_id') || null;
    is_public = formData.get('is_public') === 'true';
    imageFiles = formData.getAll('images');
  } else {
    // JSON
    const body = await c.req.json();
    title = body.title;
    description = body.description || '';
    lat = body.lat;
    lng = body.lng;
    folder_id = body.folder_id || null;
    is_public = body.is_public;
  }

  if (!title || lat == null || lng == null) {
    return c.json({ error: 'タイトルと座標は必須です' }, 400);
  }

  if (folder_id) {
    const folder = await c.env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(folder_id, user.id).first();
    if (!folder) return c.json({ error: 'フォルダが見つかりません' }, 400);
  }

  // Only admin can make public
  const publicFlag = user.is_admin && is_public ? 1 : 0;

  const result = await c.env.DB.prepare(
    'INSERT INTO pins (title, description, lat, lng, folder_id, user_id, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(title, description, lat, lng, folder_id, user.id, publicFlag).run();

  const pinId = result.meta.last_row_id;
  const images = [];

  // Upload images if any
  for (const file of imageFiles) {
    if (!file || !file.name) continue;
    const r2Key = `images/${crypto.randomUUID()}-${file.name}`;
    await c.env.R2.put(r2Key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    const imgResult = await c.env.DB.prepare(
      'INSERT INTO pin_images (pin_id, r2_key, original_name) VALUES (?, ?, ?)'
    ).bind(pinId, r2Key, file.name).run();
    images.push({ id: imgResult.meta.last_row_id, r2_key: r2Key, original_name: file.name });
  }

  return c.json({
    id: pinId, title, description, lat, lng,
    folder_id, user_id: user.id, is_public: publicFlag, images
  });
});

app.put('/pins/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const pinId = c.req.param('id');

  const pin = await c.env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(pinId).first();
  if (!pin) return c.json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const { title, description, folder_id, is_public } = await c.req.json();

  // Only admin can make public, otherwise keep current value
  const publicFlag = user.is_admin ? (is_public ? 1 : 0) : pin.is_public;

  await c.env.DB.prepare(`
    UPDATE pins SET title = COALESCE(?, title), description = COALESCE(?, description),
    folder_id = ?, is_public = ? WHERE id = ?
  `).bind(
    title || pin.title,
    description !== undefined ? description : pin.description,
    folder_id !== undefined ? folder_id : pin.folder_id,
    publicFlag,
    pinId
  ).run();

  return c.json({ ok: true });
});

app.delete('/pins/:id', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const pinId = c.req.param('id');

  const pin = await c.env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(pinId).first();
  if (!pin) return c.json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  // Delete images from R2
  const images = await c.env.DB.prepare('SELECT r2_key FROM pin_images WHERE pin_id = ?').bind(pinId).all();
  for (const img of images.results) {
    await c.env.R2.delete(img.r2_key);
  }

  await c.env.DB.prepare('DELETE FROM pins WHERE id = ?').bind(pinId).run();

  return c.json({ ok: true });
});

// ==================== Pin Images API ====================
app.post('/pins/:id/images', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const pinId = c.req.param('id');

  const pin = await c.env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(pinId).first();
  if (!pin) return c.json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const formData = await c.req.formData();
  const files = formData.getAll('images');
  const inserted = [];

  for (const file of files) {
    if (!file || !file.name) continue;
    const r2Key = `images/${crypto.randomUUID()}-${file.name}`;
    await c.env.R2.put(r2Key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    const result = await c.env.DB.prepare(
      'INSERT INTO pin_images (pin_id, r2_key, original_name) VALUES (?, ?, ?)'
    ).bind(pinId, r2Key, file.name).run();
    inserted.push({ id: result.meta.last_row_id, r2_key: r2Key, original_name: file.name });
  }

  return c.json(inserted);
});

app.get('/images/:key', async (c) => {
  const key = c.req.param('key');
  const obj = await c.env.R2.get(`images/${key}`);
  if (!obj) return c.json({ error: '画像が見つかりません' }, 404);

  const headers = new Headers();
  headers.set('Content-Type', obj.httpMetadata?.contentType || 'image/jpeg');
  headers.set('Cache-Control', 'public, max-age=31536000');

  return new Response(obj.body, { headers });
});

app.delete('/pins/:pinId/images/:imageId', async (c) => {
  const err = requireAuth(c);
  if (err) return err;
  const user = c.get('user');
  const { pinId, imageId } = c.req.param();

  const pin = await c.env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(pinId).first();
  if (!pin) return c.json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return c.json({ error: '権限がありません' }, 403);
  }

  const img = await c.env.DB.prepare('SELECT * FROM pin_images WHERE id = ? AND pin_id = ?')
    .bind(imageId, pinId).first();
  if (!img) return c.json({ error: '画像が見つかりません' }, 404);

  await c.env.R2.delete(img.r2_key);
  await c.env.DB.prepare('DELETE FROM pin_images WHERE id = ?').bind(imageId).run();

  return c.json({ ok: true });
});

// Cloudflare Pages Functions export
export const onRequest = (context) => {
  return app.fetch(context.request, context.env, context);
};
