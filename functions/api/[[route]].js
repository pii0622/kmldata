// Cloudflare Pages Functions - No external dependencies

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

function getCookie(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

function setCookieHeader(name, value, options = {}) {
  let cookie = `${name}=${value}`;
  if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  cookie += '; Path=/';
  return cookie;
}

// Security headers
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...securityHeaders, ...headers }
  });
}

function convertKmlPolygonToLine(kml) {
  return kml.replace(
    /<Polygon[^>]*>[\s\S]*?<outerBoundaryIs>\s*<LinearRing>\s*<coordinates>([\s\S]*?)<\/coordinates>\s*<\/LinearRing>\s*<\/outerBoundaryIs>[\s\S]*?<\/Polygon>/gi,
    '<LineString><coordinates>$1</coordinates></LineString>'
  );
}

// ==================== Main Handler ====================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  const method = request.method;

  // Warn if JWT_SECRET is not set (check once per request for logging)
  if (!env.JWT_SECRET) {
    console.warn('WARNING: JWT_SECRET environment variable is not set. Using insecure default.');
  }

  // CORS headers - only allow same origin for security
  const origin = request.headers.get('Origin');
  const allowedOrigin = origin && (
    origin === url.origin ||
    origin.endsWith('.pages.dev') ||
    env.ALLOWED_ORIGIN === origin
  ) ? origin : url.origin;

  const corsHeaders = {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    ...securityHeaders
  };

  if (method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // Get current user from cookie
  let user = null;
  const token = getCookie(request, 'auth');
  if (token) {
    user = await verifyToken(token, env.JWT_SECRET || 'default-secret');
  }

  try {
    // Route matching
    // Auth routes
    if (path === '/auth/register' && method === 'POST') {
      return await handleRegister(request, env);
    }
    if (path === '/auth/login' && method === 'POST') {
      return await handleLogin(request, env);
    }
    if (path === '/auth/logout' && method === 'POST') {
      return handleLogout();
    }
    if (path === '/auth/me' && method === 'GET') {
      return json(user);
    }
    if (path === '/auth/profile' && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleUpdateProfile(request, env, user);
    }
    if (path === '/auth/password' && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleChangePassword(request, env, user);
    }

    // Users
    if (path === '/users' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetUsers(env, user);
    }

    // KML Folders
    if (path === '/kml-folders' && method === 'GET') {
      return await handleGetKmlFolders(env, user);
    }
    if (path === '/kml-folders' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreateKmlFolder(request, env, user);
    }
    if (path.match(/^\/kml-folders\/(\d+)$/) && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)$/)[1];
      return await handleRenameKmlFolder(request, env, user, id);
    }
    if (path.match(/^\/kml-folders\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)$/)[1];
      return await handleDeleteKmlFolder(env, user, id);
    }
    if (path.match(/^\/kml-folders\/(\d+)\/visibility$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)\/visibility$/)[1];
      return await handleKmlFolderVisibility(request, env, user, id);
    }
    if (path.match(/^\/kml-folders\/(\d+)\/share$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)\/share$/)[1];
      return await handleShareKmlFolder(request, env, user, id);
    }
    if (path.match(/^\/kml-folders\/(\d+)\/reorder$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)\/reorder$/)[1];
      return await handleReorderKmlFolder(request, env, user, id);
    }

    // KML Files
    if (path === '/kml-files' && method === 'GET') {
      return await handleGetKmlFiles(env, user, url);
    }
    if (path === '/kml-files/upload' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleUploadKmlFile(request, env, user);
    }
    if (path.match(/^\/kml-files\/(.+)$/) && method === 'GET') {
      const key = path.match(/^\/kml-files\/(.+)$/)[1];
      return await handleGetKmlFile(env, key);
    }
    if (path.match(/^\/kml-files\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-files\/(\d+)$/)[1];
      return await handleDeleteKmlFile(env, user, id);
    }

    // Pin Folders
    if (path === '/folders' && method === 'GET') {
      return await handleGetFolders(env, user);
    }
    if (path === '/folders' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreateFolder(request, env, user);
    }
    if (path.match(/^\/folders\/(\d+)$/) && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)$/)[1];
      return await handleRenameFolder(request, env, user, id);
    }
    if (path.match(/^\/folders\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)$/)[1];
      return await handleDeleteFolder(env, user, id);
    }
    if (path.match(/^\/folders\/(\d+)\/share$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)\/share$/)[1];
      return await handleShareFolder(request, env, user, id);
    }
    if (path.match(/^\/folders\/(\d+)\/reorder$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)\/reorder$/)[1];
      return await handleReorderFolder(request, env, user, id);
    }

    // Pins
    if (path === '/pins' && method === 'GET') {
      return await handleGetPins(env, user);
    }
    if (path === '/pins' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreatePin(request, env, user);
    }
    if (path.match(/^\/pins\/(\d+)$/) && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/pins\/(\d+)$/)[1];
      return await handleUpdatePin(request, env, user, id);
    }
    if (path.match(/^\/pins\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/pins\/(\d+)$/)[1];
      return await handleDeletePin(env, user, id);
    }
    if (path.match(/^\/pins\/(\d+)\/images$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/pins\/(\d+)\/images$/)[1];
      return await handleAddPinImages(request, env, user, id);
    }
    if (path.match(/^\/pins\/(\d+)\/images\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const match = path.match(/^\/pins\/(\d+)\/images\/(\d+)$/);
      return await handleDeletePinImage(env, user, match[1], match[2]);
    }

    // Images
    if (path.match(/^\/images\/(.+)$/) && method === 'GET') {
      const key = path.match(/^\/images\/(.+)$/)[1];
      return await handleGetImage(env, key);
    }

    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: err.message || 'Server error' }, 500);
  }
}

// ==================== Auth Handlers ====================
async function handleRegister(request, env) {
  const { username, password, display_name } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }
  if (username.length < 3) {
    return json({ error: 'ユーザー名は3文字以上にしてください' }, 400);
  }
  if (password.length < 4) {
    return json({ error: 'パスワードは4文字以上にしてください' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    return json({ error: 'そのユーザー名は既に使われています' }, 400);
  }

  // Check if display name is already used
  const actualDisplayName = (display_name || username).trim();
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ?').bind(actualDisplayName).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  const hash = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)'
  ).bind(username, hash, display_name || username).run();

  const userId = result.meta.last_row_id;
  const token = await createToken({ id: userId, username, display_name: display_name || username, is_admin: false }, env.JWT_SECRET || 'default-secret');

  return json(
    { id: userId, username, display_name: display_name || username, is_admin: false },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: 'ユーザー名またはパスワードが正しくありません' }, 401);
  }

  const token = await createToken({
    id: user.id, username: user.username,
    display_name: user.display_name || user.username,
    is_admin: !!user.is_admin
  }, env.JWT_SECRET || 'default-secret');

  return json(
    { id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

function handleLogout() {
  return json({ ok: true }, 200, { 'Set-Cookie': setCookieHeader('auth', '', { maxAge: 0 }) });
}

async function handleUpdateProfile(request, env, user) {
  const { display_name } = await request.json();
  if (!display_name || !display_name.trim()) {
    return json({ error: '表示名を入力してください' }, 400);
  }

  // Check if display name is already used by another user
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
    .bind(display_name.trim(), user.id).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  await env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?')
    .bind(display_name.trim(), user.id).run();

  // Create new token with updated display_name
  const token = await createToken({
    id: user.id,
    username: user.username,
    display_name: display_name.trim(),
    is_admin: user.is_admin
  }, env.JWT_SECRET || 'default-secret');

  return json(
    { ok: true, display_name: display_name.trim() },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleChangePassword(request, env, user) {
  const { current_password, new_password } = await request.json();

  if (!current_password) {
    return json({ error: '現在のパスワードを入力してください' }, 400);
  }
  if (!new_password || new_password.length < 4) {
    return json({ error: '新しいパスワードは4文字以上にしてください' }, 400);
  }

  // Verify current password
  const dbUser = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?')
    .bind(user.id).first();
  if (!dbUser || !(await verifyPassword(current_password, dbUser.password_hash))) {
    return json({ error: '現在のパスワードが正しくありません' }, 401);
  }

  // Update password
  const newHash = await hashPassword(new_password);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE id = ?')
    .bind(newHash, user.id).run();

  return json({ ok: true });
}

// ==================== Users Handlers ====================
async function handleGetUsers(env, user) {
  const users = await env.DB.prepare(
    'SELECT id, username, display_name, is_admin FROM users WHERE id != ? ORDER BY display_name'
  ).bind(user.id).all();
  return json(users.results);
}

// ==================== KML Folders Handlers ====================
async function handleGetKmlFolders(env, user) {
  let folders;
  if (user) {
    folders = await env.DB.prepare(`
      SELECT kf.*, u.display_name as owner_name,
        CASE WHEN kf.user_id = ? THEN 1 ELSE 0 END as is_owner,
        COALESCE(kfv.is_visible, 1) as is_visible
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      LEFT JOIN kml_folder_visibility kfv ON kf.id = kfv.kml_folder_id AND kfv.user_id = ?
      WHERE kf.user_id = ? OR kf.is_public = 1
        OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
      ORDER BY kf.sort_order, kf.name
    `).bind(user.id, user.id, user.id, user.id).all();
  } else {
    folders = await env.DB.prepare(`
      SELECT kf.*, u.display_name as owner_name, 0 as is_owner, 1 as is_visible
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      WHERE kf.is_public = 1
      ORDER BY kf.sort_order, kf.name
    `).all();
  }
  return json(folders.results);
}

async function handleCreateKmlFolder(request, env, user) {
  const { name, is_public } = await request.json();
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  const publicFlag = user.is_admin && is_public ? 1 : 0;
  const result = await env.DB.prepare(
    'INSERT INTO kml_folders (name, user_id, is_public) VALUES (?, ?, ?)'
  ).bind(name, user.id, publicFlag).run();

  return json({ id: result.meta.last_row_id, name, user_id: user.id, is_public: publicFlag });
}

async function handleRenameKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { name, is_public } = await request.json();
  if (!name || !name.trim()) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Only admin can change is_public
  const publicFlag = user.is_admin && is_public !== undefined ? (is_public ? 1 : 0) : folder.is_public;

  await env.DB.prepare('UPDATE kml_folders SET name = ?, is_public = ? WHERE id = ?')
    .bind(name.trim(), publicFlag, id).run();
  return json({ ok: true, name: name.trim(), is_public: publicFlag });
}

async function handleDeleteKmlFolder(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  // Delete KML files from R2
  const files = await env.DB.prepare('SELECT r2_key FROM kml_files WHERE folder_id = ?').bind(id).all();
  for (const f of files.results) {
    await env.R2.delete(f.r2_key);
  }

  // Delete KML files from DB
  await env.DB.prepare('DELETE FROM kml_files WHERE folder_id = ?').bind(id).run();

  // Delete folder shares
  await env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id = ?').bind(id).run();

  // Delete visibility settings
  await env.DB.prepare('DELETE FROM kml_folder_visibility WHERE kml_folder_id = ?').bind(id).run();

  // Delete folder
  await env.DB.prepare('DELETE FROM kml_folders WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function handleKmlFolderVisibility(request, env, user, id) {
  const { is_visible } = await request.json();
  await env.DB.prepare(`
    INSERT INTO kml_folder_visibility (kml_folder_id, user_id, is_visible) VALUES (?, ?, ?)
    ON CONFLICT(kml_folder_id, user_id) DO UPDATE SET is_visible = excluded.is_visible
  `).bind(id, user.id, is_visible ? 1 : 0).run();
  return json({ ok: true });
}

async function handleShareKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await request.json();
  await env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id = ?').bind(id).run();

  for (const uid of (user_ids || [])) {
    await env.DB.prepare(
      'INSERT INTO kml_folder_shares (kml_folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(id, uid).run();
  }
  return json({ ok: true });
}

async function handleReorderKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await request.json();
  const target = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(target_id).first();
  if (!target) return json({ error: '移動先が見つかりません' }, 404);

  // Swap sort_order values
  const sourceOrder = folder.sort_order || 0;
  const targetOrder = target.sort_order || 0;

  await env.DB.prepare('UPDATE kml_folders SET sort_order = ? WHERE id = ?')
    .bind(targetOrder, id).run();
  await env.DB.prepare('UPDATE kml_folders SET sort_order = ? WHERE id = ?')
    .bind(sourceOrder, target_id).run();

  return json({ ok: true });
}

// ==================== KML Files Handlers ====================
async function handleGetKmlFiles(env, user, url) {
  const folderId = url.searchParams.get('folder_id');
  let query, bindings = [];

  if (user) {
    if (folderId) {
      query = `SELECT kf.*, u.display_name as owner_name FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        WHERE kf.folder_id = ? AND (kf.user_id = ? OR kf.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?))
        ORDER BY kf.original_name`;
      bindings = [folderId, user.id, user.id];
    } else {
      query = `SELECT kf.*, u.display_name as owner_name FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        WHERE kf.user_id = ? OR kf.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
        ORDER BY kf.original_name`;
      bindings = [user.id, user.id];
    }
  } else {
    query = `SELECT kf.*, u.display_name as owner_name FROM kml_files kf
      LEFT JOIN users u ON kf.user_id = u.id WHERE kf.is_public = 1 ORDER BY kf.original_name`;
  }

  const stmt = env.DB.prepare(query);
  const files = bindings.length > 0 ? await stmt.bind(...bindings).all() : await stmt.all();
  return json(files.results);
}

async function handleUploadKmlFile(request, env, user) {
  const formData = await request.formData();
  const file = formData.get('kml');
  const folderId = formData.get('folder_id');
  const isPublic = formData.get('is_public');

  if (!file) return json({ error: 'ファイルが選択されていません' }, 400);

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'kml' && ext !== 'kmz') {
    return json({ error: 'KMLまたはKMZファイルのみアップロード可能です' }, 400);
  }

  const r2Key = `kml/${crypto.randomUUID()}.${ext}`;
  let content = await file.text();
  if (ext === 'kml') {
    content = convertKmlPolygonToLine(content);
  }

  await env.R2.put(r2Key, content, {
    httpMetadata: { contentType: ext === 'kml' ? 'application/vnd.google-earth.kml+xml' : 'application/vnd.google-earth.kmz' }
  });

  const publicFlag = user.is_admin && isPublic === 'true' ? 1 : 0;
  const result = await env.DB.prepare(
    'INSERT INTO kml_files (folder_id, user_id, r2_key, original_name, is_public) VALUES (?, ?, ?, ?, ?)'
  ).bind(folderId || null, user.id, r2Key, file.name, publicFlag).run();

  return json({ id: result.meta.last_row_id, r2_key: r2Key, original_name: file.name, folder_id: folderId || null, is_public: publicFlag });
}

async function handleGetKmlFile(env, key) {
  const obj = await env.R2.get(`kml/${key}`);
  if (!obj) return json({ error: 'ファイルが見つかりません' }, 404);

  return new Response(obj.body, {
    headers: { 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream' }
  });
}

async function handleDeleteKmlFile(env, user, id) {
  const file = await env.DB.prepare('SELECT * FROM kml_files WHERE id = ?').bind(id).first();
  if (!file) return json({ error: 'ファイルが見つかりません' }, 404);
  if (file.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  await env.R2.delete(file.r2_key);
  await env.DB.prepare('DELETE FROM kml_files WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

// ==================== Pin Folders Handlers ====================
async function handleGetFolders(env, user) {
  if (!user) {
    // Non-logged in users can see public folders
    const folders = await env.DB.prepare(`
      SELECT f.*, u.display_name as owner_name, 0 as is_owner
      FROM folders f
      LEFT JOIN users u ON f.user_id = u.id
      WHERE f.is_public = 1
      ORDER BY f.sort_order, f.name
    `).all();
    return json(folders.results);
  }

  const folders = await env.DB.prepare(`
    SELECT f.*, u.display_name as owner_name,
      CASE WHEN f.user_id = ? THEN 1 ELSE 0 END as is_owner
    FROM folders f
    LEFT JOIN users u ON f.user_id = u.id
    WHERE f.user_id = ? OR f.is_public = 1 OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
    ORDER BY f.sort_order, f.name
  `).bind(user.id, user.id, user.id).all();

  return json(folders.results);
}

async function handleCreateFolder(request, env, user) {
  const { name, parent_id, is_public } = await request.json();
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(parent_id, user.id).first();
    if (!parent) return json({ error: '親フォルダが見つかりません' }, 404);
  }

  const publicFlag = user.is_admin && is_public ? 1 : 0;
  const result = await env.DB.prepare(
    'INSERT INTO folders (name, parent_id, user_id, is_public) VALUES (?, ?, ?, ?)'
  ).bind(name, parent_id || null, user.id, publicFlag).run();

  return json({ id: result.meta.last_row_id, name, parent_id: parent_id || null, user_id: user.id, is_public: publicFlag });
}

async function handleRenameFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { name, is_public } = await request.json();
  if (!name || !name.trim()) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Only admin can change is_public
  const publicFlag = user.is_admin && is_public !== undefined ? (is_public ? 1 : 0) : (folder.is_public || 0);

  await env.DB.prepare('UPDATE folders SET name = ?, is_public = ? WHERE id = ?')
    .bind(name.trim(), publicFlag, id).run();
  return json({ ok: true, name: name.trim(), is_public: publicFlag });
}

async function handleDeleteFolder(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  // Delete pin images from R2
  const pinsInFolder = await env.DB.prepare('SELECT id FROM pins WHERE folder_id = ?').bind(id).all();
  for (const pin of pinsInFolder.results) {
    const images = await env.DB.prepare('SELECT r2_key FROM pin_images WHERE pin_id = ?').bind(pin.id).all();
    for (const img of images.results) {
      await env.R2.delete(img.r2_key);
    }
  }

  // Delete pins in this folder
  await env.DB.prepare('DELETE FROM pins WHERE folder_id = ?').bind(id).run();

  // Delete child folders recursively
  const childFolders = await env.DB.prepare('SELECT id FROM folders WHERE parent_id = ?').bind(id).all();
  for (const child of childFolders.results) {
    await handleDeleteFolder(env, user, child.id);
  }

  // Delete folder shares
  await env.DB.prepare('DELETE FROM folder_shares WHERE folder_id = ?').bind(id).run();

  // Delete the folder itself
  await env.DB.prepare('DELETE FROM folders WHERE id = ?').bind(id).run();

  return json({ ok: true });
}

async function handleShareFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await request.json();
  await env.DB.prepare('DELETE FROM folder_shares WHERE folder_id = ?').bind(id).run();

  for (const uid of (user_ids || [])) {
    await env.DB.prepare(
      'INSERT INTO folder_shares (folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(id, uid).run();
  }
  return json({ ok: true });
}

async function handleReorderFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await request.json();
  const target = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(target_id).first();
  if (!target) return json({ error: '移動先が見つかりません' }, 404);

  // Swap sort_order values
  const sourceOrder = folder.sort_order || 0;
  const targetOrder = target.sort_order || 0;

  await env.DB.prepare('UPDATE folders SET sort_order = ? WHERE id = ?')
    .bind(targetOrder, id).run();
  await env.DB.prepare('UPDATE folders SET sort_order = ? WHERE id = ?')
    .bind(sourceOrder, target_id).run();

  return json({ ok: true });
}

// ==================== Pins Handlers ====================
async function handleGetPins(env, user) {
  let pins;
  if (user && user.is_admin) {
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author FROM pins p
      LEFT JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC
    `).all();
  } else if (user) {
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      WHERE p.is_public = 1 OR p.user_id = ?
        OR p.folder_id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      ORDER BY p.created_at DESC
    `).bind(user.id, user.id).all();
  } else {
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author FROM pins p
      LEFT JOIN users u ON p.user_id = u.id WHERE p.is_public = 1 ORDER BY p.created_at DESC
    `).all();
  }

  // Get images for each pin
  const result = [];
  for (const p of pins.results) {
    const images = await env.DB.prepare('SELECT id, r2_key, original_name FROM pin_images WHERE pin_id = ?').bind(p.id).all();
    result.push({ ...p, images: images.results });
  }

  return json(result);
}

async function handleCreatePin(request, env, user) {
  const contentType = request.headers.get('content-type') || '';
  let title, description, lat, lng, folder_id, is_public, imageFiles = [];

  if (contentType.includes('multipart/form-data')) {
    const formData = await request.formData();
    title = formData.get('title');
    description = formData.get('description') || '';
    lat = parseFloat(formData.get('lat'));
    lng = parseFloat(formData.get('lng'));
    folder_id = formData.get('folder_id') || null;
    is_public = formData.get('is_public') === 'true';
    imageFiles = formData.getAll('images');
  } else {
    const body = await request.json();
    title = body.title;
    description = body.description || '';
    lat = body.lat;
    lng = body.lng;
    folder_id = body.folder_id || null;
    is_public = body.is_public;
  }

  if (!title || lat == null || lng == null) {
    return json({ error: 'タイトルと座標は必須です' }, 400);
  }

  const publicFlag = user.is_admin && is_public ? 1 : 0;

  const result = await env.DB.prepare(
    'INSERT INTO pins (title, description, lat, lng, folder_id, user_id, is_public) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(title, description, lat, lng, folder_id, user.id, publicFlag).run();

  const pinId = result.meta.last_row_id;
  const images = [];

  for (const file of imageFiles) {
    if (!file || !file.name) continue;
    const r2Key = `images/${crypto.randomUUID()}-${file.name}`;
    await env.R2.put(r2Key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    const imgResult = await env.DB.prepare(
      'INSERT INTO pin_images (pin_id, r2_key, original_name) VALUES (?, ?, ?)'
    ).bind(pinId, r2Key, file.name).run();
    images.push({ id: imgResult.meta.last_row_id, r2_key: r2Key, original_name: file.name });
  }

  return json({ id: pinId, title, description, lat, lng, folder_id, user_id: user.id, is_public: publicFlag, images });
}

async function handleUpdatePin(request, env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { title, description, folder_id, is_public } = await request.json();
  const publicFlag = user.is_admin ? (is_public ? 1 : 0) : pin.is_public;

  await env.DB.prepare(`
    UPDATE pins SET title = COALESCE(?, title), description = COALESCE(?, description),
    folder_id = ?, is_public = ? WHERE id = ?
  `).bind(title || pin.title, description !== undefined ? description : pin.description,
    folder_id !== undefined ? folder_id : pin.folder_id, publicFlag, id).run();

  return json({ ok: true });
}

async function handleDeletePin(env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const images = await env.DB.prepare('SELECT r2_key FROM pin_images WHERE pin_id = ?').bind(id).all();
  for (const img of images.results) {
    await env.R2.delete(img.r2_key);
  }

  await env.DB.prepare('DELETE FROM pins WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function handleAddPinImages(request, env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const formData = await request.formData();
  const files = formData.getAll('images');
  const inserted = [];

  for (const file of files) {
    if (!file || !file.name) continue;
    const r2Key = `images/${crypto.randomUUID()}-${file.name}`;
    await env.R2.put(r2Key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    const result = await env.DB.prepare(
      'INSERT INTO pin_images (pin_id, r2_key, original_name) VALUES (?, ?, ?)'
    ).bind(id, r2Key, file.name).run();
    inserted.push({ id: result.meta.last_row_id, r2_key: r2Key, original_name: file.name });
  }

  return json(inserted);
}

async function handleDeletePinImage(env, user, pinId, imageId) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(pinId).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const img = await env.DB.prepare('SELECT * FROM pin_images WHERE id = ? AND pin_id = ?')
    .bind(imageId, pinId).first();
  if (!img) return json({ error: '画像が見つかりません' }, 404);

  await env.R2.delete(img.r2_key);
  await env.DB.prepare('DELETE FROM pin_images WHERE id = ?').bind(imageId).run();
  return json({ ok: true });
}

async function handleGetImage(env, key) {
  const obj = await env.R2.get(`images/${key}`);
  if (!obj) return json({ error: '画像が見つかりません' }, 404);

  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
      'Cache-Control': 'public, max-age=31536000'
    }
  });
}
