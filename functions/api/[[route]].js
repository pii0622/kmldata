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
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-XSS-Protection': '1; mode=block',
  'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()'
};

// Content Security Policy for HTML responses
const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; img-src 'self' https://cyberjapandata.gsi.go.jp data: blob:; connect-src 'self' https://cyberjapandata.gsi.go.jp; font-src 'self' https://cdnjs.cloudflare.com;";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...securityHeaders, ...headers }
  });
}

// Rate limiting configuration
const RATE_LIMITS = {
  login: { maxRequests: 5, windowSeconds: 300 },      // 5 attempts per 5 minutes
  register: { maxRequests: 5, windowSeconds: 3600 },  // 5 attempts per hour
  default: { maxRequests: 100, windowSeconds: 60 }    // 100 requests per minute
};

async function checkRateLimit(env, ip, endpoint) {
  const config = RATE_LIMITS[endpoint] || RATE_LIMITS.default;
  const key = `${ip}:${endpoint}`;
  const now = new Date();
  const windowStart = new Date(now.getTime() - config.windowSeconds * 1000).toISOString();

  // Clean up old entries and get current count
  await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(windowStart).run();

  const existing = await env.DB.prepare('SELECT * FROM rate_limits WHERE key = ?').bind(key).first();

  if (existing) {
    if (existing.count >= config.maxRequests) {
      return { allowed: false, retryAfter: config.windowSeconds };
    }
    await env.DB.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').bind(key).run();
  } else {
    await env.DB.prepare('INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)').bind(key, now.toISOString()).run();
  }

  return { allowed: true };
}

async function logSecurityEvent(env, eventType, userId, request, details = {}) {
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';

  try {
    await env.DB.prepare(
      'INSERT INTO security_logs (event_type, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)'
    ).bind(eventType, userId, ip, userAgent, JSON.stringify(details)).run();
  } catch (err) {
    console.error('Failed to log security event:', err);
  }
}

// Email sending via Resend (https://resend.com)
// Free tier: 100 emails/day
// Setup: Add RESEND_API_KEY to Cloudflare Pages environment variables
const EMAIL_FROM = 'hello@map.taishi-lab.com';
const EMAIL_FROM_NAME = '地図アプリ';

async function sendEmail(env, to, subject, htmlBody, textBody) {
  // Check if Resend API key is configured
  if (!env.RESEND_API_KEY) {
    console.error('Email send failed: RESEND_API_KEY not configured');
    return false;
  }

  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${env.RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: `${EMAIL_FROM_NAME} <${EMAIL_FROM}>`,
        to: [to],
        subject: subject,
        html: htmlBody,
        text: textBody
      })
    });

    if (!response.ok) {
      const errData = await response.json();
      console.error('Email send failed:', response.status, JSON.stringify(errData));
      return false;
    }

    const result = await response.json();
    console.log('Email sent successfully:', result.id);
    return true;
  } catch (err) {
    console.error('Email send error:', err);
    return false;
  }
}

function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
         'unknown';
}

// Allowed image types and max size
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_IMAGE_SIZE = 10 * 1024 * 1024; // 10MB
const MAX_KML_SIZE = 50 * 1024 * 1024; // 50MB

function validateImageFile(file) {
  if (!file || !file.name) return { valid: false, error: 'ファイルが無効です' };
  if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    return { valid: false, error: `許可されていないファイル形式です: ${file.type}` };
  }
  if (file.size > MAX_IMAGE_SIZE) {
    return { valid: false, error: `ファイルサイズが大きすぎます（最大10MB）: ${file.name}` };
  }
  // Check extension matches type
  const ext = file.name.split('.').pop().toLowerCase();
  const validExts = { 'image/jpeg': ['jpg', 'jpeg'], 'image/png': ['png'], 'image/gif': ['gif'], 'image/webp': ['webp'] };
  if (!validExts[file.type]?.includes(ext)) {
    return { valid: false, error: `ファイル拡張子が不正です: ${file.name}` };
  }
  return { valid: true };
}

function convertKmlPolygonToLine(kml) {
  return kml.replace(
    /<Polygon[^>]*>[\s\S]*?<outerBoundaryIs>\s*<LinearRing>\s*<coordinates>([\s\S]*?)<\/coordinates>\s*<\/LinearRing>\s*<\/outerBoundaryIs>[\s\S]*?<\/Polygon>/gi,
    '<LineString><coordinates>$1</coordinates></LineString>'
  );
}

// ==================== Auto Migration ====================
let tablesInitialized = false;

async function ensureTablesExist(env) {
  if (tablesInitialized) return;

  try {
    // Create all necessary tables if they don't exist
    await env.DB.batch([
      // Users table with status for approval system
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        is_admin INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      // Admin notifications
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        user_id INTEGER,
        is_read INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
      )`),
      // Security logs
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      // Rate limits
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        count INTEGER DEFAULT 1,
        window_start TEXT DEFAULT (datetime('now'))
      )`),
      // Folders
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        parent_id INTEGER,
        is_visible INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (parent_id) REFERENCES folders(id)
      )`),
      // Pins
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS pins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        folder_id INTEGER,
        title TEXT NOT NULL,
        description TEXT,
        latitude REAL NOT NULL,
        longitude REAL NOT NULL,
        is_public INTEGER DEFAULT 0,
        is_visible INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (folder_id) REFERENCES folders(id)
      )`),
      // Pin images
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS pin_images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pin_id INTEGER NOT NULL,
        filename TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE
      )`),
      // Pin shares
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS pin_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pin_id INTEGER NOT NULL,
        shared_with_user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
      )`),
      // Folder shares
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS folder_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_id INTEGER NOT NULL,
        shared_with_user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
      )`),
      // KML folders
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS kml_folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER NOT NULL,
        parent_id INTEGER,
        is_public INTEGER DEFAULT 0,
        is_visible INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_id) REFERENCES kml_folders(id) ON DELETE CASCADE
      )`),
      // KML files
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS kml_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_id INTEGER,
        user_id INTEGER NOT NULL,
        r2_key TEXT NOT NULL,
        original_name TEXT NOT NULL,
        is_public INTEGER DEFAULT 0,
        is_visible INTEGER DEFAULT 1,
        sort_order INTEGER DEFAULT 0,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (folder_id) REFERENCES kml_folders(id) ON DELETE SET NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`)
    ]);

    // Add email column to existing users table if it doesn't exist
    try {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN email TEXT').run();
    } catch (e) {
      // Column might already exist, ignore error
    }

    tablesInitialized = true;
  } catch (err) {
    console.error('Table initialization error:', err);
    // Continue anyway - tables might already exist with different schema
    tablesInitialized = true;
  }
}

// ==================== Main Handler ====================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  const method = request.method;

  // Auto-create tables on first request
  await ensureTablesExist(env);

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
    // Auth routes with rate limiting
    if (path === '/auth/register' && method === 'POST') {
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'register');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', null, request, { endpoint: 'register' });
        return json({ error: '登録の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handleRegister(request, env);
    }
    if (path === '/auth/login' && method === 'POST') {
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'login');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', null, request, { endpoint: 'login' });
        return json({ error: 'ログインの試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handleLogin(request, env);
    }
    if (path === '/auth/refresh' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleTokenRefresh(env, user);
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

    // Admin routes
    if (path === '/admin/pending-users' && method === 'GET') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      return await handleGetPendingUsers(env);
    }
    if (path.match(/^\/admin\/users\/(\d+)\/approve$/) && method === 'POST') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      const id = path.match(/^\/admin\/users\/(\d+)\/approve$/)[1];
      return await handleApproveUser(env, id);
    }
    if (path.match(/^\/admin\/users\/(\d+)\/reject$/) && method === 'POST') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      const id = path.match(/^\/admin\/users\/(\d+)\/reject$/)[1];
      return await handleRejectUser(env, id);
    }
    if (path === '/admin/notifications' && method === 'GET') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      return await handleGetAdminNotifications(env);
    }
    if (path === '/admin/security-logs' && method === 'GET') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      return await handleGetSecurityLogs(env, url);
    }
    if (path.match(/^\/admin\/notifications\/(\d+)\/read$/) && method === 'POST') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      const id = path.match(/^\/admin\/notifications\/(\d+)\/read$/)[1];
      return await handleMarkNotificationRead(env, id);
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
    if (path.match(/^\/kml-folders\/(\d+)\/move$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)\/move$/)[1];
      return await handleMoveKmlFolder(request, env, user, id);
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
      return await handleGetKmlFile(env, user, key);
    }
    if (path.match(/^\/kml-files\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-files\/(\d+)$/)[1];
      return await handleDeleteKmlFile(env, user, id);
    }
    if (path.match(/^\/kml-files\/(\d+)\/move$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-files\/(\d+)\/move$/)[1];
      return await handleMoveKmlFile(request, env, user, id);
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
    if (path.match(/^\/folders\/(\d+)\/move$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)\/move$/)[1];
      return await handleMoveFolder(request, env, user, id);
    }
    if (path.match(/^\/folders\/(\d+)\/visibility$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)\/visibility$/)[1];
      return await handleFolderVisibility(request, env, user, id);
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
    if (path.match(/^\/pins\/(\d+)\/move$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/pins\/(\d+)\/move$/)[1];
      return await handleMovePin(request, env, user, id);
    }

    // Images
    if (path.match(/^\/images\/(.+)$/) && method === 'GET') {
      const key = path.match(/^\/images\/(.+)$/)[1];
      return await handleGetImage(env, user, key);
    }

    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(err);
    return json({ error: err.message || 'Server error' }, 500);
  }
}

// ==================== Auth Handlers ====================
async function handleTokenRefresh(env, user) {
  // Get fresh user data from DB
  const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!dbUser || dbUser.status !== 'approved') {
    return json({ error: 'ユーザーが見つかりません' }, 404);
  }

  const token = await createToken({
    id: dbUser.id,
    username: dbUser.username,
    display_name: dbUser.display_name || dbUser.username,
    is_admin: !!dbUser.is_admin
  }, env.JWT_SECRET || 'default-secret');

  return json(
    { ok: true },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleRegister(request, env) {
  const { username, password, email, display_name } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }
  if (!email) {
    return json({ error: 'メールアドレスを入力してください' }, 400);
  }
  // Validate email format
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    return json({ error: '有効なメールアドレスを入力してください' }, 400);
  }
  if (username.length < 3) {
    return json({ error: 'ユーザー名は3文字以上にしてください' }, 400);
  }
  // Validate username is full name in Roman letters (e.g., "Taro Yamada")
  const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
  if (!fullNamePattern.test(username.trim())) {
    return json({ error: 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）' }, 400);
  }
  if (password.length < 4) {
    return json({ error: 'パスワードは4文字以上にしてください' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    await logSecurityEvent(env, 'register_duplicate_username', null, request, { username });
    return json({ error: 'そのユーザー名は既に使われています' }, 400);
  }

  // Check if display name is already used
  const actualDisplayName = (display_name || username).trim();
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ?').bind(actualDisplayName).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  const hash = await hashPassword(password);
  // New users start with 'pending' status - must be approved by admin
  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, email, display_name, status) VALUES (?, ?, ?, ?, ?)'
  ).bind(username, hash, email, actualDisplayName, 'pending').run();

  const userId = result.meta.last_row_id;

  // Create admin notification for pending approval
  await env.DB.prepare(
    'INSERT INTO admin_notifications (type, message, data) VALUES (?, ?, ?)'
  ).bind('user_pending', `新規ユーザー「${actualDisplayName}」が承認待ちです`, JSON.stringify({ user_id: userId, username, display_name: actualDisplayName })).run();

  // Don't return token - user must wait for admin approval
  return json({
    pending: true,
    message: 'アカウント申請を受け付けました。管理者の承認をお待ちください。'
  });
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    await logSecurityEvent(env, 'login_failed', null, request, { username, reason: 'invalid_credentials' });
    return json({ error: 'ユーザー名またはパスワードが正しくありません' }, 401);
  }

  // Check user approval status
  if (user.status === 'pending') {
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'pending_approval' });
    return json({ error: 'アカウントは承認待ちです。管理者の承認をお待ちください。' }, 403);
  }
  if (user.status === 'rejected') {
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'rejected' });
    return json({ error: 'アカウントは承認されませんでした。' }, 403);
  }

  await logSecurityEvent(env, 'login_success', user.id, request, {});

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
    'SELECT id, username, display_name, is_admin FROM users WHERE id != ? AND status = ? ORDER BY display_name'
  ).bind(user.id, 'approved').all();
  return json(users.results);
}

// ==================== Admin Handlers ====================
async function handleGetPendingUsers(env) {
  const users = await env.DB.prepare(
    'SELECT id, username, display_name, created_at FROM users WHERE status = ? ORDER BY created_at DESC'
  ).bind('pending').all();
  return json(users.results);
}

async function handleApproveUser(env, id) {
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  if (!user) return json({ error: 'ユーザーが見つかりません' }, 404);
  if (user.status !== 'pending') return json({ error: 'このユーザーは既に処理済みです' }, 400);

  await env.DB.prepare('UPDATE users SET status = ? WHERE id = ?').bind('approved', id).run();

  // Mark related notifications as read
  await env.DB.prepare(`
    UPDATE admin_notifications SET is_read = 1
    WHERE type = 'user_pending' AND data LIKE ?
  `).bind(`%"user_id":${id}%`).run();

  // Send approval email
  if (user.email) {
    const subject = 'アカウントが承認されました - 地図アプリ';
    const htmlBody = `
      <h2>アカウント承認のお知らせ</h2>
      <p>${user.display_name || user.username} 様</p>
      <p>地図アプリへのアカウント申請が承認されました。</p>
      <p>ログインしてご利用ください。</p>
      <br>
      <p>地図アプリ</p>
    `;
    const textBody = `${user.display_name || user.username} 様\n\n地図アプリへのアカウント申請が承認されました。\nログインしてご利用ください。\n\n地図アプリ`;
    await sendEmail(env, user.email, subject, htmlBody, textBody);
  }

  return json({ ok: true, message: `${user.display_name}を承認しました` });
}

async function handleRejectUser(env, id) {
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
  if (!user) return json({ error: 'ユーザーが見つかりません' }, 404);
  if (user.status !== 'pending') return json({ error: 'このユーザーは既に処理済みです' }, 400);

  // Send rejection email first (before deleting user)
  let emailSent = false;
  if (user.email) {
    const subject = 'アカウント申請について - 地図アプリ';
    const htmlBody = `
      <h2>アカウント申請のお知らせ</h2>
      <p>${user.display_name || user.username} 様</p>
      <p>申し訳ございませんが、地図アプリへのアカウント申請は承認されませんでした。</p>
      <p>ご不明な点がございましたら、管理者までお問い合わせください。</p>
      <br>
      <p>地図アプリ</p>
    `;
    const textBody = `${user.display_name || user.username} 様\n\n申し訳ございませんが、地図アプリへのアカウント申請は承認されませんでした。\nご不明な点がございましたら、管理者までお問い合わせください。\n\n地図アプリ`;
    emailSent = await sendEmail(env, user.email, subject, htmlBody, textBody);
  }

  // Delete related notifications
  await env.DB.prepare(`
    DELETE FROM admin_notifications
    WHERE type = 'user_pending' AND data LIKE ?
  `).bind(`%"user_id":${id}%`).run();

  // Delete user from database
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id).run();

  const emailStatus = emailSent ? '（メール送信済み）' : '（メール送信失敗）';
  return json({ ok: true, message: `${user.display_name}を削除しました${emailStatus}` });
}

async function handleGetAdminNotifications(env) {
  const notifications = await env.DB.prepare(
    'SELECT * FROM admin_notifications WHERE is_read = 0 ORDER BY created_at DESC LIMIT 50'
  ).all();
  return json(notifications.results);
}

async function handleMarkNotificationRead(env, id) {
  await env.DB.prepare('UPDATE admin_notifications SET is_read = 1 WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function handleGetSecurityLogs(env, url) {
  const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
  const eventType = url.searchParams.get('type');

  let query = 'SELECT * FROM security_logs';
  const bindings = [];

  if (eventType) {
    query += ' WHERE event_type = ?';
    bindings.push(eventType);
  }

  query += ' ORDER BY created_at DESC LIMIT ?';
  bindings.push(limit);

  const logs = await env.DB.prepare(query).bind(...bindings).all();
  return json(logs.results);
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
  const { name, is_public, parent_id } = await request.json();
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ? AND user_id = ?')
      .bind(parent_id, user.id).first();
    if (!parent) return json({ error: '親フォルダが見つかりません' }, 404);
  }

  const publicFlag = user.is_admin && is_public ? 1 : 0;
  const result = await env.DB.prepare(
    'INSERT INTO kml_folders (name, user_id, is_public, parent_id) VALUES (?, ?, ?, ?)'
  ).bind(name, user.id, publicFlag, parent_id || null).run();

  return json({ id: result.meta.last_row_id, name, user_id: user.id, is_public: publicFlag, parent_id: parent_id || null });
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
  // Verify user has access to this folder (owner, public, or shared)
  const folder = await env.DB.prepare(`
    SELECT kf.* FROM kml_folders kf
    WHERE kf.id = ? AND (kf.user_id = ? OR kf.is_public = 1
      OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?))
  `).bind(id, user.id, user.id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

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

  // Get all folders at the same level owned by the user
  const parentCondition = folder.parent_id ? 'parent_id = ?' : 'parent_id IS NULL';
  const siblings = await env.DB.prepare(`
    SELECT id, sort_order FROM kml_folders
    WHERE user_id = ? AND ${parentCondition}
    ORDER BY sort_order, id
  `).bind(...(folder.parent_id ? [user.id, folder.parent_id] : [user.id])).all();

  const folderIds = siblings.results.map(f => f.id);
  const sourceIdx = folderIds.indexOf(parseInt(id));
  const targetIdx = folderIds.indexOf(parseInt(target_id));

  if (sourceIdx === -1 || targetIdx === -1) {
    return json({ error: 'フォルダが見つかりません' }, 404);
  }

  // Move source to target position
  folderIds.splice(sourceIdx, 1);
  folderIds.splice(targetIdx, 0, parseInt(id));

  // Update all sort_order values sequentially
  for (let i = 0; i < folderIds.length; i++) {
    await env.DB.prepare('UPDATE kml_folders SET sort_order = ? WHERE id = ?')
      .bind(i, folderIds[i]).run();
  }

  return json({ ok: true });
}

async function handleMoveKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { parent_id } = await request.json();

  // Cannot move folder to itself
  if (parent_id && parseInt(parent_id) === parseInt(id)) {
    return json({ error: '自分自身には移動できません' }, 400);
  }

  // Check if target parent exists and belongs to user
  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(parent_id).first();
    if (!parent) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (parent.user_id !== user.id && !user.is_admin) {
      return json({ error: '移動先フォルダの権限がありません' }, 403);
    }

    // Check for circular reference (cannot move to child folder)
    let current = parent;
    while (current && current.parent_id) {
      if (parseInt(current.parent_id) === parseInt(id)) {
        return json({ error: '子フォルダには移動できません' }, 400);
      }
      current = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(current.parent_id).first();
    }
  }

  await env.DB.prepare('UPDATE kml_folders SET parent_id = ? WHERE id = ?')
    .bind(parent_id || null, id).run();
  return json({ ok: true });
}

// ==================== KML Files Handlers ====================
async function handleGetKmlFiles(env, user, url) {
  const folderId = url.searchParams.get('folder_id');
  let query, bindings = [];

  if (user) {
    if (folderId) {
      // KML files in a specific folder - check folder access
      query = `SELECT kf.*, u.display_name as owner_name,
          COALESCE(f.is_public, 0) as is_public
        FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        LEFT JOIN kml_folders f ON kf.folder_id = f.id
        WHERE kf.folder_id = ? AND (kf.user_id = ? OR f.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?))
        ORDER BY kf.original_name`;
      bindings = [folderId, user.id, user.id];
    } else {
      // All KML files user can access (own files, public folder files, shared folder files)
      query = `SELECT kf.*, u.display_name as owner_name,
          COALESCE(f.is_public, 0) as is_public
        FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        LEFT JOIN kml_folders f ON kf.folder_id = f.id
        WHERE kf.user_id = ? OR f.is_public = 1 OR
          kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
        ORDER BY kf.original_name`;
      bindings = [user.id, user.id];
    }
  } else {
    // Non-logged in users see only KML files in public folders
    query = `SELECT kf.*, u.display_name as owner_name, 1 as is_public
      FROM kml_files kf
      LEFT JOIN users u ON kf.user_id = u.id
      INNER JOIN kml_folders f ON kf.folder_id = f.id AND f.is_public = 1
      ORDER BY kf.original_name`;
  }

  const stmt = env.DB.prepare(query);
  const files = bindings.length > 0 ? await stmt.bind(...bindings).all() : await stmt.all();
  return json(files.results);
}

async function handleUploadKmlFile(request, env, user) {
  const formData = await request.formData();
  const file = formData.get('kml');
  const folderId = formData.get('folder_id');

  if (!file) return json({ error: 'ファイルが選択されていません' }, 400);

  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'kml' && ext !== 'kmz') {
    return json({ error: 'KMLまたはKMZファイルのみアップロード可能です' }, 400);
  }

  if (file.size > MAX_KML_SIZE) {
    return json({ error: 'ファイルサイズが大きすぎます（最大50MB）' }, 400);
  }

  const r2Key = `kml/${crypto.randomUUID()}.${ext}`;
  let content = await file.text();
  if (ext === 'kml') {
    content = convertKmlPolygonToLine(content);
  }

  await env.R2.put(r2Key, content, {
    httpMetadata: { contentType: ext === 'kml' ? 'application/vnd.google-earth.kml+xml' : 'application/vnd.google-earth.kmz' }
  });

  // KML files no longer have individual public flag - visibility is controlled by folder
  const result = await env.DB.prepare(
    'INSERT INTO kml_files (folder_id, user_id, r2_key, original_name, is_public) VALUES (?, ?, ?, ?, 0)'
  ).bind(folderId || null, user.id, r2Key, file.name).run();

  return json({ id: result.meta.last_row_id, r2_key: r2Key, original_name: file.name, folder_id: folderId || null });
}

async function handleGetKmlFile(env, user, key) {
  const r2Key = `kml/${key}`;

  // Look up file and check access
  const file = await env.DB.prepare('SELECT * FROM kml_files WHERE r2_key = ?').bind(r2Key).first();
  if (!file) return json({ error: 'ファイルが見つかりません' }, 404);

  // Check access: public file, or user owns it, or user has folder access
  if (!file.is_public) {
    if (!user) return json({ error: '認証が必要です' }, 401);

    const hasAccess = file.user_id === user.id || user.is_admin ||
      (file.folder_id && await env.DB.prepare(`
        SELECT 1 FROM kml_folders kf
        WHERE kf.id = ? AND (kf.user_id = ? OR kf.is_public = 1
          OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?))
      `).bind(file.folder_id, user.id, user.id).first());

    if (!hasAccess) return json({ error: 'アクセス権限がありません' }, 403);
  }

  const obj = await env.R2.get(r2Key);
  if (!obj) return json({ error: 'ファイルが見つかりません' }, 404);

  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream',
      ...securityHeaders
    }
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

async function handleMoveKmlFile(request, env, user, id) {
  const file = await env.DB.prepare('SELECT * FROM kml_files WHERE id = ?').bind(id).first();
  if (!file) return json({ error: 'ファイルが見つかりません' }, 404);
  if (file.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { folder_id } = await request.json();

  // Check if target folder exists and user has access
  if (folder_id) {
    const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(folder_id).first();
    if (!folder) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (folder.user_id !== user.id && !user.is_admin) {
      return json({ error: '移動先フォルダの権限がありません' }, 403);
    }
  }

  await env.DB.prepare('UPDATE kml_files SET folder_id = ? WHERE id = ?')
    .bind(folder_id || null, id).run();
  return json({ ok: true });
}

// ==================== Pin Folders Handlers ====================
async function handleGetFolders(env, user) {
  if (!user) {
    // Non-logged in users can see public folders
    const folders = await env.DB.prepare(`
      SELECT f.*, u.display_name as owner_name, 0 as is_owner, 1 as is_visible
      FROM folders f
      LEFT JOIN users u ON f.user_id = u.id
      WHERE f.is_public = 1
      ORDER BY f.sort_order, f.name
    `).all();
    return json(folders.results);
  }

  const folders = await env.DB.prepare(`
    SELECT f.*, u.display_name as owner_name,
      CASE WHEN f.user_id = ? THEN 1 ELSE 0 END as is_owner,
      COALESCE(fv.is_visible, 1) as is_visible
    FROM folders f
    LEFT JOIN users u ON f.user_id = u.id
    LEFT JOIN folder_visibility fv ON f.id = fv.folder_id AND fv.user_id = ?
    WHERE f.user_id = ? OR f.is_public = 1 OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
    ORDER BY f.sort_order, f.name
  `).bind(user.id, user.id, user.id, user.id).all();

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

  // Get all folders at the same level owned by the user
  const parentCondition = folder.parent_id ? 'parent_id = ?' : 'parent_id IS NULL';
  const siblings = await env.DB.prepare(`
    SELECT id, sort_order FROM folders
    WHERE user_id = ? AND ${parentCondition}
    ORDER BY sort_order, id
  `).bind(...(folder.parent_id ? [user.id, folder.parent_id] : [user.id])).all();

  const folderIds = siblings.results.map(f => f.id);
  const sourceIdx = folderIds.indexOf(parseInt(id));
  const targetIdx = folderIds.indexOf(parseInt(target_id));

  if (sourceIdx === -1 || targetIdx === -1) {
    return json({ error: 'フォルダが見つかりません' }, 404);
  }

  // Move source to target position
  folderIds.splice(sourceIdx, 1);
  folderIds.splice(targetIdx, 0, parseInt(id));

  // Update all sort_order values sequentially
  for (let i = 0; i < folderIds.length; i++) {
    await env.DB.prepare('UPDATE folders SET sort_order = ? WHERE id = ?')
      .bind(i, folderIds[i]).run();
  }

  return json({ ok: true });
}

async function handleMoveFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { parent_id } = await request.json();

  // Cannot move folder to itself
  if (parent_id && parseInt(parent_id) === parseInt(id)) {
    return json({ error: '自分自身には移動できません' }, 400);
  }

  // Check if target parent exists and belongs to user
  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(parent_id).first();
    if (!parent) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (parent.user_id !== user.id && !user.is_admin) {
      return json({ error: '移動先フォルダの権限がありません' }, 403);
    }

    // Check for circular reference (cannot move to child folder)
    let current = parent;
    while (current && current.parent_id) {
      if (parseInt(current.parent_id) === parseInt(id)) {
        return json({ error: '子フォルダには移動できません' }, 400);
      }
      current = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(current.parent_id).first();
    }
  }

  await env.DB.prepare('UPDATE folders SET parent_id = ? WHERE id = ?')
    .bind(parent_id || null, id).run();
  return json({ ok: true });
}

async function handleFolderVisibility(request, env, user, id) {
  // Verify user has access to this folder (owner, public, or shared)
  const folder = await env.DB.prepare(`
    SELECT f.* FROM folders f
    WHERE f.id = ? AND (f.user_id = ? OR f.is_public = 1
      OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?))
  `).bind(id, user.id, user.id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  const { is_visible } = await request.json();
  await env.DB.prepare(`
    INSERT INTO folder_visibility (folder_id, user_id, is_visible) VALUES (?, ?, ?)
    ON CONFLICT(folder_id, user_id) DO UPDATE SET is_visible = excluded.is_visible
  `).bind(id, user.id, is_visible ? 1 : 0).run();
  return json({ ok: true });
}

// ==================== Pins Handlers ====================
async function handleGetPins(env, user) {
  let pins;
  if (user && user.is_admin) {
    // Admin sees all pins
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        CASE WHEN f.is_public = 1 THEN 1 ELSE 0 END as is_public
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      ORDER BY p.created_at DESC
    `).all();
  } else if (user) {
    // User sees: own pins, pins in public folders, pins in shared folders
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        CASE WHEN f.is_public = 1 THEN 1 ELSE 0 END as is_public
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      WHERE p.user_id = ?
        OR f.is_public = 1
        OR p.folder_id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      ORDER BY p.created_at DESC
    `).bind(user.id, user.id).all();
  } else {
    // Non-logged in users see only pins in public folders
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author, 1 as is_public
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      WHERE f.is_public = 1
      ORDER BY p.created_at DESC
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
  let title, description, lat, lng, folder_id, imageFiles = [];

  if (contentType.includes('multipart/form-data')) {
    const formData = await request.formData();
    title = formData.get('title');
    description = formData.get('description') || '';
    lat = parseFloat(formData.get('lat'));
    lng = parseFloat(formData.get('lng'));
    folder_id = formData.get('folder_id') || null;
    imageFiles = formData.getAll('images');
  } else {
    const body = await request.json();
    title = body.title;
    description = body.description || '';
    lat = body.lat;
    lng = body.lng;
    folder_id = body.folder_id || null;
  }

  if (!title || lat == null || lng == null) {
    return json({ error: 'タイトルと座標は必須です' }, 400);
  }

  // Verify folder access if folder_id is specified
  if (folder_id) {
    const folder = await env.DB.prepare(`
      SELECT f.* FROM folders f
      WHERE f.id = ? AND (
        f.user_id = ? OR
        f.is_public = 1 OR
        f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      )
    `).bind(folder_id, user.id, user.id).first();
    if (!folder) {
      return json({ error: 'このフォルダへのアクセス権限がありません' }, 403);
    }
  }

  // Pins no longer have individual public flag - visibility is controlled by folder
  const result = await env.DB.prepare(
    'INSERT INTO pins (title, description, lat, lng, folder_id, user_id, is_public) VALUES (?, ?, ?, ?, ?, ?, 0)'
  ).bind(title, description, lat, lng, folder_id, user.id).run();

  const pinId = result.meta.last_row_id;
  const images = [];

  for (const file of imageFiles) {
    if (!file || !file.name) continue;
    const validation = validateImageFile(file);
    if (!validation.valid) {
      return json({ error: validation.error }, 400);
    }
    // Sanitize filename
    const safeFilename = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const r2Key = `images/${crypto.randomUUID()}-${safeFilename}`;
    await env.R2.put(r2Key, await file.arrayBuffer(), {
      httpMetadata: { contentType: file.type }
    });
    const imgResult = await env.DB.prepare(
      'INSERT INTO pin_images (pin_id, r2_key, original_name) VALUES (?, ?, ?)'
    ).bind(pinId, r2Key, file.name).run();
    images.push({ id: imgResult.meta.last_row_id, r2_key: r2Key, original_name: file.name });
  }

  return json({ id: pinId, title, description, lat, lng, folder_id, user_id: user.id, images });
}

async function handleUpdatePin(request, env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { title, description, folder_id } = await request.json();

  await env.DB.prepare(`
    UPDATE pins SET title = COALESCE(?, title), description = COALESCE(?, description),
    folder_id = ? WHERE id = ?
  `).bind(title || pin.title, description !== undefined ? description : pin.description,
    folder_id !== undefined ? folder_id : pin.folder_id, id).run();

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
    const validation = validateImageFile(file);
    if (!validation.valid) {
      return json({ error: validation.error }, 400);
    }
    // Sanitize filename
    const safeFilename = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
    const r2Key = `images/${crypto.randomUUID()}-${safeFilename}`;
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

async function handleMovePin(request, env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (pin.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { folder_id } = await request.json();

  // Check if target folder exists and user has access
  if (folder_id) {
    const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(folder_id).first();
    if (!folder) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (folder.user_id !== user.id && !user.is_admin) {
      return json({ error: '移動先フォルダの権限がありません' }, 403);
    }
  }

  await env.DB.prepare('UPDATE pins SET folder_id = ? WHERE id = ?')
    .bind(folder_id || null, id).run();
  return json({ ok: true });
}

async function handleGetImage(env, user, key) {
  const r2Key = `images/${key}`;

  // Look up image and check access via pin
  const image = await env.DB.prepare('SELECT pi.*, p.user_id as pin_user_id, p.is_public as pin_is_public, p.folder_id as pin_folder_id FROM pin_images pi JOIN pins p ON pi.pin_id = p.id WHERE pi.r2_key = ?').bind(r2Key).first();
  if (!image) return json({ error: '画像が見つかりません' }, 404);

  // Check access: public pin, or user owns it, or user has folder access
  if (!image.pin_is_public) {
    if (!user) return json({ error: '認証が必要です' }, 401);

    const hasAccess = image.pin_user_id === user.id || user.is_admin ||
      (image.pin_folder_id && await env.DB.prepare(`
        SELECT 1 FROM folders f
        WHERE f.id = ? AND (f.user_id = ? OR f.is_public = 1
          OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?))
      `).bind(image.pin_folder_id, user.id, user.id).first());

    if (!hasAccess) return json({ error: 'アクセス権限がありません' }, 403);
  }

  const obj = await env.R2.get(r2Key);
  if (!obj) return json({ error: '画像が見つかりません' }, 404);

  return new Response(obj.body, {
    headers: {
      'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
      'Cache-Control': image.pin_is_public ? 'public, max-age=31536000' : 'private, max-age=3600',
      ...securityHeaders
    }
  });
}
