// Cloudflare Pages Functions - Modular architecture via lib/ imports

import {
  // utils
  base64urlEncode, base64urlDecode, base64urlDecodeToString,
  getCookie, setCookieHeader, securityHeaders, json, getClientIP,
  isValidEmail, sanitizeValue, sanitizeObject, getRequestBody, hashIP,
  // crypto
  hashPassword, verifyPassword, createToken, verifyToken,
  // sessions
  generateSessionToken, hashSessionToken, parseDeviceName,
  createSession, validateSession, revokeSession, revokeSessionById,
  revokeAllUserSessions, getUserSessions, cleanupExpiredSessions,
  // security
  RATE_LIMITS, FREE_TIER_LIMITS, checkRateLimit,
  isUserFreeTier, getUserKmlFolderCount, getUserPinFolderCount,
  getUserKmlFileCount, getUserPinCount, getUserShareCount,
  checkFreeTierLimit, logSecurityEvent,
  ALLOWED_IMAGE_TYPES, MAX_IMAGE_SIZE, MAX_KML_SIZE,
  validateImageFile, convertKmlPolygonToLine, validateCSRF,
  // organization permissions
  getUserOrgIds, isOrgAdmin, isOrgMember,
  canEditFolder, canEditPin, canEditKmlFile,
  // webauthn
  generateWebAuthnChallenge, decodeCBOR, parseAttestationObject,
  parseAuthenticatorData, coseKeyToCryptoKey, verifyWebAuthnSignature,
  derToRaw, getRelyingPartyId,
  // email
  sendEmail, sendExternalWelcomeEmail, sendOrgInvitationEmail
} from './lib/index.js';

// Content Security Policy for HTML responses
const cspHeader = "default-src 'self'; script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; img-src 'self' https://cyberjapandata.gsi.go.jp data: blob:; connect-src 'self' https://cyberjapandata.gsi.go.jp; font-src 'self' https://cdnjs.cloudflare.com;";

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
        password_hash TEXT NOT NULL,
        password_salt TEXT,
        email TEXT,
        display_name TEXT,
        is_admin INTEGER DEFAULT 0,
        status TEXT DEFAULT 'pending',
        plan TEXT DEFAULT 'free',
        member_source TEXT,
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        subscription_ends_at TEXT,
        external_id TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`),
      // Admin notifications
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        data TEXT,
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
        r2_key TEXT NOT NULL,
        original_name TEXT NOT NULL,
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
      )`),
      // Pin comments
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS pin_comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pin_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (pin_id) REFERENCES pins(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`),
      // Comment read status - tracks when user last checked notifications
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS comment_read_status (
        user_id INTEGER PRIMARY KEY,
        last_read_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`),
      // Push notification subscriptions
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        endpoint TEXT NOT NULL UNIQUE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`),
      // KML folder shares
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS kml_folder_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kml_folder_id INTEGER NOT NULL,
        shared_with_user_id INTEGER NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (kml_folder_id) REFERENCES kml_folders(id) ON DELETE CASCADE,
        FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(kml_folder_id, shared_with_user_id)
      )`),
      // KML folder visibility (per-user visibility settings)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS kml_folder_visibility (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        kml_folder_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        is_visible INTEGER DEFAULT 1,
        FOREIGN KEY (kml_folder_id) REFERENCES kml_folders(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(kml_folder_id, user_id)
      )`),
      // Folder visibility (per-user visibility settings for pin folders)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS folder_visibility (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        folder_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        is_visible INTEGER DEFAULT 1,
        FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(folder_id, user_id)
      )`),
      // Passkeys (WebAuthn credentials)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS passkeys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL,
        counter INTEGER DEFAULT 0,
        device_name TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`),
      // Passkey challenges (temporary storage for WebAuthn ceremonies)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS passkey_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        challenge TEXT NOT NULL,
        user_id INTEGER,
        type TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL
      )`),
      // Sessions (for token invalidation and session management)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        device_name TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        last_active_at TEXT DEFAULT (datetime('now')),
        expires_at TEXT NOT NULL,
        is_revoked INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`),
      // Verification codes (email-based short code authentication)
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code TEXT NOT NULL,
        purpose TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`)
    ]);

    // Add email column to existing users table if it doesn't exist
    try {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN email TEXT').run();
    } catch (e) {
      // Column might already exist, ignore error
    }

    // Add password_salt column to existing users table if it doesn't exist
    try {
      await env.DB.prepare('ALTER TABLE users ADD COLUMN password_salt TEXT').run();
    } catch (e) {
      // Column might already exist, ignore error
    }

    // Organization tables
    await env.DB.batch([
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        created_by INTEGER NOT NULL,
        stripe_subscription_id TEXT,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (created_by) REFERENCES users(id)
      )`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS organization_members (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(organization_id, user_id)
      )`),
      env.DB.prepare(`CREATE TABLE IF NOT EXISTS organization_invitations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        invited_by INTEGER NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
        FOREIGN KEY (invited_by) REFERENCES users(id)
      )`)
    ]);

    // Add organization_id to folders and kml_folders
    try {
      await env.DB.prepare('ALTER TABLE folders ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL').run();
    } catch (e) { /* Column might already exist */ }
    try {
      await env.DB.prepare('ALTER TABLE kml_folders ADD COLUMN organization_id INTEGER REFERENCES organizations(id) ON DELETE SET NULL').run();
    } catch (e) { /* Column might already exist */ }
    try {
      await env.DB.prepare('ALTER TABLE organizations ADD COLUMN stripe_subscription_id TEXT').run();
    } catch (e) { /* Column might already exist */ }

    tablesInitialized = true;
  } catch (err) {
    console.error('Table initialization error:', err);
    // Continue anyway - tables might already exist with different schema
    tablesInitialized = true;
  }
}

// ==================== Sentry Error Reporting ====================
// Lightweight Sentry client for Cloudflare Workers
// 環境変数 SENTRY_DSN を設定すると有効化されます
function parseSentryDsn(dsn) {
  if (!dsn) return null;
  try {
    const url = new URL(dsn);
    const projectId = url.pathname.replace('/', '');
    return {
      publicKey: url.username,
      host: url.hostname,
      projectId: projectId,
      endpoint: `https://${url.hostname}/api/${projectId}/envelope/`
    };
  } catch {
    return null;
  }
}

async function reportErrorToSentry(env, error, request, extra) {
  const config = parseSentryDsn(env.SENTRY_DSN);
  if (!config) return;

  const eventId = crypto.randomUUID().replace(/-/g, '');
  const timestamp = new Date().toISOString();

  const event = {
    event_id: eventId,
    timestamp: timestamp,
    platform: 'javascript',
    server_name: 'cloudflare-worker',
    release: '2.0.0',
    environment: env.ENVIRONMENT || 'production',
    exception: {
      values: [{
        type: error.name || 'Error',
        value: error.message || String(error),
        stacktrace: error.stack ? {
          frames: error.stack.split('\n').slice(1, 10).map(line => ({
            filename: line.trim(),
            function: line.trim()
          }))
        } : undefined
      }]
    },
    request: request ? {
      url: request.url,
      method: request.method,
      headers: {
        'user-agent': request.headers.get('user-agent') || ''
      }
    } : undefined,
    extra: extra || {}
  };

  const envelope = [
    JSON.stringify({ event_id: eventId, dsn: env.SENTRY_DSN, sent_at: timestamp }),
    JSON.stringify({ type: 'event', content_type: 'application/json' }),
    JSON.stringify(event)
  ].join('\n');

  try {
    await fetch(config.endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-sentry-envelope',
        'X-Sentry-Auth': `Sentry sentry_version=7, sentry_client=fieldnota-worker/1.0, sentry_key=${config.publicKey}`
      },
      body: envelope
    });
  } catch {
    // Sentry送信失敗は無視（本体の処理を妨げない）
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

  // Validate JWT_SECRET is properly configured
  if (!env.JWT_SECRET) {
    console.error('FATAL: JWT_SECRET environment variable is not set');
    return json({ error: 'Server configuration error' }, 500);
  }
  if (env.JWT_SECRET.length < 32) {
    console.error('FATAL: JWT_SECRET must be at least 32 characters long');
    return json({ error: 'Server configuration error' }, 500);
  }

  // CORS headers - strict origin allowlist
  const origin = request.headers.get('Origin');
  const PRODUCTION_ORIGIN = 'https://fieldnota-commons.com';

  // Build allowed origins list (no wildcards, explicit list only)
  const allowedOrigins = new Set([
    url.origin,
    PRODUCTION_ORIGIN
  ]);
  // Add custom allowed origin from environment if configured
  if (env.ALLOWED_ORIGIN) {
    allowedOrigins.add(env.ALLOWED_ORIGIN);
  }

  // Strict origin validation - only allow explicitly listed origins
  const isAllowedOrigin = origin && allowedOrigins.has(origin);

  // For cross-origin requests with credentials, reject unknown origins
  if (origin && !isAllowedOrigin) {
    // Return response without CORS headers - browser will block the request
    // For preflight, return 403 to explicitly deny
    if (method === 'OPTIONS') {
      return new Response('CORS origin not allowed', {
        status: 403,
        headers: securityHeaders
      });
    }
  }

  const corsHeaders = {
    // Only set Allow-Origin for validated origins (never use wildcard with credentials)
    'Access-Control-Allow-Origin': isAllowedOrigin ? origin : url.origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    // Cache preflight requests for 1 hour to reduce OPTIONS requests
    'Access-Control-Max-Age': '3600',
    ...securityHeaders
  };

  if (method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  // CSRF protection for state-changing requests
  // Exclude webhook endpoints that receive external requests
  const csrfExemptPaths = [
    '/stripe/webhook',           // Stripe webhook (external)
    '/external/member-sync'      // Server-to-server sync
  ];
  const isCSRFExempt = csrfExemptPaths.some(p => path.startsWith(p));

  if (!isCSRFExempt) {
    const csrfCheck = validateCSRF(request, url);
    if (!csrfCheck.valid) {
      await logSecurityEvent(env, 'csrf_validation_failed', null, request, { error: csrfCheck.error, path });
      return json({ error: 'CSRF検証に失敗しました' }, 403);
    }
  }

  // Get current user from cookie and validate session
  let user = null;
  const token = getCookie(request, 'auth');
  if (token) {
    const tokenPayload = await verifyToken(token, env.JWT_SECRET);
    if (tokenPayload) {
      // Validate session - session token (sid) is required
      if (tokenPayload.sid) {
        const session = await validateSession(env, tokenPayload.sid);
        if (session) {
          user = tokenPayload;  // Session is valid
        }
        // If session is invalid/revoked, user remains null (forces re-login)
      }
      // Tokens without sid are rejected (legacy support removed)
    }
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
      return await handleTokenRefresh(env, user, request);
    }
    if (path === '/auth/logout' && method === 'POST') {
      return await handleLogout(env, user, request);
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'passwordChange');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', user.id, request, { endpoint: 'passwordChange' });
        return json({ error: 'パスワード変更の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handleChangePassword(request, env, user);
    }
    if (path === '/auth/delete-account' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleDeleteAccount(request, env, user);
    }

    // Session management routes
    if (path === '/auth/sessions' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetSessions(env, user);
    }
    if (path === '/auth/sessions' && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleRevokeAllSessions(env, user);
    }
    if (path.startsWith('/auth/sessions/') && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const sessionId = parseInt(path.split('/')[3]);
      if (isNaN(sessionId)) {
        return json({ error: '無効なセッションIDです' }, 400);
      }
      return await handleRevokeSession(env, user, sessionId);
    }

    // Passkeys (WebAuthn) routes - with rate limiting
    if (path === '/auth/passkey/register/options' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'passkey');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', user.id, request, { endpoint: 'passkey_register' });
        return json({ error: 'パスキー登録の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handlePasskeyRegisterOptions(request, env, user);
    }
    if (path === '/auth/passkey/register/verify' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handlePasskeyRegisterVerify(request, env, user);
    }
    if (path === '/auth/passkey/login/options' && method === 'POST') {
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'passkey');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', null, request, { endpoint: 'passkey_login' });
        return json({ error: 'パスキーログインの試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handlePasskeyLoginOptions(request, env);
    }
    if (path === '/auth/passkey/login/verify' && method === 'POST') {
      return await handlePasskeyLoginVerify(request, env);
    }
    if (path === '/auth/passkeys' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetPasskeys(env, user);
    }
    if (path.startsWith('/auth/passkey/') && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const passkeyId = parseInt(path.split('/')[3]);
      return await handleDeletePasskey(env, user, passkeyId);
    }

    // Users
    if (path === '/users' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetUsers(env, user);
    }

    // Admin routes - with rate limiting for sensitive operations
    if (path === '/admin/pending-users' && method === 'GET') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      return await handleGetPendingUsers(env);
    }
    if (path.match(/^\/admin\/users\/(\d+)\/approve$/) && method === 'POST') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'admin');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', user.id, request, { endpoint: 'admin_approve' });
        return json({ error: '管理者操作が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      const id = path.match(/^\/admin\/users\/(\d+)\/approve$/)[1];
      return await handleApproveUser(env, id);
    }
    if (path.match(/^\/admin\/users\/(\d+)\/reject$/) && method === 'POST') {
      if (!user || !user.is_admin) return json({ error: '管理者権限が必要です' }, 403);
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'admin');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', user.id, request, { endpoint: 'admin_reject' });
        return json({ error: '管理者操作が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'folderCreate');
      if (!rateCheck.allowed) {
        return json({ error: 'フォルダ作成の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
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
    if (path.match(/^\/kml-folders\/(\d+)\/shares$/) && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/kml-folders\/(\d+)\/shares$/)[1];
      return await handleGetKmlFolderShares(env, user, id);
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'kmlUpload');
      if (!rateCheck.allowed) {
        return json({ error: 'ファイルアップロードの試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'folderCreate');
      if (!rateCheck.allowed) {
        return json({ error: 'フォルダ作成の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
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
    if (path.match(/^\/folders\/(\d+)\/shares$/) && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/folders\/(\d+)\/shares$/)[1];
      return await handleGetFolderShares(env, user, id);
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'pinCreate');
      if (!rateCheck.allowed) {
        return json({ error: 'ピン作成の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
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
    // Pin comments
    if (path.match(/^\/pins\/(\d+)\/comments$/) && method === 'GET') {
      const id = path.match(/^\/pins\/(\d+)\/comments$/)[1];
      return await handleGetPinComments(env, user, id);
    }
    if (path.match(/^\/pins\/(\d+)\/comments$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'commentCreate');
      if (!rateCheck.allowed) {
        return json({ error: 'コメント投稿の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      const id = path.match(/^\/pins\/(\d+)\/comments$/)[1];
      return await handleCreatePinComment(request, env, user, id);
    }
    if (path.match(/^\/pins\/(\d+)\/comments\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const match = path.match(/^\/pins\/(\d+)\/comments\/(\d+)$/);
      return await handleDeletePinComment(env, user, match[1], match[2]);
    }
    // Comment notifications
    if (path === '/comments/unread' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetUnreadComments(env, user);
    }
    if (path === '/comments/mark-read' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleMarkCommentsRead(env, user);
    }

    // Push notifications
    if (path === '/push/vapid-key' && method === 'GET') {
      return handleGetVapidKey(env);
    }
    if (path === '/push/subscribe' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handlePushSubscribe(request, env, user);
    }
    if (path === '/push/unsubscribe' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handlePushUnsubscribe(request, env, user);
    }
    if (path === '/push/test' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handlePushTest(request, env, user);
    }

    // Images
    if (path.match(/^\/images\/(.+)$/) && method === 'GET') {
      const key = path.match(/^\/images\/(.+)$/)[1];
      return await handleGetImage(env, user, key);
    }

    // Organizations
    if (path === '/organizations' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetOrganizations(env, user);
    }
    if (path === '/organizations' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      if (!user.is_admin) return json({ error: '団体の作成はランディングページからお支払いが必要です' }, 403);
      return await handleCreateOrganization(request, env, user);
    }
    if (path.match(/^\/organizations\/(\d+)$/) && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)$/)[1];
      return await handleUpdateOrganization(request, env, user, id);
    }
    if (path.match(/^\/organizations\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)$/)[1];
      return await handleDeleteOrganization(env, user, id);
    }
    // Organization members
    if (path.match(/^\/organizations\/(\d+)\/members$/) && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)\/members$/)[1];
      return await handleGetOrgMembers(env, user, id);
    }
    if (path.match(/^\/organizations\/(\d+)\/members\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const match = path.match(/^\/organizations\/(\d+)\/members\/(\d+)$/);
      return await handleRemoveOrgMember(env, user, match[1], match[2]);
    }
    if (path.match(/^\/organizations\/(\d+)\/members\/(\d+)\/role$/) && method === 'PUT') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const match = path.match(/^\/organizations\/(\d+)\/members\/(\d+)\/role$/);
      return await handleChangeOrgMemberRole(request, env, user, match[1], match[2]);
    }
    // Organization invitations
    if (path.match(/^\/organizations\/(\d+)\/invitations$/) && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)\/invitations$/)[1];
      return await handleGetOrgInvitations(env, user, id);
    }
    if (path.match(/^\/organizations\/(\d+)\/invite$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)\/invite$/)[1];
      return await handleInviteToOrg(request, env, user, id);
    }
    if (path.match(/^\/organizations\/invitations\/(\d+)$/) && method === 'DELETE') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/invitations\/(\d+)$/)[1];
      return await handleCancelOrgInvitation(env, user, id);
    }
    if (path === '/organizations/accept-invite' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleAcceptOrgInvitation(request, env, user);
    }
    // Organization folders
    if (path.match(/^\/organizations\/(\d+)\/folders$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)\/folders$/)[1];
      return await handleCreateOrgFolder(request, env, user, id);
    }
    if (path.match(/^\/organizations\/(\d+)\/kml-folders$/) && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      const id = path.match(/^\/organizations\/(\d+)\/kml-folders$/)[1];
      return await handleCreateOrgKmlFolder(request, env, user, id);
    }

    // External Member Sync API (for WordPress/Stripe integration)
    if (path === '/external/member-sync' && method === 'POST') {
      return await handleExternalMemberSync(request, env);
    }
    if (path === '/auth/setup-password' && method === 'POST') {
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'passwordSetup');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', null, request, { endpoint: 'passwordSetup' });
        return json({ error: 'パスワード設定の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handleSetupPassword(request, env);
    }

    // Subscription Management API
    if (path === '/subscription' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetSubscription(env, user);
    }

    // Stripe Direct Payment API
    if (path === '/stripe/create-checkout-session' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreateCheckoutSession(request, env, user);
    }
    if (path === '/stripe/create-org-checkout-session' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreateOrgCheckoutSession(request, env, user);
    }
    if (path === '/stripe/webhook' && method === 'POST') {
      return await handleStripeWebhook(request, env);
    }
    if (path === '/stripe/create-portal-session' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCreatePortalSession(request, env, user);
    }
    if (path === '/subscription/cancel' && method === 'POST') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleCancelSubscription(env, user);
    }
    if (path === '/usage' && method === 'GET') {
      if (!user) return json({ error: 'ログインが必要です' }, 401);
      return await handleGetUsage(env, user);
    }

    return json({ error: 'Not found' }, 404);
  } catch (err) {
    console.error(`API Error [${method} ${path}]:`, err.message || err);
    // Sentryにエラーを報告（非同期、レスポンスをブロックしない）
    context.waitUntil(
      reportErrorToSentry(env, err, request, { route: `${method} ${path}` })
    );
    return json({ error: 'Server error' }, 500);
  }
}

// ==================== Auth Handlers ====================
async function handleTokenRefresh(env, user, request) {
  // Get fresh user data from DB
  const dbUser = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!dbUser || dbUser.status !== 'approved') {
    return json({ error: 'ユーザーが見つかりません' }, 404);
  }

  // Keep the existing session token if present, otherwise create a new session
  let sessionToken = user.sid;
  if (!sessionToken) {
    sessionToken = await createSession(env, user.id, request);
  }

  const token = await createToken({
    id: dbUser.id,
    username: dbUser.username,
    display_name: dbUser.display_name || dbUser.username,
    is_admin: !!dbUser.is_admin,
    sid: sessionToken
  }, env.JWT_SECRET);

  return json(
    { ok: true },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleRegister(request, env) {
  const { username, password, email, display_name } = await getRequestBody(request);
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }
  if (!email) {
    return json({ error: 'メールアドレスを入力してください' }, 400);
  }
  // Validate email format
  if (!isValidEmail(email)) {
    return json({ error: '有効なメールアドレスを入力してください' }, 400);
  }
  if (username.length < 3) {
    return json({ error: 'ユーザー名は3文字以上にしてください' }, 400);
  }
  // Validate username is full name in Roman letters (e.g., "Taro Yamada")
  const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
  if (!fullNamePattern.test(username)) {
    return json({ error: 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）' }, 400);
  }
  if (password.length < 12) {
    return json({ error: 'パスワードは12文字以上にしてください' }, 400);
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if (existing) {
    await logSecurityEvent(env, 'register_duplicate_username', null, request, {});
    return json({ error: 'そのユーザー名は既に使われています' }, 400);
  }

  // Check if email is already used
  const existingEmail = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existingEmail) {
    return json({ error: 'このメールアドレスは既に登録されています' }, 400);
  }

  // Check if display name is already used
  const actualDisplayName = display_name || username;
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ?').bind(actualDisplayName).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  const { hash, salt } = await hashPassword(password);
  // New users start with 'pending' status - must be approved by admin
  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, email, display_name, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(username, hash, salt, email, actualDisplayName, 'pending').run();

  const userId = result.meta.last_row_id;

  // Create admin notification for pending approval
  await env.DB.prepare(
    'INSERT INTO admin_notifications (type, message, data) VALUES (?, ?, ?)'
  ).bind('user_pending', `新規ユーザー「${actualDisplayName}」が承認待ちです`, JSON.stringify({ user_id: userId, display_name: actualDisplayName })).run();

  // Don't return token - user must wait for admin approval
  return json({
    pending: true,
    message: 'アカウント申請を受け付けました。管理者の承認をお待ちください。'
  });
}

async function handleLogin(request, env) {
  const { username, password } = await getRequestBody(request);
  if (!username || !password) {
    return json({ error: 'ユーザー名とパスワードを入力してください' }, 400);
  }

  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) {
    await logSecurityEvent(env, 'login_failed', null, request, { reason: 'invalid_credentials' });
    return json({ error: 'ユーザー名またはパスワードが正しくありません' }, 401);
  }

  // Auto-migrate legacy SHA-256 passwords to PBKDF2
  if (!user.password_salt) {
    const { hash, salt } = await hashPassword(password);
    await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
      .bind(hash, salt, user.id).run();
    await logSecurityEvent(env, 'password_migrated', user.id, request, { from: 'sha256', to: 'pbkdf2' });
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
  if (user.status === 'needs_password') {
    // External member who needs to set up password - this shouldn't happen as password won't match
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'needs_password_setup' });
    return json({ error: 'パスワードを設定してください。登録時に送信されたメールをご確認ください。', needs_password: true }, 403);
  }

  // Create session for token invalidation support
  const sessionToken = await createSession(env, user.id, request);

  await logSecurityEvent(env, 'login_success', user.id, request, {});

  const token = await createToken({
    id: user.id, username: user.username,
    display_name: user.display_name || user.username,
    is_admin: !!user.is_admin,
    sid: sessionToken  // Session token for server-side invalidation
  }, env.JWT_SECRET);

  return json(
    { id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleLogout(env, user, request) {
  // Revoke the current session if user is authenticated
  if (user && user.sid) {
    await revokeSession(env, user.sid);
    await logSecurityEvent(env, 'logout', user.id, request, {});
  }
  return json({ ok: true }, 200, { 'Set-Cookie': setCookieHeader('auth', '', { maxAge: 0 }) });
}

// External Member Sync API Handler (for WordPress/Stripe integration)
async function handleExternalMemberSync(request, env) {
  try {
    // Verify IP whitelist if configured (EXTERNAL_SYNC_ALLOWED_IPS: comma-separated IPs)
    if (env.EXTERNAL_SYNC_ALLOWED_IPS) {
      const clientIP = getClientIP(request);
      const allowedIPs = env.EXTERNAL_SYNC_ALLOWED_IPS.split(',').map(ip => ip.trim());
      if (!allowedIPs.includes(clientIP)) {
        console.log(`External sync rejected: IP ${clientIP} not in whitelist`);
        return json({ error: 'Forbidden' }, 403);
      }
    }

    const { action, email, display_name, plan, external_id, secret, stripe_customer_id, user_id } = await getRequestBody(request);

    // Verify shared secret
    // TODO: Remove debug response after fixing auth issue
    if (!env.EXTERNAL_SYNC_SECRET || secret !== env.EXTERNAL_SYNC_SECRET) {
      return json({
        error: 'Unauthorized',
        debug: {
          hasEnvSecret: !!env.EXTERNAL_SYNC_SECRET,
          envSecretLength: env.EXTERNAL_SYNC_SECRET ? env.EXTERNAL_SYNC_SECRET.length : 0,
          receivedSecretLength: secret ? secret.length : 0,
          match: env.EXTERNAL_SYNC_SECRET === secret,
        }
      }, 401);
    }

    if (action === 'create') {
      // Try to find existing user by multiple identifiers (priority order):
      // 1. stripe_customer_id - most reliable for Stripe-originated requests
      // 2. user_id - if provided from metadata
      // 3. email - fallback, but may be wrong if Link/ApplePay used different email
      let existing = null;

      if (stripe_customer_id) {
        existing = await env.DB.prepare(
          'SELECT id, email, member_source FROM users WHERE stripe_customer_id = ?'
        ).bind(stripe_customer_id).first();
      }

      if (!existing && user_id) {
        existing = await env.DB.prepare(
          'SELECT id, email, member_source FROM users WHERE id = ?'
        ).bind(user_id).first();
      }

      if (!existing && email && isValidEmail(email)) {
        existing = await env.DB.prepare(
          'SELECT id, email, member_source FROM users WHERE email = ?'
        ).bind(email).first();
      }

      if (existing) {
        // Update existing user's plan
        if (existing.member_source === 'wordpress') {
          await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan || 'premium', existing.id).run();
          return json({ success: true, action: 'updated', user_id: existing.id });
        } else {
          // User registered normally or via Stripe, update their plan
          // Don't change member_source if it's already 'stripe' - that takes precedence
          if (existing.member_source !== 'stripe') {
            await env.DB.prepare('UPDATE users SET plan = ?, member_source = ? WHERE id = ?')
              .bind(plan || 'premium', 'wordpress', existing.id).run();
          } else {
            await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?')
              .bind(plan || 'premium', existing.id).run();
          }
          return json({ success: true, action: 'upgraded', user_id: existing.id });
        }
      }

      // No existing user found - only create new if we have valid email
      if (!email) {
        return json({ error: 'Email is required for new user creation' }, 400);
      }

      if (!isValidEmail(email)) {
        return json({ error: 'Invalid email format' }, 400);
      }

      // Create new external member
      // Use email as username for external members
      const username = email;
      const actualDisplayName = display_name || email.split('@')[0];

      // Generate random temporary password hash (user must set password on first login)
      const tempPassword = crypto.randomUUID();
      const { hash, salt } = await hashPassword(tempPassword);

      const result = await env.DB.prepare(
        `INSERT INTO users (username, password_hash, password_salt, email, display_name, status, member_source, plan, external_id)
         VALUES (?, ?, ?, ?, ?, 'needs_password', 'wordpress', ?, ?)`
      ).bind(username, hash, salt, email, actualDisplayName, plan || 'premium', external_id || null).run();

      const userId = result.meta.last_row_id;

      // Send welcome email with password setup link
      await sendExternalWelcomeEmail(env, email, actualDisplayName);

      return json({ success: true, action: 'created', user_id: userId });

    } else if (action === 'delete') {
      // Find user by multiple identifiers
      let user = null;

      if (stripe_customer_id) {
        user = await env.DB.prepare('SELECT id FROM users WHERE stripe_customer_id = ?').bind(stripe_customer_id).first();
      }

      if (!user && user_id) {
        user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(user_id).first();
      }

      if (!user && email) {
        user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      }

      if (!user) {
        return json({ success: true, action: 'not_found' });
      }

      // Delete user and all related data (cascades via foreign keys)
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();

      return json({ success: true, action: 'deleted', user_id: user.id });

    } else {
      return json({ error: 'Invalid action. Use "create" or "delete"' }, 400);
    }
  } catch (err) {
    console.error('External member sync error:', err);
    return json({ error: 'Server error' }, 500);
  }
}


// Handle account setup for external members (username + password)
async function handleSetupPassword(request, env) {
  try {
    const { email, username, display_name, password } = await getRequestBody(request);

    if (!email || !username || !password) {
      return json({ error: 'すべての必須項目を入力してください' }, 400);
    }

    // Validate username format (full name in Roman letters)
    const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
    if (!fullNamePattern.test(username)) {
      return json({ error: 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）' }, 400);
    }

    if (password.length < 12) {
      return json({ error: 'パスワードは12文字以上にしてください' }, 400);
    }

    // Find user by email
    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

    if (!user) {
      return json({ error: 'ユーザーが見つかりません' }, 404);
    }

    if (user.status !== 'needs_password') {
      return json({ error: 'このアカウントは既にパスワードが設定されています。ログインしてください。' }, 400);
    }

    // Check if username is already taken (by another user)
    const existingUsername = await env.DB.prepare('SELECT id FROM users WHERE username = ? AND id != ?')
      .bind(username, user.id).first();
    if (existingUsername) {
      return json({ error: 'そのユーザー名は既に使われています' }, 400);
    }

    // Check if display name is already taken
    const actualDisplayName = display_name || username;
    const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
      .bind(actualDisplayName, user.id).first();
    if (existingDisplayName) {
      return json({ error: 'その表示名は既に使われています' }, 400);
    }

    // Update username, display_name, password and status
    const { hash, salt } = await hashPassword(password);
    await env.DB.prepare('UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_salt = ?, status = ? WHERE id = ?')
      .bind(username, actualDisplayName, hash, salt, 'approved', user.id).run();

    // Create session for token invalidation support
    const sessionToken = await createSession(env, user.id, request);

    // Create token for auto-login with session
    const token = await createToken({
      id: user.id,
      username: username,
      display_name: actualDisplayName,
      is_admin: !!user.is_admin,
      sid: sessionToken
    }, env.JWT_SECRET);

    await logSecurityEvent(env, 'account_setup_complete', user.id, request, { member_source: user.member_source });

    return json(
      {
        success: true,
        message: 'アカウントを設定しました',
        user: { id: user.id, username: username, display_name: actualDisplayName, is_admin: !!user.is_admin }
      },
      200,
      { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
    );
  } catch (err) {
    console.error('Account setup error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// ==================== Subscription Management Handlers ====================

// Get current subscription status
async function handleGetSubscription(env, user) {
  const dbUser = await env.DB.prepare(
    'SELECT plan, member_source, stripe_customer_id, stripe_subscription_id, subscription_ends_at FROM users WHERE id = ?'
  ).bind(user.id).first();

  if (!dbUser) {
    return json({ error: 'ユーザーが見つかりません' }, 404);
  }

  // Determine subscription source and management method
  let managedBy = 'none';
  if (dbUser.member_source === 'wordpress') {
    managedBy = 'wordpress'; // Managed externally
  } else if (dbUser.member_source === 'stripe') {
    managedBy = 'stripe'; // Managed in-app
  }

  return json({
    plan: dbUser.plan || 'free',
    member_source: dbUser.member_source,
    managed_by: managedBy,
    has_stripe_subscription: !!dbUser.stripe_subscription_id,
    subscription_ends_at: dbUser.subscription_ends_at,
    can_manage_in_app: managedBy === 'stripe' || managedBy === 'none',
    stripe_enabled: !!env.STRIPE_SECRET_KEY && !!env.STRIPE_PRICE_ID
  });
}

// Get current usage counts for free tier limits display
async function handleGetUsage(env, user) {
  const dbUser = await env.DB.prepare(
    'SELECT plan, is_admin FROM users WHERE id = ?'
  ).bind(user.id).first();

  if (!dbUser) {
    return json({ error: 'ユーザーが見つかりません' }, 404);
  }

  const plan = dbUser.plan || 'free';
  const isAdmin = !!dbUser.is_admin;

  // Premium and admin users have no limits
  if (plan === 'premium' || isAdmin) {
    return json({
      plan,
      is_admin: isAdmin,
      has_limits: false
    });
  }

  // Free users - get current usage counts
  const [kmlFolders, pinFolders, kmlFiles, pins, shares] = await Promise.all([
    getUserKmlFolderCount(env, user.id),
    getUserPinFolderCount(env, user.id),
    getUserKmlFileCount(env, user.id),
    getUserPinCount(env, user.id),
    getUserShareCount(env, user.id)
  ]);

  return json({
    plan,
    is_admin: isAdmin,
    has_limits: true,
    usage: {
      kmlFolders: { current: kmlFolders, max: FREE_TIER_LIMITS.kmlFolders },
      pinFolders: { current: pinFolders, max: FREE_TIER_LIMITS.pinFolders },
      kmlFiles: { current: kmlFiles, max: FREE_TIER_LIMITS.kmlFiles },
      pins: { current: pins, max: FREE_TIER_LIMITS.pins },
      shares: { current: shares, max: FREE_TIER_LIMITS.shares }
    }
  });
}

// Create Stripe Checkout Session for new subscription
async function handleCreateCheckoutSession(request, env, user) {
  try {
    if (!env.STRIPE_SECRET_KEY) {
      return json({ error: 'Stripe is not configured' }, 500);
    }

    const dbUser = await env.DB.prepare(
      'SELECT plan, member_source, stripe_customer_id, email FROM users WHERE id = ?'
    ).bind(user.id).first();

    // Check if user is already premium via WordPress
    if (dbUser.member_source === 'wordpress' && dbUser.plan === 'premium') {
      return json({ error: 'WordPress経由で既にプレミアム会員です。課金管理はWordPress側で行ってください。' }, 400);
    }

    // Check if user already has an active Stripe subscription
    if (dbUser.member_source === 'stripe' && dbUser.plan === 'premium') {
      return json({ error: '既にプレミアム会員です' }, 400);
    }

    const { success_url, cancel_url } = await getRequestBody(request);
    const appUrl = success_url || 'https://fieldnota-commons.com';
    const cancelUrl = cancel_url || 'https://fieldnota-commons.com';

    // Create or retrieve Stripe customer
    // Use email from DB (not from payment method like Link/ApplePay)
    const userEmail = dbUser.email || '';
    let customerId = dbUser.stripe_customer_id;

    if (!customerId) {
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'email': userEmail,
          'name': user.display_name || user.username,
          'metadata[user_id]': user.id.toString()
        })
      });

      if (!customerResponse.ok) {
        const error = await customerResponse.text();
        console.error('Stripe customer creation failed:', error);
        return json({ error: 'Stripe customer creation failed' }, 500);
      }

      const customer = await customerResponse.json();
      customerId = customer.id;

      // Save customer ID
      await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
        .bind(customerId, user.id).run();
    } else {
      // Ensure existing customer has correct email (prevent Link/ApplePay email override)
      await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'email': userEmail,
          'metadata[user_id]': user.id.toString()
        })
      });
    }

    // Create Checkout Session
    // Note: customer_update prevents Link/ApplePay from overwriting customer data
    const sessionResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'customer': customerId,
        'customer_update[address]': 'never',
        'customer_update[name]': 'never',
        'mode': 'subscription',
        'line_items[0][price]': env.STRIPE_PRICE_ID,
        'line_items[0][quantity]': '1',
        'success_url': `${appUrl}?session_id={CHECKOUT_SESSION_ID}`,
        'cancel_url': cancelUrl,
        'metadata[user_id]': user.id.toString(),
        'metadata[user_email]': userEmail,
        'subscription_data[metadata][user_id]': user.id.toString(),
        'subscription_data[metadata][user_email]': userEmail
      })
    });

    if (!sessionResponse.ok) {
      const error = await sessionResponse.text();
      console.error('Stripe session creation failed:', error);
      return json({ error: 'Checkout session creation failed' }, 500);
    }

    const session = await sessionResponse.json();
    return json({ url: session.url, session_id: session.id });

  } catch (err) {
    console.error('Create checkout session error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// Create Stripe Checkout Session for organization plan
async function handleCreateOrgCheckoutSession(request, env, user) {
  try {
    if (!env.STRIPE_SECRET_KEY) {
      return json({ error: 'Stripe is not configured' }, 500);
    }
    if (!env.STRIPE_ORG_PRICE_ID) {
      return json({ error: 'Organization plan is not configured' }, 500);
    }

    const { org_name, success_url, cancel_url } = await getRequestBody(request);

    if (!org_name || !org_name.trim()) {
      return json({ error: '団体名を入力してください' }, 400);
    }
    if (org_name.length > 100) {
      return json({ error: '団体名は100文字以内にしてください' }, 400);
    }

    const dbUser = await env.DB.prepare(
      'SELECT stripe_customer_id, email FROM users WHERE id = ?'
    ).bind(user.id).first();

    const appUrl = success_url || 'https://fieldnota-commons.com';
    const cancelUrl = cancel_url || 'https://fieldnota-commons.com';
    const userEmail = dbUser.email || '';
    let customerId = dbUser.stripe_customer_id;

    if (!customerId) {
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'email': userEmail,
          'name': user.display_name || user.username,
          'metadata[user_id]': user.id.toString()
        })
      });

      if (!customerResponse.ok) {
        console.error('Stripe customer creation failed:', await customerResponse.text());
        return json({ error: 'Stripe customer creation failed' }, 500);
      }

      const customer = await customerResponse.json();
      customerId = customer.id;

      await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
        .bind(customerId, user.id).run();
    }

    const sessionResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'customer': customerId,
        'customer_update[address]': 'never',
        'customer_update[name]': 'never',
        'mode': 'subscription',
        'line_items[0][price]': env.STRIPE_ORG_PRICE_ID,
        'line_items[0][quantity]': '1',
        'success_url': `${appUrl}?session_id={CHECKOUT_SESSION_ID}`,
        'cancel_url': cancelUrl,
        'metadata[user_id]': user.id.toString(),
        'metadata[user_email]': userEmail,
        'metadata[org_name]': org_name.trim(),
        'metadata[type]': 'organization',
        'subscription_data[metadata][user_id]': user.id.toString(),
        'subscription_data[metadata][org_name]': org_name.trim(),
        'subscription_data[metadata][type]': 'organization'
      })
    });

    if (!sessionResponse.ok) {
      console.error('Stripe org session creation failed:', await sessionResponse.text());
      return json({ error: 'Checkout session creation failed' }, 500);
    }

    const session = await sessionResponse.json();
    return json({ url: session.url, session_id: session.id });

  } catch (err) {
    console.error('Create org checkout session error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// Handle Stripe Webhook events
async function handleStripeWebhook(request, env) {
  try {
    if (!env.STRIPE_WEBHOOK_SECRET) {
      console.error('STRIPE_WEBHOOK_SECRET not configured');
      return json({ error: 'Webhook not configured' }, 500);
    }

    const signature = request.headers.get('stripe-signature');
    if (!signature) {
      return json({ error: 'No signature' }, 400);
    }

    const body = await request.text();

    // Verify webhook signature
    const isValid = await verifyStripeWebhookSignature(body, signature, env.STRIPE_WEBHOOK_SECRET);
    if (!isValid) {
      console.error('Invalid webhook signature');
      return json({ error: 'Invalid signature' }, 400);
    }

    const event = JSON.parse(body);
    console.log('Stripe webhook event:', event.type);

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const userId = session.metadata?.user_id;
        const customerId = session.customer;
        const subscriptionId = session.subscription;
        const sessionType = session.metadata?.type;

        if (userId && sessionType === 'organization') {
          // Organization plan: create org and set user as admin
          const orgName = session.metadata?.org_name;
          if (orgName) {
            const result = await env.DB.prepare(
              'INSERT INTO organizations (name, created_by, stripe_subscription_id) VALUES (?, ?, ?)'
            ).bind(orgName, parseInt(userId), subscriptionId).run();

            const orgId = result.meta.last_row_id;
            await env.DB.prepare(
              'INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)'
            ).bind(orgId, parseInt(userId), 'admin').run();

            // Save customer ID on user
            await env.DB.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?')
              .bind(customerId, userId).run();

            await logSecurityEvent(env, 'org_subscription_created', parseInt(userId), request, {
              source: 'stripe',
              subscription_id: subscriptionId,
              organization_id: orgId
            });
          }
        } else if (userId) {
          // Personal premium plan
          await env.DB.prepare(`
            UPDATE users SET
              plan = 'premium',
              member_source = 'stripe',
              stripe_customer_id = ?,
              stripe_subscription_id = ?,
              subscription_ends_at = NULL
            WHERE id = ?
          `).bind(customerId, subscriptionId, userId).run();

          await logSecurityEvent(env, 'subscription_created', parseInt(userId), request, {
            source: 'stripe',
            subscription_id: subscriptionId
          });
        }
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const customerId = subscription.customer;
        const isOrgSub = subscription.metadata?.type === 'organization';

        if (isOrgSub) {
          // Organization subscription update - no action needed for now
          // Org data persists regardless of payment status
        } else {
          // Personal premium subscription
          const user = await env.DB.prepare(
            'SELECT id FROM users WHERE stripe_customer_id = ?'
          ).bind(customerId).first();

          if (user) {
            const status = subscription.status;
            if (status === 'active' || status === 'trialing') {
              await env.DB.prepare(`
                UPDATE users SET plan = 'premium', subscription_ends_at = NULL WHERE id = ?
              `).bind(user.id).run();
            } else if (status === 'canceled' || status === 'unpaid' || status === 'past_due') {
              const endsAt = new Date(subscription.current_period_end * 1000).toISOString();
              await env.DB.prepare(`
                UPDATE users SET subscription_ends_at = ? WHERE id = ?
              `).bind(endsAt, user.id).run();
            }
          }
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const customerId = subscription.customer;
        const isOrgSub = subscription.metadata?.type === 'organization';

        if (isOrgSub) {
          // Organization subscription canceled - log it
          const org = await env.DB.prepare(
            'SELECT id, created_by FROM organizations WHERE stripe_subscription_id = ?'
          ).bind(subscription.id).first();
          if (org) {
            await logSecurityEvent(env, 'org_subscription_canceled', org.created_by, request, {
              source: 'stripe',
              subscription_id: subscription.id,
              organization_id: org.id
            });
          }
        } else {
          // Personal premium subscription canceled
          const user = await env.DB.prepare(
            'SELECT id FROM users WHERE stripe_customer_id = ?'
          ).bind(customerId).first();

          if (user) {
            await env.DB.prepare(`
              UPDATE users SET
                plan = 'free',
                member_source = NULL,
                stripe_subscription_id = NULL,
                subscription_ends_at = NULL
              WHERE id = ?
            `).bind(user.id).run();

            await logSecurityEvent(env, 'subscription_canceled', user.id, request, {
              source: 'stripe',
              subscription_id: subscription.id
            });
          }
        }
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        const customerId = invoice.customer;

        const user = await env.DB.prepare(
          'SELECT id FROM users WHERE stripe_customer_id = ?'
        ).bind(customerId).first();

        if (user) {
          await logSecurityEvent(env, 'payment_failed', user.id, request, {
            invoice_id: invoice.id
          });
        }
        break;
      }
    }

    return json({ received: true });

  } catch (err) {
    console.error('Stripe webhook error:', err);
    return json({ error: 'Webhook error' }, 500);
  }
}

// Verify Stripe webhook signature
async function verifyStripeWebhookSignature(payload, signature, secret) {
  try {
    const parts = signature.split(',').reduce((acc, part) => {
      const [key, value] = part.split('=');
      acc[key] = value;
      return acc;
    }, {});

    const timestamp = parts['t'];
    const sig = parts['v1'];

    if (!timestamp || !sig) return false;

    // Check timestamp tolerance (5 minutes)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - parseInt(timestamp)) > 300) return false;

    // Compute expected signature
    const signedPayload = `${timestamp}.${payload}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signatureBytes = await crypto.subtle.sign('HMAC', key, encoder.encode(signedPayload));
    const expectedSig = Array.from(new Uint8Array(signatureBytes))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return sig === expectedSig;
  } catch (err) {
    console.error('Signature verification error:', err);
    return false;
  }
}

// Create Stripe Customer Portal session for subscription management
// Step 1 (no code): Send verification code via email, return { needCode, email }
// Step 2 (with code): Verify code and return Stripe portal URL
async function handleCreatePortalSession(request, env, user) {
  try {
    if (!env.STRIPE_SECRET_KEY) {
      return json({ error: 'Stripe is not configured' }, 500);
    }

    const body = await getRequestBody(request).catch(() => ({}));
    const { code } = body;

    // Step 1: No code provided — send verification code via email
    if (!code) {
      const dbUser = await env.DB.prepare(
        'SELECT email FROM users WHERE id = ?'
      ).bind(user.id).first();

      if (!dbUser || !dbUser.email) {
        return json({ error: 'メールアドレスが登録されていません' }, 400);
      }

      // Delete any existing codes for this user/purpose
      await env.DB.prepare(
        "DELETE FROM verification_codes WHERE user_id = ? AND purpose = 'portal'"
      ).bind(user.id).run();

      // Generate 6-digit code
      const newCode = String(Math.floor(100000 + Math.random() * 900000));
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();

      await env.DB.prepare(
        "INSERT INTO verification_codes (user_id, code, purpose, expires_at) VALUES (?, ?, 'portal', ?)"
      ).bind(user.id, newCode, expiresAt).run();

      const subject = '管理画面アクセス確認コード - Fieldnota commons';
      const htmlBody = `
        <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
          <h2 style="color: #333;">確認コード</h2>
          <p>Stripe管理画面へのアクセスが要求されました。</p>
          <div style="background: #f5f5f5; padding: 20px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <span style="font-size: 32px; letter-spacing: 8px; font-weight: bold; color: #1a1a1a;">${newCode}</span>
          </div>
          <p style="color: #666; font-size: 14px;">このコードは5分間有効です。心当たりがない場合は無視してください。</p>
        </div>
      `;
      const textBody = `確認コード: ${newCode}\nこのコードは5分間有効です。`;

      const sent = await sendEmail(env, dbUser.email, subject, htmlBody, textBody);
      if (!sent) {
        return json({ error: 'メール送信に失敗しました' }, 500);
      }

      // Mask email for display
      const [local, domain] = dbUser.email.split('@');
      const masked = local.slice(0, 2) + '***@' + domain;

      return json({ needCode: true, email: masked });
    }

    // Step 2: Code provided — verify and create portal session
    const codeRecord = await env.DB.prepare(
      "SELECT id, code, expires_at FROM verification_codes WHERE user_id = ? AND purpose = 'portal' ORDER BY created_at DESC LIMIT 1"
    ).bind(user.id).first();

    if (!codeRecord || codeRecord.code !== code) {
      return json({ error: '確認コードが正しくありません' }, 401);
    }

    if (new Date(codeRecord.expires_at) < new Date()) {
      await env.DB.prepare('DELETE FROM verification_codes WHERE id = ?').bind(codeRecord.id).run();
      return json({ error: '確認コードの有効期限が切れています。再度お試しください' }, 401);
    }

    // Delete used code
    await env.DB.prepare('DELETE FROM verification_codes WHERE id = ?').bind(codeRecord.id).run();

    const dbUser = await env.DB.prepare(
      'SELECT stripe_customer_id, member_source FROM users WHERE id = ?'
    ).bind(user.id).first();

    if (dbUser.member_source === 'wordpress') {
      return json({ error: 'WordPress経由の会員はWordPress側で管理してください' }, 400);
    }

    if (!dbUser.stripe_customer_id) {
      return json({ error: 'Stripe顧客情報がありません' }, 400);
    }

    const portalResponse = await fetch('https://api.stripe.com/v1/billing_portal/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'customer': dbUser.stripe_customer_id,
        'return_url': 'https://fieldnota-commons.com'
      })
    });

    if (!portalResponse.ok) {
      const error = await portalResponse.text();
      console.error('Stripe portal session creation failed:', error);
      return json({ error: 'Portal session creation failed' }, 500);
    }

    const session = await portalResponse.json();
    return json({ url: session.url });

  } catch (err) {
    console.error('Create portal session error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// Cancel subscription (for Stripe direct users)
async function handleCancelSubscription(env, user) {
  try {
    if (!env.STRIPE_SECRET_KEY) {
      return json({ error: 'Stripe is not configured' }, 500);
    }

    const dbUser = await env.DB.prepare(
      'SELECT stripe_subscription_id, member_source FROM users WHERE id = ?'
    ).bind(user.id).first();

    if (dbUser.member_source === 'wordpress') {
      return json({ error: 'WordPress経由の会員はWordPress側で解約してください' }, 400);
    }

    if (!dbUser.stripe_subscription_id) {
      return json({ error: '有効なサブスクリプションがありません' }, 400);
    }

    // Cancel at period end (don't cancel immediately)
    const cancelResponse = await fetch(
      `https://api.stripe.com/v1/subscriptions/${dbUser.stripe_subscription_id}`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'cancel_at_period_end': 'true'
        })
      }
    );

    if (!cancelResponse.ok) {
      const error = await cancelResponse.text();
      console.error('Stripe subscription cancel failed:', error);
      return json({ error: 'Subscription cancellation failed' }, 500);
    }

    const subscription = await cancelResponse.json();
    const endsAt = new Date(subscription.current_period_end * 1000).toISOString();

    await env.DB.prepare('UPDATE users SET subscription_ends_at = ? WHERE id = ?')
      .bind(endsAt, user.id).run();

    await logSecurityEvent(env, 'subscription_cancel_requested', user.id, null, {
      subscription_id: dbUser.stripe_subscription_id,
      ends_at: endsAt
    });

    return json({
      success: true,
      message: '解約手続きが完了しました。現在の請求期間終了まではプレミアム機能をご利用いただけます。',
      subscription_ends_at: endsAt
    });

  } catch (err) {
    console.error('Cancel subscription error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

async function handleUpdateProfile(request, env, user) {
  const { display_name } = await getRequestBody(request);
  if (!display_name) {
    return json({ error: '表示名を入力してください' }, 400);
  }

  // Check if display name is already used by another user
  const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
    .bind(display_name, user.id).first();
  if (existingDisplayName) {
    return json({ error: 'その表示名は既に使われています' }, 400);
  }

  await env.DB.prepare('UPDATE users SET display_name = ? WHERE id = ?')
    .bind(display_name, user.id).run();

  // Create new token with updated display_name (preserve session token)
  const token = await createToken({
    id: user.id,
    username: user.username,
    display_name: display_name,
    is_admin: user.is_admin,
    sid: user.sid
  }, env.JWT_SECRET);

  return json(
    { ok: true, display_name: display_name },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

async function handleChangePassword(request, env, user) {
  const { current_password, new_password, revoke_other_sessions } = await getRequestBody(request);

  if (!current_password) {
    return json({ error: '現在のパスワードを入力してください' }, 400);
  }
  if (!new_password || new_password.length < 12) {
    return json({ error: '新しいパスワードは12文字以上にしてください' }, 400);
  }

  // Verify current password
  const dbUser = await env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?')
    .bind(user.id).first();
  if (!dbUser || !(await verifyPassword(current_password, dbUser.password_hash, dbUser.password_salt))) {
    return json({ error: '現在のパスワードが正しくありません' }, 401);
  }

  // Update password
  const { hash: newHash, salt: newSalt } = await hashPassword(new_password);
  await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(newHash, newSalt, user.id).run();

  // Revoke all other sessions if requested (recommended for security)
  if (revoke_other_sessions !== false && user.sid) {
    await revokeAllUserSessions(env, user.id, user.sid);
  }

  await logSecurityEvent(env, 'password_changed', user.id, request, { revoked_sessions: revoke_other_sessions !== false });

  return json({ ok: true });
}

// Delete account (soft-delete: anonymize user row, delete user data)
async function handleDeleteAccount(request, env, user) {
  try {
    const body = await getRequestBody(request).catch(() => ({}));
    const { consent } = body;

    if (!consent) {
      return json({ error: 'データ削除への同意が必要です' }, 400);
    }

    // Verify user exists
    const dbUser = await env.DB.prepare(
      'SELECT id FROM users WHERE id = ?'
    ).bind(user.id).first();

    if (!dbUser) {
      return json({ error: 'ユーザーが見つかりません' }, 404);
    }

    // Delete user's R2 images (pin_images) - only personal pins, not org folder pins
    try {
      const userPins = await env.DB.prepare(
        'SELECT id FROM pins WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM folders WHERE organization_id IS NULL))'
      ).bind(user.id).all();
      for (const pin of userPins.results) {
        const images = await env.DB.prepare('SELECT r2_key FROM pin_images WHERE pin_id = ?').bind(pin.id).all();
        for (const img of images.results) {
          try { await env.R2.delete(img.r2_key); } catch (e) { /* ignore */ }
        }
      }
    } catch (e) { console.error('R2 pin image cleanup error:', e); }

    // Delete user's R2 files (kml_files) - only personal, not org folder files
    try {
      const userKmlFiles = await env.DB.prepare(
        'SELECT r2_key FROM kml_files WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM kml_folders WHERE organization_id IS NULL))'
      ).bind(user.id).all();
      for (const f of userKmlFiles.results) {
        try { await env.R2.delete(f.r2_key); } catch (e) { /* ignore */ }
      }
    } catch (e) { console.error('R2 kml file cleanup error:', e); }

    // Delete DB data owned by user (only personal data, not org folder content)
    // Batch 1: Pin-related data (personal only)
    await env.DB.batch([
      env.DB.prepare('DELETE FROM pin_images WHERE pin_id IN (SELECT id FROM pins WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM folders WHERE organization_id IS NULL)))').bind(user.id),
      env.DB.prepare('DELETE FROM pin_comments WHERE pin_id IN (SELECT id FROM pins WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM folders WHERE organization_id IS NULL)))').bind(user.id),
      env.DB.prepare('DELETE FROM pins WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM folders WHERE organization_id IS NULL))').bind(user.id),
    ]);

    // Batch 2: Folder-related data (personal only, not org folders)
    await env.DB.batch([
      env.DB.prepare('DELETE FROM folder_shares WHERE folder_id IN (SELECT id FROM folders WHERE user_id = ? AND organization_id IS NULL)').bind(user.id),
      env.DB.prepare('DELETE FROM folder_visibility WHERE folder_id IN (SELECT id FROM folders WHERE user_id = ? AND organization_id IS NULL)').bind(user.id),
      env.DB.prepare('DELETE FROM folders WHERE user_id = ? AND organization_id IS NULL').bind(user.id),
    ]);

    // Batch 3: KML-related data (personal only, not org folders)
    await env.DB.batch([
      env.DB.prepare('DELETE FROM kml_files WHERE user_id = ? AND (folder_id IS NULL OR folder_id IN (SELECT id FROM kml_folders WHERE organization_id IS NULL))').bind(user.id),
      env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id IN (SELECT id FROM kml_folders WHERE user_id = ? AND organization_id IS NULL)').bind(user.id),
      env.DB.prepare('DELETE FROM kml_folder_visibility WHERE kml_folder_id IN (SELECT id FROM kml_folders WHERE user_id = ? AND organization_id IS NULL)').bind(user.id),
      env.DB.prepare('DELETE FROM kml_folders WHERE user_id = ? AND organization_id IS NULL').bind(user.id),
    ]);

    // Batch 4: User metadata + organization memberships
    await env.DB.batch([
      env.DB.prepare('DELETE FROM comment_read_status WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM push_subscriptions WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM passkeys WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM passkey_challenges WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM verification_codes WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM organization_members WHERE user_id = ?').bind(user.id),
      env.DB.prepare('DELETE FROM organization_invitations WHERE invited_by = ?').bind(user.id),
    ]);

    // Soft-delete: anonymize user row (keep for counting)
    // password_hash uses placeholder (NOT NULL constraint)
    await env.DB.prepare(
      `UPDATE users SET
        username = ?, display_name = ?, email = NULL,
        password_hash = '', password_salt = NULL,
        status = 'deleted', stripe_customer_id = NULL,
        stripe_subscription_id = NULL, external_id = NULL
      WHERE id = ?`
    ).bind(`deleted_${user.id}`, `退会済みユーザー`, user.id).run();

    await logSecurityEvent(env, 'account_deleted', user.id, request, {});

    return json({ ok: true });
  } catch (err) {
    console.error('Delete account error:', err);
    return json({ error: 'Server error' }, 500);
  }
}

// ==================== Session Management Handlers ====================

// Get all active sessions for the current user
async function handleGetSessions(env, user) {
  const sessions = await getUserSessions(env, user.id);

  // Mark current session
  const sessionsWithCurrent = sessions.map(session => ({
    ...session,
    is_current: false  // Will be set based on session token comparison
  }));

  return json(sessionsWithCurrent);
}

// Revoke a specific session
async function handleRevokeSession(env, user, sessionId) {
  const success = await revokeSessionById(env, sessionId, user.id);
  if (!success) {
    return json({ error: 'セッションが見つかりません' }, 404);
  }

  await logSecurityEvent(env, 'session_revoked', user.id, null, { session_id: sessionId });
  return json({ ok: true });
}

// Revoke all sessions except current
async function handleRevokeAllSessions(env, user) {
  if (!user.sid) {
    return json({ error: '現在のセッションが無効です' }, 400);
  }

  await revokeAllUserSessions(env, user.id, user.sid);
  await logSecurityEvent(env, 'all_sessions_revoked', user.id, null, {});

  return json({ ok: true });
}

// ==================== Users Handlers ====================
async function handleGetUsers(env, user) {
  // Only return id, username, display_name - do not expose is_admin to regular users
  const users = await env.DB.prepare(
    'SELECT id, username, display_name FROM users WHERE id != ? AND status = ? ORDER BY display_name'
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
    const appUrl = 'https://fieldnota-commons.com';
    const subject = 'アカウントが承認されました - Fieldnota commons';
    const htmlBody = `
      <h2>アカウント承認のお知らせ</h2>
      <p>${user.display_name || user.username} 様</p>
      <p>Fieldnota commonsへのアカウント申請が承認されました。</p>
      <p>以下のリンクからログインしてご利用ください。</p>
      <p><a href="${appUrl}">${appUrl}</a></p>
      <br>
      <p><strong>※ユーザー名はフルネーム（ローマ字）で登録されています。</strong></p>
      <p>例: Taro Yamada</p>
      <br>
      <p>Fieldnota commons</p>
    `;
    const textBody = `${user.display_name || user.username} 様\n\nFieldnota commonsへのアカウント申請が承認されました。\n以下のリンクからログインしてご利用ください。\n\n${appUrl}\n\n※ユーザー名はフルネーム（ローマ字）で登録されています。\n例: Taro Yamada\n\nFieldnota commons`;
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
    const subject = 'アカウント申請について - Fieldnota commons';
    const htmlBody = `
      <h2>アカウント申請のお知らせ</h2>
      <p>${user.display_name || user.username} 様</p>
      <p>申し訳ございませんが、Fieldnota commonsへのアカウント申請は承認されませんでした。</p>
      <p>ご不明な点がございましたら、管理者までお問い合わせください。</p>
      <br>
      <p>Fieldnota commons</p>
    `;
    const textBody = `${user.display_name || user.username} 様\n\n申し訳ございませんが、Fieldnota commonsへのアカウント申請は承認されませんでした。\nご不明な点がございましたら、管理者までお問い合わせください。\n\nFieldnota commons`;
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

  let query = 'SELECT id, event_type, user_id, created_at FROM security_logs';
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
        COALESCE(kfv.is_visible, 1) as is_visible,
        CASE WHEN EXISTS (SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = kf.id) THEN 1 ELSE 0 END as is_shared,
        o.name as organization_name
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      LEFT JOIN kml_folder_visibility kfv ON kf.id = kfv.kml_folder_id AND kfv.user_id = ?
      LEFT JOIN organizations o ON kf.organization_id = o.id
      WHERE kf.user_id = ? OR kf.is_public = 1
        OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
        OR kf.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
      ORDER BY kf.sort_order, kf.name
    `).bind(user.id, user.id, user.id, user.id, user.id).all();
  } else {
    folders = await env.DB.prepare(`
      SELECT kf.*, u.display_name as owner_name, 0 as is_owner, 1 as is_visible, 0 as is_shared
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      WHERE kf.is_public = 1
      ORDER BY kf.sort_order, kf.name
    `).all();
  }
  return json(folders.results);
}

async function handleCreateKmlFolder(request, env, user) {
  const { name, is_public, parent_id } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Check free tier limit
  const limitCheck = await checkFreeTierLimit(env, user, 'kmlFolder');
  if (!limitCheck.allowed) {
    return json({ error: limitCheck.message }, 403);
  }

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
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { name, is_public } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Only admin can change is_public
  const publicFlag = user.is_admin && is_public !== undefined ? (is_public ? 1 : 0) : folder.is_public;

  await env.DB.prepare('UPDATE kml_folders SET name = ?, is_public = ? WHERE id = ?')
    .bind(name, publicFlag, id).run();
  return json({ ok: true, name: name, is_public: publicFlag });
}

async function handleDeleteKmlFolder(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) {
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
  // Verify user has access to this folder (owner, public, shared, or org member)
  const folder = await env.DB.prepare(`
    SELECT kf.* FROM kml_folders kf
    WHERE kf.id = ? AND (kf.user_id = ? OR kf.is_public = 1
      OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
      OR kf.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?))
  `).bind(id, user.id, user.id, user.id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  const { is_visible } = await getRequestBody(request);
  await env.DB.prepare(`
    INSERT INTO kml_folder_visibility (kml_folder_id, user_id, is_visible) VALUES (?, ?, ?)
    ON CONFLICT(kml_folder_id, user_id) DO UPDATE SET is_visible = excluded.is_visible
  `).bind(id, user.id, is_visible ? 1 : 0).run();
  return json({ ok: true });
}

async function handleGetKmlFolderShares(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  // User must be owner, admin, shared with this folder, or org member
  const isOwner = folder.user_id === user.id;
  const isSiteAdmin = user.is_admin;
  const isSharedWith = await env.DB.prepare(
    'SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = ? AND shared_with_user_id = ?'
  ).bind(id, user.id).first();
  const isMember = folder.organization_id && await isOrgMember(env, user.id, folder.organization_id);

  if (!isOwner && !isSiteAdmin && !isSharedWith && !isMember) {
    return json({ error: '権限がありません' }, 403);
  }

  const shares = await env.DB.prepare(`
    SELECT kfs.shared_with_user_id, u.username, u.display_name
    FROM kml_folder_shares kfs
    JOIN users u ON kfs.shared_with_user_id = u.id
    WHERE kfs.kml_folder_id = ?
  `).bind(id).all();

  return json(shares.results);
}

async function handleShareKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await getRequestBody(request);
  const newUserIds = user_ids || [];

  // Check free tier limit for folder owner (admin can share without limits)
  if (!user.is_admin && newUserIds.length > 0) {
    // Get current existing shares for this folder
    const existingShares = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM kml_folder_shares WHERE kml_folder_id = ?'
    ).bind(id).first();

    // If adding new shares (not just updating existing ones), check limit
    if (newUserIds.length > existingShares.count) {
      const limitCheck = await checkFreeTierLimit(env, user, 'share');
      if (!limitCheck.allowed) {
        return json({ error: limitCheck.message }, 403);
      }
    }
  }

  await env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id = ?').bind(id).run();

  for (const uid of newUserIds) {
    await env.DB.prepare(
      'INSERT INTO kml_folder_shares (kml_folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(id, uid).run();
  }
  return json({ ok: true });
}

async function handleReorderKmlFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await getRequestBody(request);

  // Get all folders at the same level (scoped by org or user)
  let siblings;
  if (folder.organization_id) {
    // Organization folder: scope to org
    if (folder.parent_id) {
      siblings = await env.DB.prepare(`
        SELECT id, sort_order FROM kml_folders
        WHERE organization_id = ? AND parent_id = ?
        ORDER BY sort_order, id
      `).bind(folder.organization_id, folder.parent_id).all();
    } else {
      siblings = await env.DB.prepare(`
        SELECT id, sort_order FROM kml_folders
        WHERE organization_id = ? AND parent_id IS NULL
        ORDER BY sort_order, id
      `).bind(folder.organization_id).all();
    }
  } else if (folder.parent_id) {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM kml_folders
      WHERE user_id = ? AND organization_id IS NULL AND parent_id = ?
      ORDER BY sort_order, id
    `).bind(user.id, folder.parent_id).all();
  } else {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM kml_folders
      WHERE user_id = ? AND organization_id IS NULL AND parent_id IS NULL
      ORDER BY sort_order, id
    `).bind(user.id).all();
  }

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
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { parent_id } = await getRequestBody(request);

  // Cannot move folder to itself
  if (parent_id && parseInt(parent_id) === parseInt(id)) {
    return json({ error: '自分自身には移動できません' }, 400);
  }

  // Check if target parent exists and user has edit permission
  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(parent_id).first();
    if (!parent) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (!await canEditFolder(env, user, parent)) {
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
        WHERE kf.folder_id = ? AND (kf.user_id = ? OR f.is_public = 1
          OR kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
          OR f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?))
        ORDER BY kf.original_name`;
      bindings = [folderId, user.id, user.id, user.id];
    } else {
      // All KML files user can access (own files, public folder files, shared folder files, org folder files)
      query = `SELECT kf.*, u.display_name as owner_name,
          COALESCE(f.is_public, 0) as is_public
        FROM kml_files kf
        LEFT JOIN users u ON kf.user_id = u.id
        LEFT JOIN kml_folders f ON kf.folder_id = f.id
        WHERE kf.user_id = ? OR f.is_public = 1
          OR kf.folder_id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
          OR f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
        ORDER BY kf.original_name`;
      bindings = [user.id, user.id, user.id];
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

  // Check free tier limit (skip if uploading to admin's public/shared folder or org folder)
  let isExemptFolder = false;
  if (folderId) {
    const folder = await env.DB.prepare(`
      SELECT f.*, u.is_admin FROM kml_folders f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = ?
    `).bind(folderId).first();
    if (folder) {
      if (folder.organization_id) {
        isExemptFolder = true;
      } else if (folder.is_admin) {
        isExemptFolder = folder.is_public === 1 ||
          await env.DB.prepare('SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = ? AND shared_with_user_id = ?')
            .bind(folderId, user.id).first();
      }
    }
  }
  if (!isExemptFolder) {
    const limitCheck = await checkFreeTierLimit(env, user, 'kmlFile');
    if (!limitCheck.allowed) {
      return json({ error: limitCheck.message }, 403);
    }
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

  // Send push notification for new KML file
  if (folderId) {
    try {
      const folder = await env.DB.prepare('SELECT is_public FROM kml_folders WHERE id = ?').bind(folderId).first();
      if (folder) {
        await sendPushNotifications(env, 'kml', {
          title: '新しいKMLファイル',
          body: `${user.display_name || user.username}: ${file.name.substring(0, 30)}`,
          id: result.meta.last_row_id,
          creatorId: user.id
        }, { id: folderId, is_public: folder.is_public === 1, type: 'kml' });
      }
    } catch (e) {
      console.error('Push notification error:', e);
    }
  }

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
          OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
          OR kf.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?))
      `).bind(file.folder_id, user.id, user.id, user.id).first());

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
  if (!await canEditKmlFile(env, user, file)) {
    return json({ error: '権限がありません' }, 403);
  }

  await env.R2.delete(file.r2_key);
  await env.DB.prepare('DELETE FROM kml_files WHERE id = ?').bind(id).run();
  return json({ ok: true });
}

async function handleMoveKmlFile(request, env, user, id) {
  const file = await env.DB.prepare('SELECT * FROM kml_files WHERE id = ?').bind(id).first();
  if (!file) return json({ error: 'ファイルが見つかりません' }, 404);
  if (!await canEditKmlFile(env, user, file)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { folder_id } = await getRequestBody(request);

  // Check if target folder exists and user has edit permission
  if (folder_id) {
    const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(folder_id).first();
    if (!folder) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (!await canEditFolder(env, user, folder)) {
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
      SELECT f.*, u.display_name as owner_name, 0 as is_owner, 1 as is_visible, 0 as is_shared
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
      COALESCE(fv.is_visible, 1) as is_visible,
      CASE WHEN EXISTS (SELECT 1 FROM folder_shares WHERE folder_id = f.id) THEN 1 ELSE 0 END as is_shared,
      o.name as organization_name
    FROM folders f
    LEFT JOIN users u ON f.user_id = u.id
    LEFT JOIN folder_visibility fv ON f.id = fv.folder_id AND fv.user_id = ?
    LEFT JOIN organizations o ON f.organization_id = o.id
    WHERE f.user_id = ? OR f.is_public = 1
      OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      OR f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
    ORDER BY f.sort_order, f.name
  `).bind(user.id, user.id, user.id, user.id, user.id).all();

  return json(folders.results);
}

async function handleCreateFolder(request, env, user) {
  const { name, parent_id, is_public } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Check free tier limit
  const limitCheck = await checkFreeTierLimit(env, user, 'pinFolder');
  if (!limitCheck.allowed) {
    return json({ error: limitCheck.message }, 403);
  }

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
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { name, is_public } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  // Only admin can change is_public
  const publicFlag = user.is_admin && is_public !== undefined ? (is_public ? 1 : 0) : (folder.is_public || 0);

  await env.DB.prepare('UPDATE folders SET name = ?, is_public = ? WHERE id = ?')
    .bind(name, publicFlag, id).run();
  return json({ ok: true, name: name, is_public: publicFlag });
}

async function handleDeleteFolder(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) {
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

async function handleGetFolderShares(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  // User must be owner, admin, shared with this folder, or org member
  const isOwner = folder.user_id === user.id;
  const isSiteAdmin = user.is_admin;
  const isSharedWith = await env.DB.prepare(
    'SELECT 1 FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
  ).bind(id, user.id).first();
  const isMember = folder.organization_id && await isOrgMember(env, user.id, folder.organization_id);

  if (!isOwner && !isSiteAdmin && !isSharedWith && !isMember) {
    return json({ error: '権限がありません' }, 403);
  }

  const shares = await env.DB.prepare(`
    SELECT fs.shared_with_user_id, u.username, u.display_name
    FROM folder_shares fs
    JOIN users u ON fs.shared_with_user_id = u.id
    WHERE fs.folder_id = ?
  `).bind(id).all();

  return json(shares.results);
}

async function handleShareFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await getRequestBody(request);
  const newUserIds = user_ids || [];

  // Check free tier limit for folder owner (admin can share without limits)
  if (!user.is_admin && newUserIds.length > 0) {
    // Get current existing shares for this folder
    const existingShares = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM folder_shares WHERE folder_id = ?'
    ).bind(id).first();

    // If adding new shares (not just updating existing ones), check limit
    if (newUserIds.length > existingShares.count) {
      const limitCheck = await checkFreeTierLimit(env, user, 'share');
      if (!limitCheck.allowed) {
        return json({ error: limitCheck.message }, 403);
      }
    }
  }

  await env.DB.prepare('DELETE FROM folder_shares WHERE folder_id = ?').bind(id).run();

  for (const uid of newUserIds) {
    await env.DB.prepare(
      'INSERT INTO folder_shares (folder_id, shared_with_user_id) VALUES (?, ?)'
    ).bind(id, uid).run();
  }
  return json({ ok: true });
}

async function handleReorderFolder(request, env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await getRequestBody(request);

  // Get all folders at the same level (scoped by org or user)
  let siblings;
  if (folder.organization_id) {
    if (folder.parent_id) {
      siblings = await env.DB.prepare(`
        SELECT id, sort_order FROM folders
        WHERE organization_id = ? AND parent_id = ?
        ORDER BY sort_order, id
      `).bind(folder.organization_id, folder.parent_id).all();
    } else {
      siblings = await env.DB.prepare(`
        SELECT id, sort_order FROM folders
        WHERE organization_id = ? AND parent_id IS NULL
        ORDER BY sort_order, id
      `).bind(folder.organization_id).all();
    }
  } else if (folder.parent_id) {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM folders
      WHERE user_id = ? AND organization_id IS NULL AND parent_id = ?
      ORDER BY sort_order, id
    `).bind(user.id, folder.parent_id).all();
  } else {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM folders
      WHERE user_id = ? AND organization_id IS NULL AND parent_id IS NULL
      ORDER BY sort_order, id
    `).bind(user.id).all();
  }

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
  if (!await canEditFolder(env, user, folder)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { parent_id } = await getRequestBody(request);

  // Cannot move folder to itself
  if (parent_id && parseInt(parent_id) === parseInt(id)) {
    return json({ error: '自分自身には移動できません' }, 400);
  }

  // Check if target parent exists and user has edit permission
  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(parent_id).first();
    if (!parent) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (!await canEditFolder(env, user, parent)) {
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
  // Verify user has access to this folder (owner, public, shared, or org member)
  const folder = await env.DB.prepare(`
    SELECT f.* FROM folders f
    WHERE f.id = ? AND (f.user_id = ? OR f.is_public = 1
      OR f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
      OR f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?))
  `).bind(id, user.id, user.id, user.id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  const { is_visible } = await getRequestBody(request);
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
        CASE WHEN f.is_public = 1 THEN 1 ELSE 0 END as is_public,
        CASE WHEN EXISTS (SELECT 1 FROM folder_shares WHERE folder_id = p.folder_id) THEN 1 ELSE 0 END as is_shared
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      ORDER BY p.created_at DESC
    `).all();
  } else if (user) {
    // User sees: own pins, pins in public folders, pins in shared folders, pins in org folders
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author,
        CASE WHEN f.is_public = 1 THEN 1 ELSE 0 END as is_public,
        CASE WHEN EXISTS (SELECT 1 FROM folder_shares WHERE folder_id = p.folder_id) THEN 1 ELSE 0 END as is_shared
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      WHERE p.user_id = ?
        OR f.is_public = 1
        OR p.folder_id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?)
        OR f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
      ORDER BY p.created_at DESC
    `).bind(user.id, user.id, user.id).all();
  } else {
    // Non-logged in users see only pins in public folders
    pins = await env.DB.prepare(`
      SELECT p.*, u.display_name as author, 1 as is_public, 0 as is_shared
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
    const body = await getRequestBody(request);
    title = body.title;
    description = body.description || '';
    lat = body.lat;
    lng = body.lng;
    folder_id = body.folder_id || null;
  }

  if (!title || lat == null || lng == null) {
    return json({ error: 'タイトルと座標は必須です' }, 400);
  }

  // Validate coordinate ranges
  if (isNaN(lat) || lat < -90 || lat > 90) {
    return json({ error: '緯度は-90から90の範囲で指定してください' }, 400);
  }
  if (isNaN(lng) || lng < -180 || lng > 180) {
    return json({ error: '経度は-180から180の範囲で指定してください' }, 400);
  }

  // Check free tier limit (skip if creating in admin's public/shared folder or org folder)
  let isExemptFolder = false;
  if (folder_id) {
    const folder = await env.DB.prepare(`
      SELECT f.*, u.is_admin FROM folders f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = ?
    `).bind(folder_id).first();
    if (folder) {
      // Exempt: admin's public/shared folders or org folders
      if (folder.organization_id) {
        isExemptFolder = true;
      } else if (folder.is_admin) {
        isExemptFolder = folder.is_public === 1 ||
          await env.DB.prepare('SELECT 1 FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?')
            .bind(folder_id, user.id).first();
      }
    }
  }
  if (!isExemptFolder) {
    const limitCheck = await checkFreeTierLimit(env, user, 'pin');
    if (!limitCheck.allowed) {
      return json({ error: limitCheck.message }, 403);
    }
  }

  // Verify folder access if folder_id is specified
  if (folder_id) {
    const folder = await env.DB.prepare(`
      SELECT f.* FROM folders f
      WHERE f.id = ? AND (
        f.user_id = ? OR
        f.is_public = 1 OR
        f.id IN (SELECT folder_id FROM folder_shares WHERE shared_with_user_id = ?) OR
        f.organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = ?)
      )
    `).bind(folder_id, user.id, user.id, user.id).first();
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

  // Send push notification for new pin
  if (folder_id) {
    try {
      const folder = await env.DB.prepare('SELECT is_public FROM folders WHERE id = ?').bind(folder_id).first();
      if (folder) {
        await sendPushNotifications(env, 'pin', {
          title: '新しいピン',
          body: `${user.display_name || user.username}: ${title.substring(0, 30)}`,
          id: pinId,
          creatorId: user.id
        }, { id: folder_id, is_public: folder.is_public === 1, type: 'pin' });
      }
    } catch (e) {
      console.error('Push notification error:', e);
    }
  }

  return json({ id: pinId, title, description, lat, lng, folder_id, user_id: user.id, images });
}

async function handleUpdatePin(request, env, user, id) {
  const pin = await env.DB.prepare('SELECT * FROM pins WHERE id = ?').bind(id).first();
  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);
  if (!await canEditPin(env, user, pin)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { title, description, folder_id } = await getRequestBody(request);

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
  if (!await canEditPin(env, user, pin)) {
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
  if (!await canEditPin(env, user, pin)) {
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
  if (!await canEditPin(env, user, pin)) {
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
  if (!await canEditPin(env, user, pin)) {
    return json({ error: '権限がありません' }, 403);
  }

  const { folder_id } = await getRequestBody(request);

  // Check if target folder exists and user has edit permission
  if (folder_id) {
    const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(folder_id).first();
    if (!folder) return json({ error: '移動先フォルダが見つかりません' }, 404);
    if (!await canEditFolder(env, user, folder)) {
      return json({ error: '移動先フォルダの権限がありません' }, 403);
    }
  }

  await env.DB.prepare('UPDATE pins SET folder_id = ? WHERE id = ?')
    .bind(folder_id || null, id).run();
  return json({ ok: true });
}

// ==================== Pin Comments Handlers ====================
async function handleGetPinComments(env, user, pinId) {
  // Check if pin exists and user has access
  const pin = await env.DB.prepare(`
    SELECT p.*, f.is_public as folder_is_public, f.user_id as folder_user_id, f.organization_id as folder_org_id
    FROM pins p
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE p.id = ?
  `).bind(pinId).first();

  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);

  // Check access: owner, admin, public folder, shared folder, or org member
  const folderIsPublic = pin.folder_is_public === 1;
  const isOwner = user && pin.user_id === user.id;
  const isSiteAdmin = user && user.is_admin;

  let hasAccess = isOwner || isSiteAdmin || folderIsPublic;

  if (!hasAccess && user && pin.folder_id) {
    const share = await env.DB.prepare(
      'SELECT * FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
    ).bind(pin.folder_id, user.id).first();
    hasAccess = !!share;
  }

  if (!hasAccess && user && pin.folder_org_id) {
    hasAccess = await isOrgMember(env, user.id, pin.folder_org_id);
  }

  if (!hasAccess) return json({ error: 'アクセス権限がありません' }, 403);

  const comments = await env.DB.prepare(`
    SELECT c.*, u.display_name as author_name
    FROM pin_comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.pin_id = ?
    ORDER BY c.created_at DESC
  `).bind(pinId).all();

  return json(comments.results);
}

async function handleCreatePinComment(request, env, user, pinId) {
  const { content } = await getRequestBody(request);

  if (!content) {
    return json({ error: 'コメントを入力してください' }, 400);
  }
  if (content.length > 50) {
    return json({ error: 'コメントは50文字以内で入力してください' }, 400);
  }

  // Check if pin exists and user has access to view it
  const pin = await env.DB.prepare(`
    SELECT p.*, f.is_public as folder_is_public, f.organization_id as folder_org_id
    FROM pins p
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE p.id = ?
  `).bind(pinId).first();

  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);

  // Check access: owner, admin, public folder, shared folder, or org member
  const folderIsPublic = pin.folder_is_public === 1;
  const isOwner = pin.user_id === user.id;
  const isSiteAdmin = user.is_admin;

  let hasAccess = isOwner || isSiteAdmin || folderIsPublic;

  if (!hasAccess && pin.folder_id) {
    const share = await env.DB.prepare(
      'SELECT * FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
    ).bind(pin.folder_id, user.id).first();
    hasAccess = !!share;
  }

  if (!hasAccess && pin.folder_org_id) {
    hasAccess = await isOrgMember(env, user.id, pin.folder_org_id);
  }

  if (!hasAccess) return json({ error: 'アクセス権限がありません' }, 403);

  const result = await env.DB.prepare(
    'INSERT INTO pin_comments (pin_id, user_id, content) VALUES (?, ?, ?)'
  ).bind(pinId, user.id, content).run();

  const newComment = await env.DB.prepare(`
    SELECT c.*, u.display_name as author_name
    FROM pin_comments c
    JOIN users u ON c.user_id = u.id
    WHERE c.id = ?
  `).bind(result.meta.last_row_id).first();

  // Send push notification
  try {
    await sendPushNotifications(env, 'comment', {
      title: '新しいコメント',
      body: `${user.display_name || user.username}: ${content.substring(0, 30)}`,
      id: pinId,
      creatorId: user.id
    }, { id: pin.folder_id, is_public: folderIsPublic, type: 'pin' });
  } catch (e) {
    console.error('Push notification error:', e);
  }

  return json(newComment, 201);
}

async function handleDeletePinComment(env, user, pinId, commentId) {
  const comment = await env.DB.prepare(
    'SELECT * FROM pin_comments WHERE id = ? AND pin_id = ?'
  ).bind(commentId, pinId).first();

  if (!comment) return json({ error: 'コメントが見つかりません' }, 404);

  // Only comment author or admin can delete
  if (comment.user_id !== user.id && !user.is_admin) {
    return json({ error: '削除権限がありません' }, 403);
  }

  await env.DB.prepare('DELETE FROM pin_comments WHERE id = ?').bind(commentId).run();

  return json({ ok: true });
}

async function handleGetUnreadComments(env, user) {
  // Get user's last read time
  const readStatus = await env.DB.prepare(
    'SELECT last_read_at FROM comment_read_status WHERE user_id = ?'
  ).bind(user.id).first();

  const lastReadAt = readStatus?.last_read_at || '1970-01-01 00:00:00';

  // Get new comments on accessible pins
  const comments = await env.DB.prepare(`
    SELECT 'comment' as type, c.id, c.content, c.created_at,
           p.id as pin_id, p.title as pin_title, p.lat, p.lng,
           u.display_name as author_name, f.name as folder_name
    FROM pin_comments c
    JOIN pins p ON c.pin_id = p.id
    JOIN users u ON c.user_id = u.id
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE c.created_at > ?
      AND c.user_id != ?
      AND (
        f.is_public = 1
        OR f.user_id = ?
        OR EXISTS (
          SELECT 1 FROM folder_shares fs
          WHERE fs.folder_id = f.id AND fs.shared_with_user_id = ?
        )
      )
    ORDER BY c.created_at DESC
    LIMIT 20
  `).bind(lastReadAt, user.id, user.id, user.id).all();

  // Get new pins in accessible folders (not user's own)
  const pins = await env.DB.prepare(`
    SELECT 'pin' as type, p.id, p.title, p.description as content, p.created_at,
           p.id as pin_id, p.title as pin_title, p.lat, p.lng,
           u.display_name as author_name, f.name as folder_name
    FROM pins p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE p.created_at > ?
      AND p.user_id != ?
      AND (
        f.is_public = 1
        OR EXISTS (
          SELECT 1 FROM folder_shares fs
          WHERE fs.folder_id = f.id AND fs.shared_with_user_id = ?
        )
      )
    ORDER BY p.created_at DESC
    LIMIT 20
  `).bind(lastReadAt, user.id, user.id).all();

  // Get new KML files in accessible folders (not user's own)
  const kmlFiles = await env.DB.prepare(`
    SELECT 'kml' as type, k.id, k.original_name as title, '' as content, k.created_at,
           k.id as kml_id, k.original_name as kml_name,
           u.display_name as author_name, kf.name as folder_name
    FROM kml_files k
    JOIN users u ON k.user_id = u.id
    LEFT JOIN kml_folders kf ON k.folder_id = kf.id
    WHERE k.created_at > ?
      AND k.user_id != ?
      AND (
        kf.is_public = 1
        OR EXISTS (
          SELECT 1 FROM kml_folder_shares kfs
          WHERE kfs.kml_folder_id = kf.id AND kfs.shared_with_user_id = ?
        )
      )
    ORDER BY k.created_at DESC
    LIMIT 20
  `).bind(lastReadAt, user.id, user.id).all();

  // Get new pin folder shares (folders shared with this user)
  const folderShares = await env.DB.prepare(`
    SELECT 'folder_share' as type, fs.id, f.name as title, '' as content, fs.created_at,
           f.id as folder_id, f.name as folder_name,
           u.display_name as author_name
    FROM folder_shares fs
    JOIN folders f ON fs.folder_id = f.id
    JOIN users u ON f.user_id = u.id
    WHERE fs.created_at > ?
      AND fs.shared_with_user_id = ?
    ORDER BY fs.created_at DESC
    LIMIT 20
  `).bind(lastReadAt, user.id).all();

  // Get new KML folder shares (folders shared with this user)
  const kmlFolderShares = await env.DB.prepare(`
    SELECT 'kml_folder_share' as type, kfs.id, kf.name as title, '' as content, kfs.created_at,
           kf.id as kml_folder_id, kf.name as folder_name,
           u.display_name as author_name
    FROM kml_folder_shares kfs
    JOIN kml_folders kf ON kfs.kml_folder_id = kf.id
    JOIN users u ON kf.user_id = u.id
    WHERE kfs.created_at > ?
      AND kfs.shared_with_user_id = ?
    ORDER BY kfs.created_at DESC
    LIMIT 20
  `).bind(lastReadAt, user.id).all();

  // Combine and sort by created_at
  const all = [...comments.results, ...pins.results, ...kmlFiles.results, ...folderShares.results, ...kmlFolderShares.results];
  all.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  return json(all.slice(0, 50));
}

async function handleMarkCommentsRead(env, user) {
  // Upsert the read status
  await env.DB.prepare(`
    INSERT INTO comment_read_status (user_id, last_read_at)
    VALUES (?, datetime('now'))
    ON CONFLICT(user_id) DO UPDATE SET last_read_at = datetime('now')
  `).bind(user.id).run();

  return json({ ok: true });
}

// ==================== Push Notification Handlers ====================
function handleGetVapidKey(env) {
  const vapidPublicKey = env.VAPID_PUBLIC_KEY;
  if (!vapidPublicKey) {
    return json({ error: 'Push notifications not configured' }, 503);
  }
  return json({ vapidPublicKey });
}

async function handlePushSubscribe(request, env, user) {
  const { subscription } = await getRequestBody(request);

  if (!subscription || !subscription.endpoint || !subscription.keys) {
    return json({ error: 'Invalid subscription' }, 400);
  }

  // Delete any existing subscription with this endpoint
  await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ?')
    .bind(subscription.endpoint).run();

  // Insert new subscription
  await env.DB.prepare(
    'INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES (?, ?, ?, ?)'
  ).bind(user.id, subscription.endpoint, subscription.keys.p256dh, subscription.keys.auth).run();

  return json({ ok: true });
}

async function handlePushUnsubscribe(request, env, user) {
  const { endpoint } = await getRequestBody(request);

  if (!endpoint) {
    return json({ error: 'Endpoint required' }, 400);
  }

  await env.DB.prepare('DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?')
    .bind(endpoint, user.id).run();

  return json({ ok: true });
}

// Test push notification - sends directly to user's subscription with detailed debugging
async function handlePushTest(request, env, user) {
  const debug = { steps: [], timestamp: new Date().toISOString() };

  try {
    // Step 1: Check VAPID keys
    debug.steps.push('1. Checking VAPID keys');
    const vapidPublicKey = env.VAPID_PUBLIC_KEY;
    const vapidPrivateKey = env.VAPID_PRIVATE_KEY;

    if (!vapidPublicKey || !vapidPrivateKey) {
      return json({ error: 'VAPID keys not configured', hasPublic: !!vapidPublicKey, hasPrivate: !!vapidPrivateKey, debug }, 500);
    }
    debug.keyLengths = { public: vapidPublicKey.length, private: vapidPrivateKey.length };
    debug.steps.push('2. VAPID keys found: pub=' + vapidPublicKey.length + ', priv=' + vapidPrivateKey.length);

    // Step 2: Get subscription
    debug.steps.push('3. Getting subscription');
    const subscriptions = await env.DB.prepare(
      'SELECT * FROM push_subscriptions WHERE user_id = ?'
    ).bind(user.id).all();

    if (!subscriptions.results || subscriptions.results.length === 0) {
      return json({ error: 'No push subscription found for user', debug }, 400);
    }
    const sub = subscriptions.results[0];
    debug.steps.push('4. Subscription found');
    debug.subscription = { endpoint: sub.endpoint.substring(0, 60), p256dhLen: sub.p256dh?.length, authLen: sub.auth?.length };

    // Step 3: Decode keys
    debug.steps.push('5. Decoding keys');
    const urlBase64ToUint8Array = (base64String) => {
      const padding = '='.repeat((4 - base64String.length % 4) % 4);
      const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
      const rawData = atob(base64);
      return new Uint8Array([...rawData].map(c => c.charCodeAt(0)));
    };

    const uint8ArrayToUrlBase64 = (uint8Array) => {
      return btoa(String.fromCharCode(...uint8Array))
        .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    };

    const privateKeyBytes = urlBase64ToUint8Array(vapidPrivateKey);
    const publicKeyBytes = urlBase64ToUint8Array(vapidPublicKey);
    debug.decodedLengths = { private: privateKeyBytes.length, public: publicKeyBytes.length };
    debug.steps.push('6. Decoded: priv=' + privateKeyBytes.length + ' bytes, pub=' + publicKeyBytes.length + ' bytes');

    // Step 4: Create JWK
    debug.steps.push('7. Creating JWK');
    if (publicKeyBytes.length !== 65) {
      return json({ error: 'Invalid public key length (expected 65)', debug }, 500);
    }
    if (privateKeyBytes.length !== 32) {
      return json({ error: 'Invalid private key length (expected 32)', debug }, 500);
    }

    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: uint8ArrayToUrlBase64(publicKeyBytes.slice(1, 33)),
      y: uint8ArrayToUrlBase64(publicKeyBytes.slice(33, 65)),
      d: uint8ArrayToUrlBase64(privateKeyBytes)
    };
    debug.steps.push('8. JWK created');

    // Step 5: Import key
    debug.steps.push('9. Importing key to WebCrypto');
    const privateKey = await crypto.subtle.importKey(
      'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
    );
    debug.steps.push('10. Key imported successfully');

    // Step 6: Try signing
    debug.steps.push('11. Testing signature');
    const testData = new TextEncoder().encode('test');
    const testSig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, testData);
    debug.steps.push('12. Signature works, length=' + testSig.byteLength);

    // Step 7: Send actual push
    debug.steps.push('13. Calling sendWebPush');
    const payload = JSON.stringify({
      title: 'テスト通知',
      body: 'プッシュ通知のテストです',
      type: 'test'
    });

    await sendWebPush(env, {
      endpoint: sub.endpoint,
      keys: { p256dh: sub.p256dh, auth: sub.auth }
    }, payload);

    debug.steps.push('14. sendWebPush completed!');
    return json({ ok: true, message: 'Push sent successfully', debug });

  } catch (err) {
    console.error('Push notification error:', err);
    return json({ error: 'Push failed' }, 500);
  }
}

// Send push notification to users who have access to a folder
async function sendPushNotifications(env, type, data, folderInfo) {
  const vapidPublicKey = env.VAPID_PUBLIC_KEY;
  const vapidPrivateKey = env.VAPID_PRIVATE_KEY;

  if (!vapidPublicKey || !vapidPrivateKey) {
    console.log('VAPID keys not configured, skipping push notifications');
    return;
  }

  // Get users who should receive this notification
  let targetUserIds = [];

  if (folderInfo.is_public) {
    // Public folder - get all users with push subscriptions except the creator
    const users = await env.DB.prepare(
      'SELECT DISTINCT user_id FROM push_subscriptions WHERE user_id != ?'
    ).bind(data.creatorId).all();
    targetUserIds = users.results.map(u => u.user_id);
  } else if (folderInfo.id) {
    // Shared folder - get users who have been shared this folder
    // Use separate queries to avoid dynamic SQL construction
    let shares;
    if (folderInfo.type === 'kml') {
      shares = await env.DB.prepare(
        'SELECT shared_with_user_id FROM kml_folder_shares WHERE kml_folder_id = ?'
      ).bind(folderInfo.id).all();
    } else {
      shares = await env.DB.prepare(
        'SELECT shared_with_user_id FROM folder_shares WHERE folder_id = ?'
      ).bind(folderInfo.id).all();
    }
    targetUserIds = shares.results.map(s => s.shared_with_user_id);
  }

  if (targetUserIds.length === 0) return;

  // Get subscriptions for target users
  const placeholders = targetUserIds.map(() => '?').join(',');
  const subscriptions = await env.DB.prepare(
    `SELECT * FROM push_subscriptions WHERE user_id IN (${placeholders})`
  ).bind(...targetUserIds).all();

  // Build notification payload
  const payload = JSON.stringify({
    title: data.title,
    body: data.body,
    type: type,
    id: data.id,
    url: '/'
  });

  // Send to each subscription
  for (const sub of subscriptions.results) {
    try {
      await sendWebPush(env, {
        endpoint: sub.endpoint,
        keys: { p256dh: sub.p256dh, auth: sub.auth }
      }, payload);
    } catch (err) {
      console.error('Failed to send push:', err);
      // Remove invalid subscription
      if (err.status === 410 || err.status === 404) {
        await env.DB.prepare('DELETE FROM push_subscriptions WHERE id = ?').bind(sub.id).run();
      }
    }
  }
}

// Web Push implementation for Cloudflare Workers
async function sendWebPush(env, subscription, payload) {
  const vapidPublicKey = env.VAPID_PUBLIC_KEY;
  const vapidPrivateKey = env.VAPID_PRIVATE_KEY;

  // Helper functions
  const urlBase64ToUint8Array = (base64String) => {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
  };

  const uint8ArrayToUrlBase64 = (uint8Array) => {
    return btoa(String.fromCharCode(...uint8Array))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  };

  const endpoint = new URL(subscription.endpoint);
  const audience = `${endpoint.protocol}//${endpoint.host}`;

  // Create JWT for VAPID
  const header = { typ: 'JWT', alg: 'ES256' };
  const now = Math.floor(Date.now() / 1000);
  const jwtPayload = {
    aud: audience,
    exp: now + 86400,
    sub: 'mailto:noreply@example.com'
  };

  const headerB64 = uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(header)));
  const payloadB64 = uint8ArrayToUrlBase64(new TextEncoder().encode(JSON.stringify(jwtPayload)));
  const unsignedToken = `${headerB64}.${payloadB64}`;

  // Import private key as JWK (VAPID private key is raw 32-byte value)
  const privateKeyBytes = urlBase64ToUint8Array(vapidPrivateKey);
  const publicKeyBytes = urlBase64ToUint8Array(vapidPublicKey);

  // Create JWK from raw keys
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: uint8ArrayToUrlBase64(publicKeyBytes.slice(1, 33)),
    y: uint8ArrayToUrlBase64(publicKeyBytes.slice(33, 65)),
    d: uint8ArrayToUrlBase64(privateKeyBytes)
  };

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );

  // Sign the JWT
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    new TextEncoder().encode(unsignedToken)
  );

  // Convert signature to raw r||s format if needed
  const sigBytes = new Uint8Array(signature);
  let rawSignature;

  if (sigBytes.length === 64) {
    // Already in raw format (r || s, each 32 bytes)
    rawSignature = sigBytes;
  } else {
    // DER format - parse it
    let offset = 2; // Skip sequence tag and length
    const rLength = sigBytes[offset + 1];
    offset += 2;
    let r = sigBytes.slice(offset, offset + rLength);
    offset += rLength;
    const sLength = sigBytes[offset + 1];
    offset += 2;
    let s = sigBytes.slice(offset, offset + sLength);

    // Ensure r and s are 32 bytes each
    if (r.length > 32) r = r.slice(r.length - 32);
    if (s.length > 32) s = s.slice(s.length - 32);
    if (r.length < 32) r = new Uint8Array([...new Array(32 - r.length).fill(0), ...r]);
    if (s.length < 32) s = new Uint8Array([...new Array(32 - s.length).fill(0), ...s]);

    rawSignature = new Uint8Array([...r, ...s]);
  }

  const signatureB64 = uint8ArrayToUrlBase64(rawSignature);
  const jwt = `${unsignedToken}.${signatureB64}`;

  // Encrypt payload using aes128gcm
  const userPublicKey = urlBase64ToUint8Array(subscription.keys.p256dh);
  const userAuth = urlBase64ToUint8Array(subscription.keys.auth);

  // Generate local key pair for ECDH
  const localKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const localPublicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', localKeyPair.publicKey));

  // Import user's public key
  const userKey = await crypto.subtle.importKey(
    'raw',
    userPublicKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // Derive shared secret
  const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: userKey },
    localKeyPair.privateKey,
    256
  ));

  // HKDF to derive IKM
  const authInfo = new Uint8Array([
    ...new TextEncoder().encode('WebPush: info\0'),
    ...userPublicKey,
    ...localPublicKeyRaw
  ]);

  const prkKey = await crypto.subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveBits']);
  const ikm = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: userAuth, info: authInfo },
    prkKey,
    256
  ));

  // Generate salt
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Derive content encryption key and nonce
  const ikmKey = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);

  const cekInfo = new TextEncoder().encode('Content-Encoding: aes128gcm\0');
  const contentEncryptionKey = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt, info: cekInfo },
    ikmKey,
    128
  ));

  const nonceInfo = new TextEncoder().encode('Content-Encoding: nonce\0');
  const nonce = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: salt, info: nonceInfo },
    ikmKey,
    96
  ));

  // Encrypt payload with padding
  const aesKey = await crypto.subtle.importKey(
    'raw',
    contentEncryptionKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Add padding delimiter (0x02) to payload
  const payloadBytes = new TextEncoder().encode(payload);
  const paddedPayload = new Uint8Array([...payloadBytes, 2]);

  const encrypted = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    paddedPayload
  ));

  // Build aes128gcm body: salt (16) + rs (4) + idlen (1) + keyid (65) + encrypted
  const rs = 4096;
  const body = new Uint8Array([
    ...salt,
    (rs >> 24) & 0xff, (rs >> 16) & 0xff, (rs >> 8) & 0xff, rs & 0xff,
    65,
    ...localPublicKeyRaw,
    ...encrypted
  ]);

  // Send push
  const response = await fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `vapid t=${jwt}, k=${vapidPublicKey}`,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400'
    },
    body: body
  });

  if (!response.ok) {
    const errorText = await response.text();
    console.error('Push failed:', response.status, errorText);
    const error = new Error(`Push failed: ${response.status}`);
    error.status = response.status;
    throw error;
  }
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

// ==================== Passkeys (WebAuthn) Handlers ====================

// Generate registration options for passkey
async function handlePasskeyRegisterOptions(request, env, user) {
  const rpId = getRelyingPartyId(request);
  const challenge = generateWebAuthnChallenge();

  // Store challenge in database with 5-minute expiration
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB.prepare(
    'INSERT INTO passkey_challenges (challenge, user_id, type, expires_at) VALUES (?, ?, ?, ?)'
  ).bind(challenge, user.id, 'register', expiresAt).run();

  // Clean up expired challenges
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at < datetime("now")').run();

  // Get existing passkeys for excludeCredentials
  const existingPasskeys = await env.DB.prepare(
    'SELECT credential_id FROM passkeys WHERE user_id = ?'
  ).bind(user.id).all();

  const options = {
    challenge,
    rp: {
      name: 'Fieldnota Commons',
      id: rpId
    },
    user: {
      id: base64urlEncode(new TextEncoder().encode(String(user.id))),
      name: user.username,
      displayName: user.display_name || user.username
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256
      { alg: -257, type: 'public-key' }  // RS256
    ],
    timeout: 300000,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      userVerification: 'preferred'
    },
    attestation: 'none',
    excludeCredentials: existingPasskeys.results.map(pk => ({
      id: pk.credential_id,
      type: 'public-key'
    }))
  };

  return json(options);
}

// Verify passkey registration
async function handlePasskeyRegisterVerify(request, env, user) {
  const { credential, deviceName } = await getRequestBody(request);

  if (!credential || !credential.id || !credential.response) {
    return json({ error: '無効なクレデンシャルです' }, 400);
  }

  // Verify challenge
  const storedChallenge = await env.DB.prepare(
    'SELECT * FROM passkey_challenges WHERE user_id = ? AND type = ? AND expires_at > datetime("now") ORDER BY created_at DESC LIMIT 1'
  ).bind(user.id, 'register').first();

  if (!storedChallenge) {
    return json({ error: 'チャレンジが見つからないか期限切れです' }, 400);
  }

  // Delete used challenge
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE id = ?').bind(storedChallenge.id).run();

  // Decode client data and verify
  const clientDataJSON = base64urlDecode(credential.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));

  if (clientData.type !== 'webauthn.create') {
    return json({ error: '無効なクレデンシャルタイプです' }, 400);
  }

  if (clientData.challenge !== storedChallenge.challenge) {
    return json({ error: 'チャレンジが一致しません' }, 400);
  }

  // Parse attestation object
  const attestationObject = base64urlDecode(credential.response.attestationObject);
  const attestation = parseAttestationObject(attestationObject);
  const authData = parseAuthenticatorData(attestation.authData);

  if (!authData.userPresent) {
    return json({ error: 'ユーザー確認が必要です' }, 400);
  }

  if (!authData.credentialId || !authData.publicKey) {
    return json({ error: '公開鍵の取得に失敗しました' }, 400);
  }

  // Encode credential ID and public key for storage
  const credentialId = base64urlEncode(authData.credentialId);

  // Re-encode public key as CBOR for storage
  const publicKeyBytes = attestation.authData.slice(55 + authData.credentialId.length);
  const publicKeyBase64 = base64urlEncode(publicKeyBytes);

  // Check if credential already exists
  const existing = await env.DB.prepare(
    'SELECT id FROM passkeys WHERE credential_id = ?'
  ).bind(credentialId).first();

  if (existing) {
    return json({ error: 'このパスキーは既に登録されています' }, 400);
  }

  // Store passkey
  await env.DB.prepare(
    'INSERT INTO passkeys (user_id, credential_id, public_key, counter, device_name) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.id, credentialId, publicKeyBase64, authData.signCount, deviceName || 'Unknown Device').run();

  await logSecurityEvent(env, 'passkey_registered', user.id, request, { deviceName });

  return json({ ok: true, message: 'パスキーを登録しました' });
}

// Generate login options for passkey
async function handlePasskeyLoginOptions(request, env) {
  const rpId = getRelyingPartyId(request);
  const challenge = generateWebAuthnChallenge();

  // Store challenge with 5-minute expiration
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
  await env.DB.prepare(
    'INSERT INTO passkey_challenges (challenge, type, expires_at) VALUES (?, ?, ?)'
  ).bind(challenge, 'login', expiresAt).run();

  // Clean up expired challenges
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE expires_at < datetime("now")').run();

  const options = {
    challenge,
    rpId,
    timeout: 300000,
    userVerification: 'preferred',
    allowCredentials: [] // Empty to allow any registered passkey
  };

  return json(options);
}

// Verify passkey login
async function handlePasskeyLoginVerify(request, env) {
  const { credential } = await getRequestBody(request);

  if (!credential || !credential.id || !credential.response) {
    return json({ error: '無効なクレデンシャルです' }, 400);
  }

  const credentialId = credential.id;

  // Find passkey
  const passkey = await env.DB.prepare(
    'SELECT p.*, u.id as uid, u.username, u.display_name, u.is_admin, u.status FROM passkeys p JOIN users u ON p.user_id = u.id WHERE p.credential_id = ?'
  ).bind(credentialId).first();

  if (!passkey) {
    return json({ error: 'パスキーが見つかりません' }, 401);
  }

  // Check user status (valid statuses: 'approved', 'pending', 'rejected', 'needs_password')
  if (passkey.status !== 'approved') {
    return json({ error: 'アカウントが無効です' }, 403);
  }

  // Decode client data
  const clientDataJSON = base64urlDecode(credential.response.clientDataJSON);
  const clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));

  if (clientData.type !== 'webauthn.get') {
    return json({ error: '無効なクレデンシャルタイプです' }, 400);
  }

  // Verify challenge exists
  const storedChallenge = await env.DB.prepare(
    'SELECT * FROM passkey_challenges WHERE challenge = ? AND type = ? AND expires_at > datetime("now")'
  ).bind(clientData.challenge, 'login').first();

  if (!storedChallenge) {
    return json({ error: 'チャレンジが見つからないか期限切れです' }, 400);
  }

  // Delete used challenge
  await env.DB.prepare('DELETE FROM passkey_challenges WHERE id = ?').bind(storedChallenge.id).run();

  // Decode authenticator data and signature
  const authData = base64urlDecode(credential.response.authenticatorData);
  const signature = base64urlDecode(credential.response.signature);

  // Verify signature
  try {
    const isValid = await verifyWebAuthnSignature(
      authData,
      clientDataJSON,
      signature,
      passkey.public_key
    );

    if (!isValid) {
      await logSecurityEvent(env, 'passkey_login_failed', passkey.uid, request, { reason: 'invalid_signature' });
      return json({ error: '署名の検証に失敗しました' }, 401);
    }
  } catch (err) {
    console.error('Signature verification error:', err);
    await logSecurityEvent(env, 'passkey_login_failed', passkey.uid, request, { reason: 'signature_verification_failed' });
    return json({ error: '署名の検証に失敗しました' }, 401);
  }

  // Parse authenticator data to get sign count
  const parsedAuthData = parseAuthenticatorData(authData);

  // Verify counter to prevent replay attacks
  if (parsedAuthData.signCount > 0 && parsedAuthData.signCount <= passkey.counter) {
    await logSecurityEvent(env, 'passkey_replay_attack', passkey.uid, request, {
      expected: passkey.counter + 1,
      received: parsedAuthData.signCount
    });
    return json({ error: 'リプレイ攻撃の可能性が検出されました' }, 401);
  }

  // Update counter
  await env.DB.prepare(
    'UPDATE passkeys SET counter = ? WHERE id = ?'
  ).bind(parsedAuthData.signCount, passkey.id).run();

  // Create session for token invalidation support
  const sessionToken = await createSession(env, passkey.uid, request);

  // Generate JWT token with session
  const token = await createToken({
    id: passkey.uid,
    username: passkey.username,
    display_name: passkey.display_name || passkey.username,
    is_admin: !!passkey.is_admin,
    sid: sessionToken
  }, env.JWT_SECRET);

  await logSecurityEvent(env, 'passkey_login_success', passkey.uid, request, {});

  return json(
    {
      id: passkey.uid,
      username: passkey.username,
      display_name: passkey.display_name,
      is_admin: !!passkey.is_admin
    },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

// Get user's passkeys
async function handleGetPasskeys(env, user) {
  const passkeys = await env.DB.prepare(
    'SELECT id, device_name, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC'
  ).bind(user.id).all();

  return json(passkeys.results);
}

// Delete a passkey
async function handleDeletePasskey(env, user, passkeyId) {
  if (!passkeyId || isNaN(passkeyId)) {
    return json({ error: '無効なパスキーIDです' }, 400);
  }

  // Verify ownership
  const passkey = await env.DB.prepare(
    'SELECT id FROM passkeys WHERE id = ? AND user_id = ?'
  ).bind(passkeyId, user.id).first();

  if (!passkey) {
    return json({ error: 'パスキーが見つかりません' }, 404);
  }

  await env.DB.prepare('DELETE FROM passkeys WHERE id = ?').bind(passkeyId).run();

  return json({ ok: true, message: 'パスキーを削除しました' });
}

// ==================== Organization Handlers ====================

async function handleGetOrganizations(env, user) {
  const orgs = await env.DB.prepare(`
    SELECT o.*, om.role,
      (SELECT COUNT(*) FROM organization_members WHERE organization_id = o.id) as member_count
    FROM organizations o
    JOIN organization_members om ON o.id = om.organization_id AND om.user_id = ?
    ORDER BY o.name
  `).bind(user.id).all();
  return json(orgs.results);
}

async function handleCreateOrganization(request, env, user) {
  const { name } = await getRequestBody(request);
  if (!name || !name.trim()) return json({ error: '団体名を入力してください' }, 400);
  if (name.length > 100) return json({ error: '団体名は100文字以内にしてください' }, 400);

  const result = await env.DB.prepare(
    'INSERT INTO organizations (name, created_by) VALUES (?, ?)'
  ).bind(name.trim(), user.id).run();

  const orgId = result.meta.last_row_id;

  // Creator becomes admin
  await env.DB.prepare(
    'INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)'
  ).bind(orgId, user.id, 'admin').run();

  return json({ id: orgId, name: name.trim(), role: 'admin', member_count: 1 });
}

async function handleUpdateOrganization(request, env, user, id) {
  if (!await isOrgAdmin(env, user.id, parseInt(id)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  const { name } = await getRequestBody(request);
  if (!name || !name.trim()) return json({ error: '団体名を入力してください' }, 400);
  if (name.length > 100) return json({ error: '団体名は100文字以内にしてください' }, 400);

  await env.DB.prepare('UPDATE organizations SET name = ? WHERE id = ?')
    .bind(name.trim(), id).run();
  return json({ ok: true });
}

async function handleDeleteOrganization(env, user, id) {
  const org = await env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(id).first();
  if (!org) return json({ error: '団体が見つかりません' }, 404);

  if (!await isOrgAdmin(env, user.id, parseInt(id)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  // Delete org folders' contents first
  // KML files in org kml_folders
  const orgKmlFolders = await env.DB.prepare('SELECT id FROM kml_folders WHERE organization_id = ?').bind(id).all();
  for (const f of orgKmlFolders.results) {
    const files = await env.DB.prepare('SELECT r2_key FROM kml_files WHERE folder_id = ?').bind(f.id).all();
    for (const file of files.results) {
      try { await env.R2.delete(file.r2_key); } catch (e) { /* ignore */ }
    }
    await env.DB.prepare('DELETE FROM kml_files WHERE folder_id = ?').bind(f.id).run();
  }

  // Pin images in org folders
  const orgFolders = await env.DB.prepare('SELECT id FROM folders WHERE organization_id = ?').bind(id).all();
  for (const f of orgFolders.results) {
    const pins = await env.DB.prepare('SELECT id FROM pins WHERE folder_id = ?').bind(f.id).all();
    for (const pin of pins.results) {
      const images = await env.DB.prepare('SELECT r2_key FROM pin_images WHERE pin_id = ?').bind(pin.id).all();
      for (const img of images.results) {
        try { await env.R2.delete(img.r2_key); } catch (e) { /* ignore */ }
      }
    }
    await env.DB.prepare('DELETE FROM pins WHERE folder_id = ?').bind(f.id).run();
  }

  // Delete org data
  await env.DB.batch([
    env.DB.prepare('DELETE FROM kml_folder_shares WHERE kml_folder_id IN (SELECT id FROM kml_folders WHERE organization_id = ?)').bind(id),
    env.DB.prepare('DELETE FROM kml_folder_visibility WHERE kml_folder_id IN (SELECT id FROM kml_folders WHERE organization_id = ?)').bind(id),
    env.DB.prepare('DELETE FROM kml_folders WHERE organization_id = ?').bind(id),
    env.DB.prepare('DELETE FROM folder_shares WHERE folder_id IN (SELECT id FROM folders WHERE organization_id = ?)').bind(id),
    env.DB.prepare('DELETE FROM folder_visibility WHERE folder_id IN (SELECT id FROM folders WHERE organization_id = ?)').bind(id),
    env.DB.prepare('DELETE FROM folders WHERE organization_id = ?').bind(id),
    env.DB.prepare('DELETE FROM organization_invitations WHERE organization_id = ?').bind(id),
    env.DB.prepare('DELETE FROM organization_members WHERE organization_id = ?').bind(id),
    env.DB.prepare('DELETE FROM organizations WHERE id = ?').bind(id),
  ]);

  return json({ ok: true });
}

async function handleGetOrgMembers(env, user, orgId) {
  if (!await isOrgMember(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const members = await env.DB.prepare(`
    SELECT om.user_id, om.role, om.created_at, u.username, u.display_name, u.email
    FROM organization_members om
    JOIN users u ON om.user_id = u.id
    WHERE om.organization_id = ?
    ORDER BY om.role DESC, u.display_name
  `).bind(orgId).all();

  return json(members.results);
}

async function handleRemoveOrgMember(env, user, orgId, memberId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  // Cannot remove yourself
  if (parseInt(memberId) === user.id) {
    return json({ error: '自分自身は削除できません' }, 400);
  }

  const member = await env.DB.prepare(
    'SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).bind(orgId, memberId).first();
  if (!member) return json({ error: 'メンバーが見つかりません' }, 404);

  await env.DB.prepare(
    'DELETE FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).bind(orgId, memberId).run();

  return json({ ok: true });
}

async function handleChangeOrgMemberRole(request, env, user, orgId, memberId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  const { role } = await getRequestBody(request);
  if (!['admin', 'member'].includes(role)) {
    return json({ error: '無効なロールです' }, 400);
  }

  const member = await env.DB.prepare(
    'SELECT * FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).bind(orgId, memberId).first();
  if (!member) return json({ error: 'メンバーが見つかりません' }, 404);

  // If demoting an admin to member, ensure at least one other admin remains
  if (member.role === 'admin' && role === 'member') {
    const adminCount = await env.DB.prepare(
      'SELECT COUNT(*) as cnt FROM organization_members WHERE organization_id = ? AND role = ?'
    ).bind(orgId, 'admin').first();
    if (adminCount.cnt <= 1) {
      return json({ error: '管理者が1人のため降格できません。先に他のメンバーを管理者にしてください。' }, 400);
    }
  }

  await env.DB.prepare(
    'UPDATE organization_members SET role = ? WHERE organization_id = ? AND user_id = ?'
  ).bind(role, orgId, memberId).run();

  return json({ ok: true });
}

async function handleGetOrgInvitations(env, user, orgId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  // Clean up expired invitations
  await env.DB.prepare(
    "DELETE FROM organization_invitations WHERE expires_at < datetime('now')"
  ).run();

  const invitations = await env.DB.prepare(`
    SELECT oi.id, oi.email, oi.expires_at, oi.created_at, u.display_name as invited_by_name
    FROM organization_invitations oi
    JOIN users u ON oi.invited_by = u.id
    WHERE oi.organization_id = ?
    ORDER BY oi.created_at DESC
  `).bind(orgId).all();

  return json(invitations.results);
}

async function handleInviteToOrg(request, env, user, orgId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  const org = await env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first();
  if (!org) return json({ error: '団体が見つかりません' }, 404);

  const { email } = await getRequestBody(request);
  if (!email || !email.trim()) return json({ error: 'メールアドレスを入力してください' }, 400);

  const normalizedEmail = email.trim().toLowerCase();

  // Check if user is already a member
  const existingUser = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(normalizedEmail).first();
  if (existingUser) {
    const existingMember = await env.DB.prepare(
      'SELECT 1 FROM organization_members WHERE organization_id = ? AND user_id = ?'
    ).bind(orgId, existingUser.id).first();
    if (existingMember) {
      return json({ error: 'このユーザーは既にメンバーです' }, 400);
    }
  }

  // Check if invitation already exists
  const existingInvite = await env.DB.prepare(
    "SELECT 1 FROM organization_invitations WHERE organization_id = ? AND email = ? AND expires_at > datetime('now')"
  ).bind(orgId, normalizedEmail).first();
  if (existingInvite) {
    return json({ error: 'このメールアドレスには既に招待を送信済みです' }, 400);
  }

  // Create invitation token
  const token = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(); // 7 days

  await env.DB.prepare(
    'INSERT INTO organization_invitations (organization_id, email, token, invited_by, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(orgId, normalizedEmail, token, user.id, expiresAt).run();

  // Send invitation email
  const inviterName = user.display_name || user.username;
  await sendOrgInvitationEmail(env, normalizedEmail, org.name, inviterName, token);

  return json({ ok: true, message: '招待メールを送信しました' });
}

async function handleCancelOrgInvitation(env, user, invitationId) {
  const invitation = await env.DB.prepare(
    'SELECT * FROM organization_invitations WHERE id = ?'
  ).bind(invitationId).first();
  if (!invitation) return json({ error: '招待が見つかりません' }, 404);

  if (!await isOrgAdmin(env, user.id, invitation.organization_id) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  await env.DB.prepare('DELETE FROM organization_invitations WHERE id = ?').bind(invitationId).run();
  return json({ ok: true });
}

async function handleAcceptOrgInvitation(request, env, user) {
  const { token } = await getRequestBody(request);
  if (!token) return json({ error: '招待トークンが必要です' }, 400);

  const invitation = await env.DB.prepare(
    "SELECT * FROM organization_invitations WHERE token = ? AND expires_at > datetime('now')"
  ).bind(token).first();

  if (!invitation) {
    return json({ error: '招待が見つからないか、有効期限が切れています' }, 404);
  }

  // Check if already a member
  const existingMember = await env.DB.prepare(
    'SELECT 1 FROM organization_members WHERE organization_id = ? AND user_id = ?'
  ).bind(invitation.organization_id, user.id).first();

  if (existingMember) {
    // Already a member, just delete the invitation
    await env.DB.prepare('DELETE FROM organization_invitations WHERE id = ?').bind(invitation.id).run();
    return json({ ok: true, message: '既にメンバーです' });
  }

  // Add as member
  await env.DB.prepare(
    'INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)'
  ).bind(invitation.organization_id, user.id, 'member').run();

  // Delete invitation
  await env.DB.prepare('DELETE FROM organization_invitations WHERE id = ?').bind(invitation.id).run();

  const org = await env.DB.prepare('SELECT name FROM organizations WHERE id = ?').bind(invitation.organization_id).first();

  return json({ ok: true, organization_name: org?.name, message: `${org?.name || '団体'} に参加しました` });
}

// Organization folder creation
async function handleCreateOrgFolder(request, env, user, orgId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  const org = await env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first();
  if (!org) return json({ error: '団体が見つかりません' }, 404);

  const { name, parent_id } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM folders WHERE id = ? AND organization_id = ?')
      .bind(parent_id, orgId).first();
    if (!parent) return json({ error: '親フォルダが見つかりません' }, 404);
  }

  const result = await env.DB.prepare(
    'INSERT INTO folders (name, parent_id, user_id, organization_id, is_public) VALUES (?, ?, ?, ?, 0)'
  ).bind(name, parent_id || null, user.id, orgId).run();

  return json({ id: result.meta.last_row_id, name, parent_id: parent_id || null, user_id: user.id, organization_id: parseInt(orgId) });
}

async function handleCreateOrgKmlFolder(request, env, user, orgId) {
  if (!await isOrgAdmin(env, user.id, parseInt(orgId)) && !user.is_admin) {
    return json({ error: '団体管理者権限が必要です' }, 403);
  }

  const org = await env.DB.prepare('SELECT * FROM organizations WHERE id = ?').bind(orgId).first();
  if (!org) return json({ error: '団体が見つかりません' }, 404);

  const { name, parent_id } = await getRequestBody(request);
  if (!name) return json({ error: 'フォルダ名を入力してください' }, 400);

  if (parent_id) {
    const parent = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ? AND organization_id = ?')
      .bind(parent_id, orgId).first();
    if (!parent) return json({ error: '親フォルダが見つかりません' }, 404);
  }

  const result = await env.DB.prepare(
    'INSERT INTO kml_folders (name, user_id, organization_id, parent_id, is_public) VALUES (?, ?, ?, ?, 0)'
  ).bind(name, user.id, orgId, parent_id || null).run();

  return json({ id: result.meta.last_row_id, name, user_id: user.id, organization_id: parseInt(orgId), parent_id: parent_id || null });
}
