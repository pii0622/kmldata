// Cloudflare Pages Functions - No external dependencies

// ==================== Utility Functions ====================

// PBKDF2 configuration
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_LENGTH = 32; // 256 bits

// Hash password with PBKDF2 and random salt
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const hashBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    PBKDF2_KEY_LENGTH * 8
  );
  const hashBase64 = btoa(String.fromCharCode(...new Uint8Array(hashBits)));
  const saltBase64 = btoa(String.fromCharCode(...salt));
  return { hash: hashBase64, salt: saltBase64 };
}

// Verify password - supports both PBKDF2 (with salt) and legacy SHA-256 (without salt)
async function verifyPassword(password, storedHash, salt) {
  const encoder = new TextEncoder();

  if (!salt) {
    // Legacy: SHA-256 without salt (for existing users)
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const computed = btoa(String.fromCharCode(...new Uint8Array(hash)));
    return computed === storedHash;
  }

  // PBKDF2 with salt
  const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const hashBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    keyMaterial,
    PBKDF2_KEY_LENGTH * 8
  );
  const computed = btoa(String.fromCharCode(...new Uint8Array(hashBits)));
  return computed === storedHash;
}

// Base64URL encoding (RFC 4648) - URL-safe, no padding
function base64urlEncode(data) {
  // data can be Uint8Array or string (UTF-8)
  const bytes = typeof data === 'string'
    ? new TextEncoder().encode(data)
    : data;
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
  // Restore standard Base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function base64urlDecodeToString(str) {
  const bytes = base64urlDecode(str);
  return new TextDecoder().decode(bytes);
}

async function createToken(payload, secret) {
  const encoder = new TextEncoder();
  // Encode header and payload as Base64URL (UTF-8 safe)
  const header = base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payloadStr = base64urlEncode(JSON.stringify({ ...payload, exp: Date.now() + 7 * 24 * 60 * 60 * 1000 }));
  const data = encoder.encode(`${header}.${payloadStr}`);
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const signature = base64urlEncode(new Uint8Array(sig));
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
    const sigBytes = base64urlDecode(signature);
    // crypto.subtle.verify is timing-safe
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;
    const parsed = JSON.parse(base64urlDecodeToString(payload));
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

// ==================== WebAuthn/Passkeys Utilities ====================

// Base64URL encode/decode (WebAuthn uses Base64URL, not standard Base64)
function base64urlEncode(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Generate random challenge for WebAuthn
function generateWebAuthnChallenge() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  return base64urlEncode(challenge);
}

// Simple CBOR decoder for WebAuthn public key parsing
function decodeCBOR(data) {
  let offset = 0;

  function readByte() {
    return data[offset++];
  }

  function readBytes(n) {
    const bytes = data.slice(offset, offset + n);
    offset += n;
    return bytes;
  }

  function readUint(n) {
    let value = 0;
    for (let i = 0; i < n; i++) {
      value = (value << 8) | data[offset++];
    }
    return value;
  }

  function decode() {
    const initial = readByte();
    const majorType = initial >> 5;
    const additionalInfo = initial & 0x1f;

    let value;
    if (additionalInfo < 24) {
      value = additionalInfo;
    } else if (additionalInfo === 24) {
      value = readByte();
    } else if (additionalInfo === 25) {
      value = readUint(2);
    } else if (additionalInfo === 26) {
      value = readUint(4);
    } else if (additionalInfo === 27) {
      value = Number(readUint(8));
    }

    switch (majorType) {
      case 0: // unsigned integer
        return value;
      case 1: // negative integer
        return -1 - value;
      case 2: // byte string
        return readBytes(value);
      case 3: // text string
        return new TextDecoder().decode(readBytes(value));
      case 4: // array
        const arr = [];
        for (let i = 0; i < value; i++) arr.push(decode());
        return arr;
      case 5: // map
        const map = {};
        for (let i = 0; i < value; i++) {
          const key = decode();
          map[key] = decode();
        }
        return map;
      case 6: // tagged value
        return decode();
      case 7: // simple/float
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        return undefined;
      default:
        throw new Error('Unknown CBOR type');
    }
  }

  return decode();
}

// Parse attestation object from WebAuthn registration
function parseAttestationObject(attestationObject) {
  const decoded = decodeCBOR(attestationObject);
  return {
    fmt: decoded.fmt,
    authData: decoded.authData,
    attStmt: decoded.attStmt
  };
}

// Parse authenticator data
function parseAuthenticatorData(authData) {
  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

  const userPresent = !!(flags & 0x01);
  const userVerified = !!(flags & 0x04);
  const attestedCredentialData = !!(flags & 0x40);

  let credentialId = null;
  let publicKey = null;

  if (attestedCredentialData) {
    const aaguid = authData.slice(37, 53);
    const credIdLen = (authData[53] << 8) | authData[54];
    credentialId = authData.slice(55, 55 + credIdLen);
    const publicKeyData = authData.slice(55 + credIdLen);
    publicKey = decodeCBOR(publicKeyData);
  }

  return {
    rpIdHash,
    flags,
    signCount,
    userPresent,
    userVerified,
    credentialId,
    publicKey
  };
}

// Convert COSE key to CryptoKey for verification
async function coseKeyToCryptoKey(coseKey) {
  // COSE key type 2 = EC2
  // COSE algorithm -7 = ES256 (ECDSA with P-256 and SHA-256)
  const kty = coseKey[1];
  const alg = coseKey[3];

  if (kty !== 2 || alg !== -7) {
    throw new Error('Unsupported key type or algorithm');
  }

  const crv = coseKey[-1]; // 1 = P-256
  const x = coseKey[-2];
  const y = coseKey[-3];

  if (crv !== 1) {
    throw new Error('Unsupported curve');
  }

  // Create JWK
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64urlEncode(x),
    y: base64urlEncode(y)
  };

  return await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
}

// Verify WebAuthn assertion signature
async function verifyWebAuthnSignature(authData, clientDataJSON, signature, publicKeyBase64) {
  // Decode stored public key
  const publicKeyData = base64urlDecode(publicKeyBase64);
  const coseKey = decodeCBOR(publicKeyData);
  const cryptoKey = await coseKeyToCryptoKey(coseKey);

  // Create signed data: authData + SHA-256(clientDataJSON)
  const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);
  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(new Uint8Array(clientDataHash), authData.length);

  // Convert signature from DER to raw format for Web Crypto
  const rawSignature = derToRaw(signature);

  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKey,
    rawSignature,
    signedData
  );
}

// Convert DER signature to raw format (r || s)
function derToRaw(der) {
  // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  let offset = 2; // Skip 0x30 and total length

  // Read r
  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature');
  let rLen = der[offset++];
  let r = der.slice(offset, offset + rLen);
  offset += rLen;

  // Read s
  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature');
  let sLen = der[offset++];
  let s = der.slice(offset, offset + sLen);

  // Remove leading zeros and pad to 32 bytes
  while (r.length > 32 && r[0] === 0) r = r.slice(1);
  while (s.length > 32 && s[0] === 0) s = s.slice(1);
  while (r.length < 32) r = new Uint8Array([0, ...r]);
  while (s.length < 32) s = new Uint8Array([0, ...s]);

  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

// Get RP ID from request URL
function getRelyingPartyId(request) {
  const url = new URL(request.url);
  return url.hostname;
}

// Security headers
const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-XSS-Protection': '1; mode=block',
  'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()'
};

// Content Security Policy for HTML responses
// Note: 'unsafe-inline' removed from script-src (inline scripts moved to external files)
// style-src still allows 'unsafe-inline' for inline style attributes
const cspHeader = "default-src 'self'; script-src 'self' https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://unpkg.com https://cdnjs.cloudflare.com; img-src 'self' https://cyberjapandata.gsi.go.jp data: blob:; connect-src 'self' https://cyberjapandata.gsi.go.jp; font-src 'self' https://cdnjs.cloudflare.com;";

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...securityHeaders, ...headers }
  });
}

// Rate limiting configuration
const RATE_LIMITS = {
  login: { maxRequests: 10, windowSeconds: 300 },         // 10 attempts per 5 minutes
  register: { maxRequests: 5, windowSeconds: 3600 },      // 5 attempts per hour
  passwordChange: { maxRequests: 5, windowSeconds: 300 }, // 5 attempts per 5 minutes
  passwordSetup: { maxRequests: 3, windowSeconds: 3600 }, // 3 attempts per hour
  passkey: { maxRequests: 5, windowSeconds: 300 },        // 5 attempts per 5 minutes
  admin: { maxRequests: 30, windowSeconds: 60 },          // 30 requests per minute
  default: { maxRequests: 100, windowSeconds: 60 }        // 100 requests per minute
};

// Free tier limits (premium users have no limits)
const FREE_TIER_LIMITS = {
  kmlFolders: 2,      // Max KML folders
  pinFolders: 2,      // Max pin folders
  kmlFiles: 1,        // Max KML files
  pins: 20,           // Max pins
  shares: 1           // Max folder shares (given + received, excluding admin shares)
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

// Free tier limit checking functions
// These exclude content in admin's public/shared folders from user's quota

async function isUserFreeTier(user) {
  // Admin and premium users have no limits
  return !user.is_admin && user.plan !== 'premium';
}

async function getUserKmlFolderCount(env, userId) {
  // Count only user's own KML folders
  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM kml_folders WHERE user_id = ?'
  ).bind(userId).first();
  return result.count;
}

async function getUserPinFolderCount(env, userId) {
  // Count only user's own pin folders
  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM folders WHERE user_id = ?'
  ).bind(userId).first();
  return result.count;
}

async function getUserKmlFileCount(env, userId) {
  // Count user's KML files, excluding those in admin's public/shared folders
  const result = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM kml_files kf
    WHERE kf.user_id = ?
      AND NOT EXISTS (
        SELECT 1 FROM kml_folders f
        JOIN users u ON f.user_id = u.id
        WHERE f.id = kf.folder_id
          AND u.is_admin = 1
          AND (f.is_public = 1 OR EXISTS (
            SELECT 1 FROM kml_folder_shares kfs WHERE kfs.kml_folder_id = f.id AND kfs.shared_with_user_id = ?
          ))
      )
  `).bind(userId, userId).first();
  return result.count;
}

async function getUserPinCount(env, userId) {
  // Count user's pins, excluding those in admin's public/shared folders
  const result = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM pins p
    WHERE p.user_id = ?
      AND NOT EXISTS (
        SELECT 1 FROM folders f
        JOIN users u ON f.user_id = u.id
        WHERE f.id = p.folder_id
          AND u.is_admin = 1
          AND (f.is_public = 1 OR EXISTS (
            SELECT 1 FROM folder_shares fs WHERE fs.folder_id = f.id AND fs.shared_with_user_id = ?
          ))
      )
  `).bind(userId, userId).first();
  return result.count;
}

async function getUserShareCount(env, userId) {
  // Count shares given and received by user, excluding admin's shares
  // Given: user's folders shared with others
  const givenKml = await env.DB.prepare(`
    SELECT COUNT(DISTINCT kfs.kml_folder_id) as count FROM kml_folder_shares kfs
    JOIN kml_folders kf ON kfs.kml_folder_id = kf.id
    WHERE kf.user_id = ?
  `).bind(userId).first();

  const givenPin = await env.DB.prepare(`
    SELECT COUNT(DISTINCT fs.folder_id) as count FROM folder_shares fs
    JOIN folders f ON fs.folder_id = f.id
    WHERE f.user_id = ?
  `).bind(userId).first();

  // Received: folders shared with user (excluding admin's folders)
  const receivedKml = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM kml_folder_shares kfs
    JOIN kml_folders kf ON kfs.kml_folder_id = kf.id
    JOIN users u ON kf.user_id = u.id
    WHERE kfs.shared_with_user_id = ? AND u.is_admin = 0
  `).bind(userId).first();

  const receivedPin = await env.DB.prepare(`
    SELECT COUNT(*) as count FROM folder_shares fs
    JOIN folders f ON fs.folder_id = f.id
    JOIN users u ON f.user_id = u.id
    WHERE fs.shared_with_user_id = ? AND u.is_admin = 0
  `).bind(userId).first();

  return givenKml.count + givenPin.count + receivedKml.count + receivedPin.count;
}

async function checkFreeTierLimit(env, user, limitType) {
  if (!await isUserFreeTier(user)) {
    return { allowed: true };
  }

  let currentCount, maxLimit, message;

  switch (limitType) {
    case 'kmlFolder':
      currentCount = await getUserKmlFolderCount(env, user.id);
      maxLimit = FREE_TIER_LIMITS.kmlFolders;
      message = `無料プランではKMLフォルダは${maxLimit}個までです`;
      break;
    case 'pinFolder':
      currentCount = await getUserPinFolderCount(env, user.id);
      maxLimit = FREE_TIER_LIMITS.pinFolders;
      message = `無料プランではピンフォルダは${maxLimit}個までです`;
      break;
    case 'kmlFile':
      currentCount = await getUserKmlFileCount(env, user.id);
      maxLimit = FREE_TIER_LIMITS.kmlFiles;
      message = `無料プランではKMLファイルは${maxLimit}個までです`;
      break;
    case 'pin':
      currentCount = await getUserPinCount(env, user.id);
      maxLimit = FREE_TIER_LIMITS.pins;
      message = `無料プランではピンは${maxLimit}個までです`;
      break;
    case 'share':
      currentCount = await getUserShareCount(env, user.id);
      maxLimit = FREE_TIER_LIMITS.shares;
      message = `無料プランでは共有フォルダは${maxLimit}個までです`;
      break;
    default:
      return { allowed: true };
  }

  if (currentCount >= maxLimit) {
    return { allowed: false, message, currentCount, maxLimit };
  }

  return { allowed: true, currentCount, maxLimit };
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
const EMAIL_FROM = 'hello@fieldnota-commons.com';
const EMAIL_FROM_NAME = 'Fieldnota commons';

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

// CSRF protection: validate Origin/Referer for state-changing requests
function validateCSRF(request, url) {
  const method = request.method;

  // Only validate state-changing methods
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return { valid: true };
  }

  // Get Origin or Referer header
  const origin = request.headers.get('Origin');
  const referer = request.headers.get('Referer');

  // At least one must be present for state-changing requests
  if (!origin && !referer) {
    return { valid: false, error: 'Missing Origin/Referer header' };
  }

  // Build list of allowed origins
  const allowedOrigins = [
    url.origin,
    'https://fieldnota-commons.com'
  ];

  // Validate Origin header if present
  if (origin) {
    if (!allowedOrigins.includes(origin)) {
      return { valid: false, error: 'Invalid Origin header' };
    }
    return { valid: true };
  }

  // Validate Referer header as fallback
  if (referer) {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = `${refererUrl.protocol}//${refererUrl.host}`;
      if (!allowedOrigins.includes(refererOrigin)) {
        return { valid: false, error: 'Invalid Referer header' };
      }
      return { valid: true };
    } catch {
      return { valid: false, error: 'Malformed Referer header' };
    }
  }

  return { valid: false, error: 'CSRF validation failed' };
}

// Allowed image types and max size
const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const MAX_IMAGE_SIZE = 2 * 1024 * 1024; // 2MB (client compresses to 1MB, allow margin)
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

  // Get current user from cookie
  let user = null;
  const token = getCookie(request, 'auth');
  if (token) {
    user = await verifyToken(token, env.JWT_SECRET);
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
      const ip = getClientIP(request);
      const rateCheck = await checkRateLimit(env, ip, 'passwordChange');
      if (!rateCheck.allowed) {
        await logSecurityEvent(env, 'rate_limit_exceeded', user.id, request, { endpoint: 'passwordChange' });
        return json({ error: 'パスワード変更の試行回数が多すぎます。しばらくしてから再試行してください。' }, 429, { 'Retry-After': rateCheck.retryAfter.toString() });
      }
      return await handleChangePassword(request, env, user);
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
  }, env.JWT_SECRET);

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
  if (password.length < 12) {
    return json({ error: 'パスワードは12文字以上にしてください' }, 400);
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

  const { hash, salt } = await hashPassword(password);
  // New users start with 'pending' status - must be approved by admin
  const result = await env.DB.prepare(
    'INSERT INTO users (username, password_hash, password_salt, email, display_name, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(username, hash, salt, email, actualDisplayName, 'pending').run();

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
  if (!user || !(await verifyPassword(password, user.password_hash, user.password_salt))) {
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
  if (user.status === 'needs_password') {
    // External member who needs to set up password - this shouldn't happen as password won't match
    await logSecurityEvent(env, 'login_failed', user.id, request, { reason: 'needs_password_setup' });
    return json({ error: 'パスワードを設定してください。登録時に送信されたメールをご確認ください。', needs_password: true, email: user.email }, 403);
  }

  await logSecurityEvent(env, 'login_success', user.id, request, {});

  const token = await createToken({
    id: user.id, username: user.username,
    display_name: user.display_name || user.username,
    is_admin: !!user.is_admin
  }, env.JWT_SECRET);

  return json(
    { id: user.id, username: user.username, display_name: user.display_name, is_admin: !!user.is_admin },
    200,
    { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
  );
}

function handleLogout() {
  return json({ ok: true }, 200, { 'Set-Cookie': setCookieHeader('auth', '', { maxAge: 0 }) });
}

// External Member Sync API Handler (for WordPress/Stripe integration)
async function handleExternalMemberSync(request, env) {
  try {
    const { action, email, display_name, plan, external_id, secret } = await request.json();

    // Verify shared secret
    if (!env.EXTERNAL_SYNC_SECRET || secret !== env.EXTERNAL_SYNC_SECRET) {
      return json({ error: 'Unauthorized' }, 401);
    }

    if (!email) {
      return json({ error: 'Email is required' }, 400);
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(email)) {
      return json({ error: 'Invalid email format' }, 400);
    }

    if (action === 'create') {
      // Check if user already exists by email
      const existing = await env.DB.prepare('SELECT id, member_source FROM users WHERE email = ?').bind(email).first();

      if (existing) {
        if (existing.member_source === 'wordpress') {
          // Update plan for existing external member
          await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?').bind(plan || 'premium', existing.id).run();
          return json({ success: true, action: 'updated', user_id: existing.id });
        } else {
          // User registered normally, just update their plan
          await env.DB.prepare('UPDATE users SET plan = ?, member_source = ? WHERE id = ?')
            .bind(plan || 'premium', 'wordpress', existing.id).run();
          return json({ success: true, action: 'upgraded', user_id: existing.id });
        }
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
      // Find and delete user by email
      const user = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();

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
    return json({ error: err.message || 'Server error' }, 500);
  }
}

// Send welcome email to external member
async function sendExternalWelcomeEmail(env, email, displayName) {
  const appUrl = 'https://fieldnota-commons.com';
  const subject = 'Fieldnota commons へようこそ';

  const htmlBody = `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h1 style="color: #4CAF50;">Fieldnota commons へようこそ！</h1>
  <p>${displayName} 様</p>
  <p>有料会員登録ありがとうございます。</p>
  <p>Fieldnota commons をご利用いただくには、以下のリンクからパスワードを設定してください：</p>
  <p style="text-align: center; margin: 30px 0;">
    <a href="${appUrl}?setup=password&email=${encodeURIComponent(email)}"
       style="background: #4CAF50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
      パスワードを設定する
    </a>
  </p>
  <p style="color: #666; font-size: 14px;">
    ※ このメールに心当たりがない場合は、無視してください。
  </p>
  <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
  <p style="color: #999; font-size: 12px;">Fieldnota commons</p>
</body>
</html>
  `;

  const textBody = `
${displayName} 様

Fieldnota commons へようこそ！

有料会員登録ありがとうございます。

以下のリンクからパスワードを設定してください：
${appUrl}?setup=password&email=${encodeURIComponent(email)}

※ このメールに心当たりがない場合は、無視してください。

Fieldnota commons
  `;

  return await sendEmail(env, email, subject, htmlBody, textBody);
}

// Handle account setup for external members (username + password)
async function handleSetupPassword(request, env) {
  try {
    const { email, username, display_name, password } = await request.json();

    if (!email || !username || !password) {
      return json({ error: 'すべての必須項目を入力してください' }, 400);
    }

    // Validate username format (full name in Roman letters)
    const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
    if (!fullNamePattern.test(username.trim())) {
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
      .bind(username.trim(), user.id).first();
    if (existingUsername) {
      return json({ error: 'そのユーザー名は既に使われています' }, 400);
    }

    // Check if display name is already taken
    const actualDisplayName = (display_name || username).trim();
    const existingDisplayName = await env.DB.prepare('SELECT id FROM users WHERE display_name = ? AND id != ?')
      .bind(actualDisplayName, user.id).first();
    if (existingDisplayName) {
      return json({ error: 'その表示名は既に使われています' }, 400);
    }

    // Update username, display_name, password and status
    const { hash, salt } = await hashPassword(password);
    await env.DB.prepare('UPDATE users SET username = ?, display_name = ?, password_hash = ?, password_salt = ?, status = ? WHERE id = ?')
      .bind(username.trim(), actualDisplayName, hash, salt, 'approved', user.id).run();

    // Create token for auto-login
    const token = await createToken({
      id: user.id,
      username: username.trim(),
      display_name: actualDisplayName,
      is_admin: !!user.is_admin
    }, env.JWT_SECRET);

    await logSecurityEvent(env, 'account_setup_complete', user.id, request, { member_source: user.member_source });

    return json(
      {
        success: true,
        message: 'アカウントを設定しました',
        user: { id: user.id, username: username.trim(), display_name: actualDisplayName, is_admin: !!user.is_admin }
      },
      200,
      { 'Set-Cookie': setCookieHeader('auth', token, { maxAge: 604800, httpOnly: true, secure: true, sameSite: 'Strict' }) }
    );
  } catch (err) {
    console.error('Account setup error:', err);
    return json({ error: err.message || 'Server error' }, 500);
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
      'SELECT plan, member_source, stripe_customer_id FROM users WHERE id = ?'
    ).bind(user.id).first();

    // Check if user is already premium via WordPress
    if (dbUser.member_source === 'wordpress' && dbUser.plan === 'premium') {
      return json({ error: 'WordPress経由で既にプレミアム会員です。課金管理はWordPress側で行ってください。' }, 400);
    }

    // Check if user already has an active Stripe subscription
    if (dbUser.member_source === 'stripe' && dbUser.plan === 'premium') {
      return json({ error: '既にプレミアム会員です' }, 400);
    }

    const { success_url, cancel_url } = await request.json();
    const appUrl = success_url || 'https://fieldnota-commons.com';
    const cancelUrl = cancel_url || 'https://fieldnota-commons.com';

    // Create or retrieve Stripe customer
    let customerId = dbUser.stripe_customer_id;
    if (!customerId) {
      const customerResponse = await fetch('https://api.stripe.com/v1/customers', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          'email': user.email || '',
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
    }

    // Create Checkout Session
    const sessionResponse = await fetch('https://api.stripe.com/v1/checkout/sessions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.STRIPE_SECRET_KEY}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        'customer': customerId,
        'mode': 'subscription',
        'line_items[0][price]': env.STRIPE_PRICE_ID,
        'line_items[0][quantity]': '1',
        'success_url': `${appUrl}?session_id={CHECKOUT_SESSION_ID}`,
        'cancel_url': cancelUrl,
        'metadata[user_id]': user.id.toString()
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
    return json({ error: err.message || 'Server error' }, 500);
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

        if (userId) {
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

        // Find user by customer ID
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
            // Set end date for grace period
            const endsAt = new Date(subscription.current_period_end * 1000).toISOString();
            await env.DB.prepare(`
              UPDATE users SET subscription_ends_at = ? WHERE id = ?
            `).bind(endsAt, user.id).run();
          }
        }
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const customerId = subscription.customer;

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
    return json({ error: err.message || 'Webhook error' }, 500);
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
async function handleCreatePortalSession(request, env, user) {
  try {
    if (!env.STRIPE_SECRET_KEY) {
      return json({ error: 'Stripe is not configured' }, 500);
    }

    // Require password verification for security
    const body = await request.json().catch(() => ({}));
    const { password } = body;

    if (!password) {
      return json({ error: 'パスワードが必要です' }, 400);
    }

    const dbUser = await env.DB.prepare(
      'SELECT stripe_customer_id, member_source, password_hash, password_salt FROM users WHERE id = ?'
    ).bind(user.id).first();

    // Verify password
    if (!dbUser.password_hash || !(await verifyPassword(password, dbUser.password_hash, dbUser.password_salt))) {
      return json({ error: 'パスワードが正しくありません' }, 401);
    }

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
    return json({ error: err.message || 'Server error' }, 500);
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
    return json({ error: err.message || 'Server error' }, 500);
  }
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
  }, env.JWT_SECRET);

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
        COALESCE(kfv.is_visible, 1) as is_visible,
        CASE WHEN EXISTS (SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = kf.id) THEN 1 ELSE 0 END as is_shared
      FROM kml_folders kf
      LEFT JOIN users u ON kf.user_id = u.id
      LEFT JOIN kml_folder_visibility kfv ON kf.id = kfv.kml_folder_id AND kfv.user_id = ?
      WHERE kf.user_id = ? OR kf.is_public = 1
        OR kf.id IN (SELECT kml_folder_id FROM kml_folder_shares WHERE shared_with_user_id = ?)
      ORDER BY kf.sort_order, kf.name
    `).bind(user.id, user.id, user.id, user.id).all();
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
  const { name, is_public, parent_id } = await request.json();
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

async function handleGetKmlFolderShares(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM kml_folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  // User must be owner, admin, or shared with this folder
  const isOwner = folder.user_id === user.id;
  const isAdmin = user.is_admin;
  const isSharedWith = await env.DB.prepare(
    'SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = ? AND shared_with_user_id = ?'
  ).bind(id, user.id).first();

  if (!isOwner && !isAdmin && !isSharedWith) {
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
  if (folder.user_id !== user.id && !user.is_admin) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await request.json();
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
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await request.json();

  // Get all folders at the same level owned by the user
  // Use separate queries to avoid dynamic SQL construction
  let siblings;
  if (folder.parent_id) {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM kml_folders
      WHERE user_id = ? AND parent_id = ?
      ORDER BY sort_order, id
    `).bind(user.id, folder.parent_id).all();
  } else {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM kml_folders
      WHERE user_id = ? AND parent_id IS NULL
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

  // Check free tier limit (skip if uploading to admin's public/shared folder)
  let isAdminFolder = false;
  if (folderId) {
    const folder = await env.DB.prepare(`
      SELECT f.*, u.is_admin FROM kml_folders f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = ?
    `).bind(folderId).first();
    if (folder && folder.is_admin) {
      isAdminFolder = folder.is_public === 1 ||
        await env.DB.prepare('SELECT 1 FROM kml_folder_shares WHERE kml_folder_id = ? AND shared_with_user_id = ?')
          .bind(folderId, user.id).first();
    }
  }
  if (!isAdminFolder) {
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
      CASE WHEN EXISTS (SELECT 1 FROM folder_shares WHERE folder_id = f.id) THEN 1 ELSE 0 END as is_shared
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

async function handleGetFolderShares(env, user, id) {
  const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ?').bind(id).first();
  if (!folder) return json({ error: 'フォルダが見つかりません' }, 404);

  // User must be owner, admin, or shared with this folder
  const isOwner = folder.user_id === user.id;
  const isAdmin = user.is_admin;
  const isSharedWith = await env.DB.prepare(
    'SELECT 1 FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
  ).bind(id, user.id).first();

  if (!isOwner && !isAdmin && !isSharedWith) {
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
  if (folder.user_id !== user.id && !user.is_admin) return json({ error: '権限がありません' }, 403);

  const { user_ids } = await request.json();
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
  if (folder.user_id !== user.id && !user.is_admin) {
    return json({ error: '権限がありません' }, 403);
  }

  const { target_id } = await request.json();

  // Get all folders at the same level owned by the user
  // Use separate queries to avoid dynamic SQL construction
  let siblings;
  if (folder.parent_id) {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM folders
      WHERE user_id = ? AND parent_id = ?
      ORDER BY sort_order, id
    `).bind(user.id, folder.parent_id).all();
  } else {
    siblings = await env.DB.prepare(`
      SELECT id, sort_order FROM folders
      WHERE user_id = ? AND parent_id IS NULL
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
        CASE WHEN f.is_public = 1 THEN 1 ELSE 0 END as is_public,
        CASE WHEN EXISTS (SELECT 1 FROM folder_shares WHERE folder_id = p.folder_id) THEN 1 ELSE 0 END as is_shared
      FROM pins p
      LEFT JOIN users u ON p.user_id = u.id
      LEFT JOIN folders f ON p.folder_id = f.id
      ORDER BY p.created_at DESC
    `).all();
  } else if (user) {
    // User sees: own pins, pins in public folders, pins in shared folders
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
      ORDER BY p.created_at DESC
    `).bind(user.id, user.id).all();
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

  // Check free tier limit (skip if creating in admin's public/shared folder)
  let isAdminFolder = false;
  if (folder_id) {
    const folder = await env.DB.prepare(`
      SELECT f.*, u.is_admin FROM folders f
      JOIN users u ON f.user_id = u.id
      WHERE f.id = ?
    `).bind(folder_id).first();
    if (folder && folder.is_admin) {
      isAdminFolder = folder.is_public === 1 ||
        await env.DB.prepare('SELECT 1 FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?')
          .bind(folder_id, user.id).first();
    }
  }
  if (!isAdminFolder) {
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

// ==================== Pin Comments Handlers ====================
async function handleGetPinComments(env, user, pinId) {
  // Check if pin exists and user has access
  const pin = await env.DB.prepare(`
    SELECT p.*, f.is_public as folder_is_public, f.user_id as folder_user_id
    FROM pins p
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE p.id = ?
  `).bind(pinId).first();

  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);

  // Check access: owner, admin, public folder, or shared folder
  const folderIsPublic = pin.folder_is_public === 1;
  const isOwner = user && pin.user_id === user.id;
  const isAdmin = user && user.is_admin;

  let hasAccess = isOwner || isAdmin || folderIsPublic;

  if (!hasAccess && user && pin.folder_id) {
    const share = await env.DB.prepare(
      'SELECT * FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
    ).bind(pin.folder_id, user.id).first();
    hasAccess = !!share;
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
  const { content } = await request.json();

  if (!content || content.trim().length === 0) {
    return json({ error: 'コメントを入力してください' }, 400);
  }
  if (content.length > 50) {
    return json({ error: 'コメントは50文字以内で入力してください' }, 400);
  }

  // Check if pin exists and user has access to view it
  const pin = await env.DB.prepare(`
    SELECT p.*, f.is_public as folder_is_public
    FROM pins p
    LEFT JOIN folders f ON p.folder_id = f.id
    WHERE p.id = ?
  `).bind(pinId).first();

  if (!pin) return json({ error: 'ピンが見つかりません' }, 404);

  // Check access: owner, admin, public folder, or shared folder
  const folderIsPublic = pin.folder_is_public === 1;
  const isOwner = pin.user_id === user.id;
  const isAdmin = user.is_admin;

  let hasAccess = isOwner || isAdmin || folderIsPublic;

  if (!hasAccess && pin.folder_id) {
    const share = await env.DB.prepare(
      'SELECT * FROM folder_shares WHERE folder_id = ? AND shared_with_user_id = ?'
    ).bind(pin.folder_id, user.id).first();
    hasAccess = !!share;
  }

  if (!hasAccess) return json({ error: 'アクセス権限がありません' }, 403);

  const result = await env.DB.prepare(
    'INSERT INTO pin_comments (pin_id, user_id, content) VALUES (?, ?, ?)'
  ).bind(pinId, user.id, content.trim()).run();

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
      body: `${user.display_name || user.username}: ${content.trim().substring(0, 30)}`,
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

  // Combine and sort by created_at
  const all = [...comments.results, ...pins.results, ...kmlFiles.results];
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
  const { subscription } = await request.json();

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
  const { endpoint } = await request.json();

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
    debug.steps.push('ERROR: ' + (err.message || String(err)));
    debug.error = { message: err.message, name: err.name, stack: err.stack?.substring(0, 500) };
    return json({ error: 'Push failed', message: err.message, debug }, 500);
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
  const { credential, deviceName } = await request.json();

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
  const { credential } = await request.json();

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

  // Check user status
  if (passkey.status !== 'active') {
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
    await logSecurityEvent(env, 'passkey_login_failed', passkey.uid, request, { reason: err.message });
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

  // Generate JWT token
  const token = await createToken({
    id: passkey.uid,
    username: passkey.username,
    display_name: passkey.display_name || passkey.username,
    is_admin: !!passkey.is_admin
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
