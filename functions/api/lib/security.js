// Security utilities - Rate limiting, CSRF protection, logging

import { hashIP } from './utils.js';

// Rate limiting configuration
export const RATE_LIMITS = {
  login: { maxRequests: 10, windowSeconds: 300 },
  register: { maxRequests: 5, windowSeconds: 3600 },
  passwordChange: { maxRequests: 5, windowSeconds: 300 },
  passwordSetup: { maxRequests: 3, windowSeconds: 3600 },
  passkey: { maxRequests: 5, windowSeconds: 300 },
  admin: { maxRequests: 30, windowSeconds: 60 },
  pinCreate: { maxRequests: 20, windowSeconds: 60 },
  kmlUpload: { maxRequests: 10, windowSeconds: 60 },
  folderCreate: { maxRequests: 10, windowSeconds: 60 },
  commentCreate: { maxRequests: 30, windowSeconds: 60 },
  default: { maxRequests: 100, windowSeconds: 60 }
};

// Free tier limits
export const FREE_TIER_LIMITS = {
  kmlFolders: 2,
  pinFolders: 2,
  kmlFiles: 1,
  pins: 20,
  shares: 1
};

export async function checkRateLimit(env, ip, endpoint) {
  const config = RATE_LIMITS[endpoint] || RATE_LIMITS.default;
  const key = `${ip}:${endpoint}`;
  const now = new Date();
  const windowStart = new Date(now.getTime() - config.windowSeconds * 1000).toISOString();
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

export async function logSecurityEvent(env, eventType, userId, request, details = {}) {
  const ip = request?.headers?.get('CF-Connecting-IP') || request?.headers?.get('X-Forwarded-For') || 'unknown';
  const ipHash = await hashIP(ip);
  const userAgent = request?.headers?.get('User-Agent') || 'unknown';
  try {
    await env.DB.prepare(
      'INSERT INTO security_logs (event_type, user_id, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)'
    ).bind(eventType, userId, ipHash, userAgent, JSON.stringify(details)).run();
  } catch (err) {
    console.error('Failed to log security event:', err);
  }
}

export function validateCSRF(request, url) {
  const method = request.method;
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    return { valid: true };
  }
  const origin = request.headers.get('Origin');
  const referer = request.headers.get('Referer');
  if (!origin && !referer) {
    return { valid: false, error: 'Missing Origin/Referer header' };
  }
  const allowedOrigins = [url.origin, 'https://fieldnota-commons.com'];
  if (origin) {
    if (!allowedOrigins.includes(origin)) {
      return { valid: false, error: 'Invalid Origin header' };
    }
    return { valid: true };
  }
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

// Free tier checking
export async function isUserFreeTier(user) {
  return !user.is_admin && user.plan !== 'premium';
}

export async function getUserKmlFolderCount(env, userId) {
  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM kml_folders WHERE user_id = ?'
  ).bind(userId).first();
  return result.count;
}

export async function getUserPinFolderCount(env, userId) {
  const result = await env.DB.prepare(
    'SELECT COUNT(*) as count FROM folders WHERE user_id = ?'
  ).bind(userId).first();
  return result.count;
}

export async function getUserKmlFileCount(env, userId) {
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

export async function getUserPinCount(env, userId) {
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

export async function getUserShareCount(env, userId) {
  const givenKml = await env.DB.prepare(`
    SELECT COUNT(DISTINCT kfs.kml_folder_id) as count FROM kml_folder_shares kfs
    JOIN kml_folders kf ON kfs.kml_folder_id = kf.id WHERE kf.user_id = ?
  `).bind(userId).first();
  const givenPin = await env.DB.prepare(`
    SELECT COUNT(DISTINCT fs.folder_id) as count FROM folder_shares fs
    JOIN folders f ON fs.folder_id = f.id WHERE f.user_id = ?
  `).bind(userId).first();
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

export async function checkFreeTierLimit(env, user, limitType) {
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

export const ALLOWED_IMAGE_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
export const MAX_IMAGE_SIZE = 2 * 1024 * 1024;
export const MAX_KML_SIZE = 50 * 1024 * 1024;

export function validateImageFile(file) {
  if (!file || !file.name) return { valid: false, error: 'ファイルが無効です' };
  if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
    return { valid: false, error: `許可されていないファイル形式です: ${file.type}` };
  }
  if (file.size > MAX_IMAGE_SIZE) {
    return { valid: false, error: `ファイルサイズが大きすぎます（最大10MB）: ${file.name}` };
  }
  const ext = file.name.split('.').pop().toLowerCase();
  const validExts = { 'image/jpeg': ['jpg', 'jpeg'], 'image/png': ['png'], 'image/gif': ['gif'], 'image/webp': ['webp'] };
  if (!validExts[file.type]?.includes(ext)) {
    return { valid: false, error: `ファイル拡張子が不正です: ${file.name}` };
  }
  return { valid: true };
}

export function convertKmlPolygonToLine(kml) {
  return kml.replace(
    /<Polygon[^>]*>[\s\S]*?<outerBoundaryIs>\s*<LinearRing>\s*<coordinates>([\s\S]*?)<\/coordinates>\s*<\/LinearRing>\s*<\/outerBoundaryIs>[\s\S]*?<\/Polygon>/gi,
    '<LineString><coordinates>$1</coordinates></LineString>'
  );
}
