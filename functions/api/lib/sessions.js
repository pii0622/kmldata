// Session management with hashed token/IP storage

import { base64urlEncode, hashIP } from './utils.js';

// Hash session token for secure storage
export async function hashSessionToken(token) {
  const encoder = new TextEncoder();
  const data = encoder.encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(hash));
}

export function generateSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64urlEncode(bytes);
}

export function parseDeviceName(userAgent) {
  if (!userAgent) return 'Unknown Device';
  let browser = 'Unknown Browser';
  if (userAgent.includes('Firefox/')) browser = 'Firefox';
  else if (userAgent.includes('Edg/')) browser = 'Edge';
  else if (userAgent.includes('Chrome/')) browser = 'Chrome';
  else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) browser = 'Safari';
  else if (userAgent.includes('Opera') || userAgent.includes('OPR/')) browser = 'Opera';
  let os = 'Unknown OS';
  if (userAgent.includes('Windows')) os = 'Windows';
  else if (userAgent.includes('Mac OS X') || userAgent.includes('Macintosh')) os = 'Mac';
  else if (userAgent.includes('Linux') && !userAgent.includes('Android')) os = 'Linux';
  else if (userAgent.includes('Android')) os = 'Android';
  else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) os = 'iOS';
  return `${browser} on ${os}`;
}

const SESSION_INACTIVITY_MS = 3 * 24 * 60 * 60 * 1000; // 3 days

export async function createSession(env, userId, request) {
  const sessionToken = generateSessionToken();
  const tokenHash = await hashSessionToken(sessionToken);
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const ipHash = await hashIP(ip);
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const deviceName = parseDeviceName(userAgent);
  const expiresAt = new Date(Date.now() + SESSION_INACTIVITY_MS).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (user_id, session_token, ip_address, user_agent, device_name, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(userId, tokenHash, ipHash, userAgent, deviceName, expiresAt).run();

  return sessionToken;
}

export async function validateSession(env, sessionToken) {
  if (!sessionToken) return null;
  const tokenHash = await hashSessionToken(sessionToken);
  const session = await env.DB.prepare(
    `SELECT * FROM sessions
     WHERE session_token = ?
     AND is_revoked = 0
     AND datetime(expires_at) > datetime('now')`
  ).bind(tokenHash).first();

  if (session) {
    // Sliding window: extend expiry on each activity (3 days from now)
    const newExpiresAt = new Date(Date.now() + SESSION_INACTIVITY_MS).toISOString();
    env.DB.prepare(
      `UPDATE sessions SET last_active_at = datetime('now'), expires_at = ? WHERE id = ?`
    ).bind(newExpiresAt, session.id).run().catch(() => {});
  }
  return session;
}

export async function revokeSession(env, sessionToken) {
  const tokenHash = await hashSessionToken(sessionToken);
  await env.DB.prepare(
    `UPDATE sessions SET is_revoked = 1 WHERE session_token = ?`
  ).bind(tokenHash).run();
}

export async function revokeSessionById(env, sessionId, userId) {
  const result = await env.DB.prepare(
    `UPDATE sessions SET is_revoked = 1 WHERE id = ? AND user_id = ?`
  ).bind(sessionId, userId).run();
  return result.meta.changes > 0;
}

export async function revokeAllUserSessions(env, userId, exceptSessionToken = null) {
  if (exceptSessionToken) {
    const tokenHash = await hashSessionToken(exceptSessionToken);
    await env.DB.prepare(
      `UPDATE sessions SET is_revoked = 1 WHERE user_id = ? AND session_token != ?`
    ).bind(userId, tokenHash).run();
  } else {
    await env.DB.prepare(
      `UPDATE sessions SET is_revoked = 1 WHERE user_id = ?`
    ).bind(userId).run();
  }
}

export async function getUserSessions(env, userId) {
  const sessions = await env.DB.prepare(
    `SELECT id, ip_address, device_name, created_at, last_active_at
     FROM sessions
     WHERE user_id = ? AND is_revoked = 0 AND datetime(expires_at) > datetime('now')
     ORDER BY last_active_at DESC`
  ).bind(userId).all();
  return sessions.results;
}

// Clean up expired sessions (can be called periodically)
export async function cleanupExpiredSessions(env) {
  await env.DB.prepare(
    `DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')`
  ).run();
}
