// Session management for token invalidation support

import { base64urlEncode } from './utils.js';

// Generate a cryptographically secure session token
export function generateSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64urlEncode(bytes);
}

// Parse user agent to get a friendly device name
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

// Create a new session for a user
export async function createSession(env, userId, request) {
  const sessionToken = generateSessionToken();
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
  const userAgent = request.headers.get('User-Agent') || 'unknown';
  const deviceName = parseDeviceName(userAgent);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await env.DB.prepare(
    `INSERT INTO sessions (user_id, session_token, ip_address, user_agent, device_name, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(userId, sessionToken, ip, userAgent, deviceName, expiresAt).run();

  return sessionToken;
}

// Validate a session token
export async function validateSession(env, sessionToken) {
  if (!sessionToken) return null;

  const session = await env.DB.prepare(
    `SELECT * FROM sessions
     WHERE session_token = ?
     AND is_revoked = 0
     AND datetime(expires_at) > datetime('now')`
  ).bind(sessionToken).first();

  if (session) {
    env.DB.prepare(
      `UPDATE sessions SET last_active_at = datetime('now') WHERE id = ?`
    ).bind(session.id).run().catch(() => {});
  }

  return session;
}

// Revoke a specific session by token
export async function revokeSession(env, sessionToken) {
  await env.DB.prepare(
    `UPDATE sessions SET is_revoked = 1 WHERE session_token = ?`
  ).bind(sessionToken).run();
}

// Revoke a session by ID (for user self-management)
export async function revokeSessionById(env, sessionId, userId) {
  const result = await env.DB.prepare(
    `UPDATE sessions SET is_revoked = 1 WHERE id = ? AND user_id = ?`
  ).bind(sessionId, userId).run();
  return result.meta.changes > 0;
}

// Revoke all sessions for a user (except optionally current one)
export async function revokeAllUserSessions(env, userId, exceptSessionToken = null) {
  if (exceptSessionToken) {
    await env.DB.prepare(
      `UPDATE sessions SET is_revoked = 1 WHERE user_id = ? AND session_token != ?`
    ).bind(userId, exceptSessionToken).run();
  } else {
    await env.DB.prepare(
      `UPDATE sessions SET is_revoked = 1 WHERE user_id = ?`
    ).bind(userId).run();
  }
}

// Get all active sessions for a user
export async function getUserSessions(env, userId) {
  const sessions = await env.DB.prepare(
    `SELECT id, ip_address, device_name, created_at, last_active_at
     FROM sessions
     WHERE user_id = ? AND is_revoked = 0 AND datetime(expires_at) > datetime('now')
     ORDER BY last_active_at DESC`
  ).bind(userId).all();
  return sessions.results;
}

// Clean up expired sessions
export async function cleanupExpiredSessions(env) {
  await env.DB.prepare(
    `DELETE FROM sessions WHERE datetime(expires_at) < datetime('now')`
  ).run();
}
