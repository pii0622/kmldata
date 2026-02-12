// Cryptographic utilities - Password hashing and JWT

import { base64urlEncode, base64urlDecode, base64urlDecodeToString } from './utils.js';

// PBKDF2 configuration
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEY_LENGTH = 32; // 256 bits

// Hash password with PBKDF2 and random salt
export async function hashPassword(password) {
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
export async function verifyPassword(password, storedHash, salt) {
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

// Create JWT token
export async function createToken(payload, secret) {
  const encoder = new TextEncoder();
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

// Verify JWT token
export async function verifyToken(token, secret) {
  try {
    const [header, payload, signature] = token.split('.');
    const encoder = new TextEncoder();
    const data = encoder.encode(`${header}.${payload}`);
    const key = await crypto.subtle.importKey(
      'raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sigBytes = base64urlDecode(signature);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, data);
    if (!valid) return null;
    const parsed = JSON.parse(base64urlDecodeToString(payload));
    if (parsed.exp < Date.now()) return null;
    return parsed;
  } catch { return null; }
}
