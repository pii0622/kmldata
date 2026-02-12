// Base utilities for Cloudflare Pages Functions

// Base64URL encoding (RFC 4648) - URL-safe, no padding
export function base64urlEncode(data) {
  const bytes = data instanceof Uint8Array ? data :
    typeof data === 'string' ? new TextEncoder().encode(data) :
    new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) base64 += '='.repeat(4 - pad);
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

export function base64urlDecodeToString(str) {
  const bytes = base64urlDecode(str);
  return new TextDecoder().decode(bytes);
}

// Cookie utilities
export function getCookie(request, name) {
  const cookies = request.headers.get('Cookie') || '';
  const match = cookies.match(new RegExp(`${name}=([^;]+)`));
  return match ? match[1] : null;
}

export function setCookieHeader(name, value, options = {}) {
  let cookie = `${name}=${value}`;
  if (options.maxAge) cookie += `; Max-Age=${options.maxAge}`;
  if (options.httpOnly) cookie += '; HttpOnly';
  if (options.secure) cookie += '; Secure';
  if (options.sameSite) cookie += `; SameSite=${options.sameSite}`;
  cookie += '; Path=/';
  return cookie;
}

// JSON response helper
export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers }
  });
}

// Client IP extraction
export function getClientIP(request) {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
         'unknown';
}

// Email validation (RFC-compliant)
export function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;

  const parts = email.split('@');
  if (parts.length !== 2) return false;

  const [localPart, domain] = parts;

  if (!localPart || localPart.length > 64) return false;
  if (localPart.startsWith('.') || localPart.endsWith('.') || localPart.includes('..')) return false;
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(localPart)) return false;

  if (!domain || domain.length > 253) return false;
  if (domain.startsWith('.') || domain.startsWith('-') || domain.endsWith('.') || domain.endsWith('-')) return false;
  if (domain.includes('..')) return false;

  const domainLabels = domain.split('.');
  if (domainLabels.length < 2) return false;

  for (const label of domainLabels) {
    if (!label || label.length > 63) return false;
    if (label.startsWith('-') || label.endsWith('-')) return false;
    if (!/^[a-zA-Z0-9-]+$/.test(label)) return false;
  }

  const tld = domainLabels[domainLabels.length - 1];
  if (tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) return false;

  return true;
}

// Security headers
export const securityHeaders = {
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'X-XSS-Protection': '1; mode=block',
  'Permissions-Policy': 'geolocation=(self), camera=(), microphone=()'
};
