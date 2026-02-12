// WebAuthn/Passkeys utilities

import { base64urlEncode, base64urlDecode } from './utils.js';

// Generate random challenge for WebAuthn
export function generateWebAuthnChallenge() {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  return base64urlEncode(challenge);
}

// Simple CBOR decoder for WebAuthn public key parsing
export function decodeCBOR(data) {
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
      case 0: return value;
      case 1: return -1 - value;
      case 2: return readBytes(value);
      case 3: return new TextDecoder().decode(readBytes(value));
      case 4:
        const arr = [];
        for (let i = 0; i < value; i++) arr.push(decode());
        return arr;
      case 5:
        const map = {};
        for (let i = 0; i < value; i++) {
          const key = decode();
          map[key] = decode();
        }
        return map;
      case 6: return decode();
      case 7:
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
export function parseAttestationObject(attestationObject) {
  const decoded = decodeCBOR(attestationObject);
  return {
    fmt: decoded.fmt,
    authData: decoded.authData,
    attStmt: decoded.attStmt
  };
}

// Parse authenticator data
export function parseAuthenticatorData(authData) {
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
export async function coseKeyToCryptoKey(coseKey) {
  const kty = coseKey[1];
  const alg = coseKey[3];

  if (kty !== 2 || alg !== -7) {
    throw new Error('Unsupported key type or algorithm');
  }

  const crv = coseKey[-1];
  const x = coseKey[-2];
  const y = coseKey[-3];

  if (crv !== 1) {
    throw new Error('Unsupported curve');
  }

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

// Convert DER signature to raw format (r || s)
export function derToRaw(der) {
  let offset = 2;

  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature');
  let rLen = der[offset++];
  let r = der.slice(offset, offset + rLen);
  offset += rLen;

  if (der[offset++] !== 0x02) throw new Error('Invalid DER signature');
  let sLen = der[offset++];
  let s = der.slice(offset, offset + sLen);

  while (r.length > 32 && r[0] === 0) r = r.slice(1);
  while (s.length > 32 && s[0] === 0) s = s.slice(1);
  while (r.length < 32) r = new Uint8Array([0, ...r]);
  while (s.length < 32) s = new Uint8Array([0, ...s]);

  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

// Verify WebAuthn assertion signature
export async function verifyWebAuthnSignature(authData, clientDataJSON, signature, publicKeyBase64) {
  const publicKeyData = base64urlDecode(publicKeyBase64);
  const coseKey = decodeCBOR(publicKeyData);
  const cryptoKey = await coseKeyToCryptoKey(coseKey);

  const clientDataHash = await crypto.subtle.digest('SHA-256', clientDataJSON);
  const signedData = new Uint8Array(authData.length + 32);
  signedData.set(authData, 0);
  signedData.set(new Uint8Array(clientDataHash), authData.length);

  const rawSignature = derToRaw(signature);

  return await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    cryptoKey,
    rawSignature,
    signedData
  );
}

// Get RP ID from request URL
export function getRelyingPartyId(request) {
  const url = new URL(request.url);
  return url.hostname;
}
