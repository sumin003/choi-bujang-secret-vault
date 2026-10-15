import { createHash, createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';

const COOKIE = '__Host-vault_device';
const LIFETIME = 5 * 60;
const HASH = /^[a-f0-9]{64}$/;

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function credentialHash(credentialId) {
  if (typeof credentialId !== 'string' || !/^[A-Za-z0-9_-]{16,1024}$/.test(credentialId))
    return null;
  return digest(credentialId);
}

function signingKey(secret) {
  if (typeof secret !== 'string' || !secret) throw new Error('device_unavailable');
  return hkdfSync('sha256', secret, 'vault-device-approval', 'device-session-v1', 32);
}

export function makeDeviceCookie({ authorization, userId, hash, secret, now = Date.now() }) {
  if (!HASH.test(hash) || !userId || !authorization) throw new Error('device_unavailable');
  const payload = Buffer.from(JSON.stringify({ u: userId, h: hash, t: digest(authorization),
    e: Math.floor(now / 1000) + LIFETIME })).toString('base64url');
  const signature = createHmac('sha256', signingKey(secret)).update(payload).digest('base64url');
  return `${COOKIE}=${payload}.${signature}; Max-Age=${LIFETIME}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

function readDeviceCookie(req, identity, secret, now) {
  const authorization = req.headers?.authorization;
  if (typeof authorization !== 'string') return null;
  const header = req.headers?.cookie ?? '';
  const match = new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`).exec(header);
  if (!match) return null;
  const [payload, signature, extra] = match[1].split('.');
  if (extra || !payload || !signature || payload.length > 1000) return null;
  try {
    const expected = createHmac('sha256', signingKey(secret)).update(payload).digest();
    const supplied = Buffer.from(signature, 'base64url');
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) return null;
    const record = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (record.u !== identity.userId || record.t !== digest(authorization)
        || !HASH.test(record.h ?? '') || !Number.isSafeInteger(record.e)
        || record.e <= Math.floor(now / 1000) || record.e > Math.floor(now / 1000) + LIFETIME) return null;
    return record.h;
  } catch { return null; }
}

export async function deviceRecord({ userId, hash, secret, url, fetchImpl = fetch }) {
  if (!HASH.test(hash) || !/^[0-9a-f-]{36}$/i.test(userId)) throw new Error('device_unavailable');
  const base = new URL(url);
  if (base.protocol !== 'https:' || base.username || base.password) throw new Error('device_unavailable');
  const endpoint = new URL('/rest/v1/learning_device_approvals', base);
  endpoint.search = new URLSearchParams({ select: 'credential_hash,status', user_id: 'eq.' + userId,
    credential_hash: 'eq.' + hash, limit: '1' }).toString();
  const response = await fetchImpl(endpoint, { headers: { apikey: secret },
    cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (!response.ok) throw new Error('device_unavailable');
  const rows = await response.json();
  if (!Array.isArray(rows) || rows.length > 1) throw new Error('device_unavailable');
  const row = rows[0];
  if (row && (row.credential_hash !== hash || !['pending', 'approved', 'rejected'].includes(row.status)))
    throw new Error('device_unavailable');
  return row?.status ?? null;
}

export async function requestDeviceApproval({ userId, hash, secret, url, fetchImpl = fetch }) {
  const existing = await deviceRecord({ userId, hash, secret, url, fetchImpl });
  if (existing) return existing;
  const base = new URL(url);
  const endpoint = new URL('/rest/v1/learning_device_approvals', base);
  const response = await fetchImpl(endpoint, { method: 'POST',
    headers: { apikey: secret, 'Content-Type': 'application/json',
      Prefer: 'return=minimal' },
    body: JSON.stringify({ user_id: userId, credential_hash: hash, status: 'pending' }),
    cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (response.status === 409) return deviceRecord({ userId, hash, secret, url, fetchImpl });
  if (!response.ok) throw new Error('device_unavailable');
  return 'pending';
}

export async function checkApprovedDevice(req, identity, {
  secret = process.env.SUPABASE_SECRET_KEY, url = process.env.SUPABASE_URL,
  fetchImpl = fetch, now = Date.now(),
} = {}) {
  // Judge tokens are independently verified by the existing judge issuer and
  // are never exposed to the student's browser or device enrollment flow.
  if (identity?.kind === 'judge') return 'approved';
  if (identity?.kind !== 'student') return 'required';
  const hash = readDeviceCookie(req, identity, secret, now);
  if (!hash) return 'required';
  try {
    return await deviceRecord({ userId: identity.userId, hash, secret, url, fetchImpl }) === 'approved'
      ? 'approved' : 'required';
  } catch { return 'unavailable'; }
}

export async function enforceApprovedDevice(req, res, identity, options) {
  const result = await checkApprovedDevice(req, identity, options);
  if (result === 'approved') return true;
  res.status(result === 'unavailable' ? 503 : 403).json({
    error: result === 'unavailable' ? 'DEVICE_STATUS_UNAVAILABLE' : 'DEVICE_APPROVAL_REQUIRED',
  });
  return false;
}
