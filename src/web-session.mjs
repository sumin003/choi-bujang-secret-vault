import { createHash, randomBytes, createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';

const COOKIE = '__Host-vault_web_session';
export const WEB_SESSION_SECONDS = 7 * 24 * 60 * 60;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
const fail = () => { throw new Error('WEB_SESSION_UNAVAILABLE'); };
export const expiredWebCookie = () => `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`;

function cookieHash(req) {
  const header = req.headers?.cookie;
  if (typeof header !== 'string') return null;
  const values = header.split(';').map(v => v.trim()).filter(v => v.startsWith(COOKIE + '='));
  if (values.length !== 1) return null;
  const raw = values[0].slice(COOKIE.length + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(raw)
      || Buffer.from(raw, 'base64url').toString('base64url') !== raw) return null;
  return createHash('sha256').update(raw).digest('hex');
}
function encryptionKey(secret) {
  if (typeof secret !== 'string' || !secret) return fail();
  return hkdfSync('sha256', secret, 'vault-server-session', 'tokens-aes-gcm-v1', 32);
}
function tokensOf(value) {
  if (!value || typeof value.access_token !== 'string' || value.access_token.length > 8192
      || typeof value.refresh_token !== 'string' || value.refresh_token.length > 8192
      || !value.access_token || !value.refresh_token || !Number.isSafeInteger(value.expires_at)) return fail();
  return { access_token: value.access_token, refresh_token: value.refresh_token, expires_at: value.expires_at };
}
function seal(value, hash, userId, secret) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', encryptionKey(secret), iv);
  cipher.setAAD(Buffer.from(hash + ':' + userId));
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(tokensOf(value)), 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}
function open(row, secret) {
  try {
    if (typeof row.sealed_tokens !== 'string' || row.sealed_tokens.length > 32768) return fail();
    const bytes = Buffer.from(row.sealed_tokens, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey(secret), bytes.subarray(0, 12));
    decipher.setAAD(Buffer.from(row.session_hash + ':' + row.user_id));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return tokensOf(JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString('utf8')));
  } catch { return fail(); }
}

export function createWebSessions({ env = process.env, fetchImpl = globalThis.fetch,
  now = () => Date.now(), makeClient } = {}) {
  const refreshes = new Map();
  async function client() {
    if (makeClient) return makeClient();
    const { createClient } = await import('@supabase/supabase-js');
    return createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY,
      { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } });
  }
  async function store(method, hash, body, version) {
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY || !HASH.test(hash)) return fail();
    const base = new URL(env.SUPABASE_URL);
    if (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash) return fail();
    const url = new URL('/rest/v1/learning_web_sessions', base);
    if (method !== 'POST') {
      url.searchParams.set('session_hash', 'eq.' + hash);
      if (version !== undefined) url.searchParams.set('version', 'eq.' + version);
      if (method === 'GET') url.searchParams.set('select', 'session_hash,user_id,sealed_tokens,expires_at,version');
    }
    const response = await fetchImpl(url, { method, cache: 'no-store', redirect: 'error',
      signal: AbortSignal.timeout(10000), headers: { apikey: env.SUPABASE_SECRET_KEY,
        'Content-Type': 'application/json', Prefer: 'return=representation' },
      body: body ? JSON.stringify(body) : undefined });
    if (!response.ok) return fail();
    const rows = response.status === 204 ? [] : await response.json();
    if (!Array.isArray(rows)) return fail();
    return rows;
  }
  async function get(hash) {
    const rows = await store('GET', hash);
    if (rows.length > 1) return fail();
    const row = rows[0]; if (!row) return null;
    if (row.session_hash !== hash || !UUID.test(row.user_id ?? '') || !Number.isSafeInteger(row.version)
        || row.version < 1 || !Number.isFinite(Date.parse(row.expires_at))) return fail();
    if (Date.parse(row.expires_at) <= now()) { await store('DELETE', hash); return null; }
    return row;
  }
  async function issue(session, userId) {
    if (!UUID.test(userId ?? '')) return fail();
    const raw = randomBytes(32).toString('base64url');
    const hash = createHash('sha256').update(raw).digest('hex');
    await store('POST', hash, { session_hash: hash, user_id: userId,
      sealed_tokens: seal(session, hash, userId, env.SUPABASE_SECRET_KEY),
      expires_at: new Date(now() + WEB_SESSION_SECONDS * 1000).toISOString(), version: 1 });
    return `${COOKIE}=${raw}; Max-Age=${WEB_SESSION_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`;
  }
  async function refresh(row, previous) {
    const sdk = await client();
    const { data, error } = await sdk.auth.refreshSession({ refresh_token: previous.refresh_token });
    if (error) {
      const latest = await get(row.session_hash);
      if (latest && latest.version > row.version) return { row: latest, tokens: open(latest, env.SUPABASE_SECRET_KEY) };
      if (['refresh_token_not_found', 'refresh_token_already_used', 'user_banned', 'session_not_found'].includes(error.code)) {
        await store('DELETE', row.session_hash); return null;
      }
      return fail();
    }
    if (data?.user?.id !== row.user_id) return fail();
    const tokens = tokensOf(data.session);
    const sealed = seal(tokens, row.session_hash, row.user_id, env.SUPABASE_SECRET_KEY);
    const rows = await store('PATCH', row.session_hash, { sealed_tokens: sealed, version: row.version + 1 }, row.version);
    if (rows.length === 1) return { row: rows[0], tokens };
    const latest = await get(row.session_hash);
    return latest ? { row: latest, tokens: open(latest, env.SUPABASE_SECRET_KEY) } : null;
  }
  async function load(req) {
    const hash = cookieHash(req); if (!hash) return null;
    const row = await get(hash); if (!row) return null;
    const tokens = open(row, env.SUPABASE_SECRET_KEY);
    if (tokens.expires_at > Math.floor(now() / 1000) + 60) return { row, tokens };
    if (!refreshes.has(hash)) refreshes.set(hash, refresh(row, tokens).finally(() => refreshes.delete(hash)));
    return refreshes.get(hash);
  }
  async function authorization(req) {
    if (req.headers?.authorization !== undefined)
      return typeof req.headers.authorization === 'string' ? req.headers.authorization : null;
    const session = await load(req);
    return session ? 'Bearer ' + session.tokens.access_token : null;
  }
  async function revoke(req) {
    const hash = cookieHash(req); if (!hash) return;
    const row = await get(hash); if (!row) return;
    const tokens = open(row, env.SUPABASE_SECRET_KEY);
    await store('DELETE', hash);
    try { const sdk = await client(); await sdk.auth.admin.signOut(tokens.access_token, 'local'); } catch { /* Never log tokens or upstream errors. */ }
  }
  return Object.freeze({ client, issue, load, authorization, revoke });
}
const sessions = createWebSessions();
export const resolveSessionAuthorization = req => sessions.authorization(req);
