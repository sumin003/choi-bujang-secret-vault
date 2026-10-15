import { createHash, randomBytes } from 'node:crypto';
import { createWebSessions } from './web-session.mjs';
import { decideDeviceRegistration } from './decider.mjs';

const COOKIE = '__Host-vault_browser';
const LIFETIME = 30 * 24 * 60 * 60;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const fail = () => { throw new Error('device_registration_not_connected'); };
function browserHash(req) {
  const values = (typeof req.headers?.cookie === 'string' ? req.headers.cookie : '').split(';')
    .map(v => v.trim()).filter(v => v.startsWith(COOKIE + '='));
  if (values.length !== 1) return null;
  const raw = values[0].slice(COOKIE.length + 1);
  if (!/^[A-Za-z0-9_-]{43}$/.test(raw) || Buffer.from(raw, 'base64url').toString('base64url') !== raw) return null;
  return createHash('sha256').update(raw).digest('hex');
}

// Self-enrollment policy for the explicitly permitted HttpOnly browser cookie.
// This registers a browser, not hardware, and is independent of login sessions.
export function createBrowserRegistration({ env = process.env, fetchImpl = globalThis.fetch,
  now = () => Date.now(), sessions = createWebSessions(), readEvidence } = {}) {
  async function store(method, identity, hash, body, pendingOnly = false) {
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY || !UUID.test(identity?.userId ?? '')) return fail();
    const base = new URL(env.SUPABASE_URL);
    if (base.protocol !== 'https:' || base.pathname !== '/' || base.username || base.password || base.search || base.hash) return fail();
    const url = new URL('/rest/v1/learning_browser_registrations', base);
    if (method !== 'POST') {
      url.searchParams.set('browser_hash', 'eq.' + hash);
      url.searchParams.set('user_id', 'eq.' + identity.userId);
      if (pendingOnly) url.searchParams.set('status', 'eq.pending');
      if (method === 'GET') url.searchParams.set('select', 'browser_hash,user_id,status,requested_at,expires_at,approved_at,reason');
    }
    const res = await fetchImpl(url, { method, cache:'no-store', redirect:'error', signal:AbortSignal.timeout(10000),
      headers:{apikey:env.SUPABASE_SECRET_KEY,'Content-Type':'application/json',Prefer:'return=representation'},
      body:body ? JSON.stringify(body) : undefined });
    if (!res.ok) return fail();
    const rows = res.status === 204 ? [] : await res.json();
    if (!Array.isArray(rows) || rows.length > 1) return fail();
    return rows;
  }
  async function rowFor(req, identity) {
    if (identity?.kind !== 'student' || !UUID.test(identity.userId ?? '')) return fail();
    const hash = browserHash(req); if (!hash) return null;
    const [row] = await store('GET', identity, hash);
    if (!row) return null;
    if (row.browser_hash !== hash || row.user_id !== identity.userId
        || !['pending','approved','rejected'].includes(row.status)
        || !Number.isFinite(Date.parse(row.expires_at)) || !Number.isFinite(Date.parse(row.requested_at))) return fail();
    return Date.parse(row.expires_at) > now() ? row : null;
  }
  async function evidence(req, identity) {
    if (readEvidence) return readEvidence(req, identity);
    const authorization = await sessions.authorization(req);
    if (!authorization?.startsWith('Bearer ')) return null;
    const sdk = await sessions.client(), token = authorization.slice(7);
    const userResult = await sdk.auth.getUser(token);
    if (userResult.error) {
      if (!userResult.error.status || userResult.error.status >= 500) return fail();
      return null;
    }
    const claimsResult = await sdk.auth.getClaims(token);
    if (claimsResult.error) return null;
    const user = userResult.data?.user, claims = claimsResult.data?.claims;
    if (user?.id !== identity.userId || claims?.sub !== identity.userId || !user.email_confirmed_at
        || user.is_anonymous || (user.banned_until && Date.parse(user.banned_until) > now())) return null;
    const times = Array.isArray(claims.amr) ? claims.amr.filter(v => v?.method === 'password'
      && Number.isSafeInteger(v.timestamp)).map(v => v.timestamp) : [];
    return { confirmed: true, passwordAt: times.length ? Math.max(...times) : null };
  }
  async function status(req, identity, { review = false } = {}) {
    let row = await rowFor(req, identity);
    if (!row) return { status:'unverified' };
    if (row.status === 'pending' && review) {
      const proof = await evidence(req, identity);
      const age = now() / 1000 - proof?.passwordAt;
      if (proof?.confirmed !== true || !Number.isSafeInteger(proof.passwordAt) || age < 0 || age > 600)
        return { status:'pending', reason:'recent_login_required' };
      // Read back the committed server state; a concurrent rejection must win.
      await store('PATCH',identity,row.browser_hash,{status:'approved',approved_at:new Date(now()).toISOString(),
        reason:'verified_recent_password_login'},true);
      row = await rowFor(req,identity); if (!row) return {status:'unverified'};
    }
    const permitted = row.status === 'approved' && Number.isFinite(Date.parse(row.approved_at));
    const decision = decideDeviceRegistration(permitted);
    return { status:decision.decision === 'allow' ? 'approved' : row.status === 'approved' ? 'unverified' : row.status };
  }
  async function request(req,identity,res) {
    const existing = await rowFor(req,identity);
    if (existing) return status(req,identity); // Never review or approve in POST.
    if (typeof res?.setHeader !== 'function') return fail();
    const raw = randomBytes(32).toString('base64url'), hash = createHash('sha256').update(raw).digest('hex');
    await store('POST',identity,hash,{browser_hash:hash,user_id:identity.userId,status:'pending',
      requested_at:new Date(now()).toISOString(),expires_at:new Date(now()+LIFETIME*1000).toISOString(),
      approved_at:null,reason:'requested'});
    res.setHeader('Set-Cookie',`${COOKIE}=${raw}; Max-Age=${LIFETIME}; Path=/; HttpOnly; Secure; SameSite=Strict`);
    return { status:'pending' };
  }
  return Object.freeze({status,request});
}
