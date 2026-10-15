import { createHash, randomBytes } from 'node:crypto';
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

// Browser cookie selects a server record; only a database operator may approve it.
// This registers a browser, not hardware, and is independent of login sessions.
export function createBrowserRegistration({ env = process.env, fetchImpl = globalThis.fetch,
  now = () => Date.now() } = {}) {
  async function store(method, identity, hash, body) {
    if (!['GET','POST'].includes(method)) return fail();
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY || !UUID.test(identity?.userId ?? '')) return fail();
    const base = new URL(env.SUPABASE_URL);
    if (base.protocol !== 'https:' || base.pathname !== '/' || base.username || base.password || base.search || base.hash) return fail();
    const url = new URL('/rest/v1/learning_browser_registrations', base);
    if (method !== 'POST') {
      url.searchParams.set('browser_hash', 'eq.' + hash);
      url.searchParams.set('user_id', 'eq.' + identity.userId);
      if (method === 'GET') url.searchParams.set('select', 'browser_hash,user_id,request_id,status,requested_at,expires_at,approved_at,reason,operator_reviewed_at');
    }
    const res = await fetchImpl(url, { method, cache:'no-store', redirect:'error', signal:AbortSignal.timeout(10000),
      headers:{apikey:env.SUPABASE_SECRET_KEY,'Content-Type':'application/json',Prefer:'return=representation'},
      body:body ? JSON.stringify(body) : undefined });
    if (!res.ok) {
      const error = await res.json().catch(() => null);
      if (res.status === 400 && error?.code === 'P0001' && error?.message === 'pending_request_limit')
        throw new Error('device_request_limit');
      return fail();
    }
    const rows = res.status === 204 ? [] : await res.json();
    if (!Array.isArray(rows) || rows.length > 1) return fail();
    return rows;
  }
  async function rowFor(req, identity) {
    if (identity?.kind !== 'student' || !UUID.test(identity.userId ?? '')) return fail();
    const hash = browserHash(req); if (!hash) return null;
    const [row] = await store('GET', identity, hash);
    if (!row) return null;
    if (!UUID.test(row.request_id ?? '') || row.browser_hash !== hash || row.user_id !== identity.userId
        || !['pending','approved','rejected'].includes(row.status)
        || !Number.isFinite(Date.parse(row.expires_at)) || !Number.isFinite(Date.parse(row.requested_at))) return fail();
    return Date.parse(row.expires_at) > now() ? row : null;
  }
  async function status(req, identity) {
    const row = await rowFor(req, identity);
    if (!row) return { status:'unverified' };
    const approved = Date.parse(row.approved_at), reviewed = Date.parse(row.operator_reviewed_at);
    const permitted = row.status === 'approved' && row.reason === 'operator_approved'
      && Number.isFinite(approved) && Number.isFinite(reviewed) && approved === reviewed
      && approved >= Date.parse(row.requested_at) && approved <= now();
    const decision = decideDeviceRegistration(permitted);
    return { status:decision.decision === 'allow' ? 'approved' : row.status === 'approved' ? 'unverified' : row.status, requestId:row.request_id };
  }
  async function request(req,identity,res) {
    const existing = await rowFor(req,identity);
    if (existing) return status(req,identity); // Never review or approve in POST.
    if (typeof res?.setHeader !== 'function') return fail();
    const raw = randomBytes(32).toString('base64url'), hash = createHash('sha256').update(raw).digest('hex');
    const [created] = await store('POST',identity,hash,{browser_hash:hash,user_id:identity.userId,requested_at:new Date(now()).toISOString(),expires_at:new Date(now()+LIFETIME*1000).toISOString()});
    if (!created || !UUID.test(created.request_id ?? '') || created.status !== 'pending'
      || created.user_id !== identity.userId || created.browser_hash !== hash) return fail();
    res.setHeader('Set-Cookie',`${COOKIE}=${raw}; Max-Age=${LIFETIME}; Path=/; HttpOnly; Secure; SameSite=Strict`);
    return { status:'pending', requestId:created.request_id };
  }
  return Object.freeze({status,request});
}
