import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createWebSessions, WEB_SESSION_SECONDS } from '../src/web-session.mjs';

const USER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const BASE_TIME = Date.parse('2026-10-15T09:00:00Z');
const env = { SUPABASE_URL: 'https://fixture.example.invalid', SUPABASE_SECRET_KEY: 'fixture-server-only' };
const credentials = { access_token: 'fixture-access', refresh_token: 'fixture-refresh', expires_at: BASE_TIME / 1000 + 3600 };
function fixture({ expiring = false } = {}) {
  const rows = new Map(); let clock = BASE_TIME, refreshed = 0, revoked = 0;
  const sdk = { auth: {
    signInWithPassword: async input => input.password === 'wrong' ? { error: { code: 'invalid_credentials', status: 400 } }
      : { data: { session: credentials, user: { id: USER } } },
    getUser: async () => ({ data: { user: { id: USER } } }),
    refreshSession: async ({ refresh_token }) => { assert.equal(refresh_token, credentials.refresh_token); refreshed++;
      return { data: { user: { id: USER }, session: { access_token: 'rotated-access', refresh_token: 'rotated-refresh', expires_at: clock / 1000 + 3600 } } }; },
    admin: { signOut: async (_token, scope) => { assert.equal(scope, 'local'); revoked++; return {}; } },
  } };
  const fetchImpl = async (url, init) => {
    assert.equal(url.pathname, '/rest/v1/learning_web_sessions'); assert.equal(init.headers.apikey, env.SUPABASE_SECRET_KEY);
    const hash = url.searchParams.get('session_hash')?.slice(3);
    let result = [];
    if (init.method === 'POST') { const row = JSON.parse(init.body); rows.set(row.session_hash, row); result = [row]; }
    if (init.method === 'GET') { const row = rows.get(hash); result = row ? [structuredClone(row)] : []; }
    if (init.method === 'DELETE') { const row = rows.get(hash); rows.delete(hash); result = row ? [row] : []; }
    if (init.method === 'PATCH') { const row = rows.get(hash);
      if (row && url.searchParams.get('version') === 'eq.' + row.version) { Object.assign(row, JSON.parse(init.body)); result = [structuredClone(row)]; } }
    return { ok: true, status: 200, json: async () => result };
  };
  const options = { env, fetchImpl, now: () => clock, makeClient: () => sdk };
  return { rows, sdk, options, sessions: createWebSessions(options), get refreshed() { return refreshed; },
    get revoked() { return revoked; }, advance(ms) { clock += ms; } };
}
const req = cookie => ({ headers: { cookie: cookie?.split(';')[0], origin: 'https://vault.example.com', host: 'vault.example.com' } });
const response = () => ({ code: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });

test('new server instance restores login from opaque cookie; tokens stay encrypted on server', async () => {
  const f = fixture(), cookie = await f.sessions.issue(credentials, USER);
  assert.match(cookie, /HttpOnly; Secure; SameSite=Strict/);
  assert.match(cookie, /Max-Age=604800/);
  assert.equal(cookie.includes(credentials.access_token), false); assert.equal(cookie.includes(credentials.refresh_token), false);
  const stored = JSON.stringify([...f.rows.values()]);
  assert.equal(stored.includes(credentials.access_token), false); assert.equal(stored.includes(credentials.refresh_token), false);
  assert.equal(stored.includes(cookie.split('=')[1].split(';')[0]), false);
  const restarted = createWebSessions(f.options);
  assert.equal(await restarted.authorization(req(cookie)), 'Bearer ' + credentials.access_token);
  assert.equal((await restarted.load(req(cookie))).row.user_id, USER);
  assert.equal(await restarted.authorization({ headers: { authorization: 'Bearer judge-fixture', cookie } }), 'Bearer judge-fixture');
  assert.equal(await restarted.authorization(req()), null);
});

test('logout, expiration, duplicate cookies and tampering do not restore a login', async () => {
  const f = fixture(), cookie = await f.sessions.issue(credentials, USER);
  const originalRow = structuredClone([...f.rows.values()][0]);
  assert.equal(await f.sessions.load({ headers: { cookie: req(cookie).headers.cookie + '; ' + req(cookie).headers.cookie } }), null);
  f.rows.get(originalRow.session_hash).user_id = OTHER;
  await assert.rejects(f.sessions.load(req(cookie)), /WEB_SESSION_UNAVAILABLE/);
  f.rows.set(originalRow.session_hash, originalRow);
  await f.sessions.revoke(req(cookie));
  assert.equal(await f.sessions.load(req(cookie)), null); assert.equal(f.revoked, 1);
  const second = await f.sessions.issue(credentials, USER);
  f.advance(WEB_SESSION_SECONDS * 1000 + 1);
  assert.equal(await f.sessions.load(req(second)), null); assert.equal(f.rows.size, 0);
});

test('near-expiry tokens rotate on server and concurrent requests share a refresh', async () => {
  const f = fixture(), cookie = await f.sessions.issue({ ...credentials, expires_at: BASE_TIME / 1000 + 30 }, USER);
  const values = await Promise.all([f.sessions.authorization(req(cookie)), f.sessions.authorization(req(cookie))]);
  assert.deepEqual(values, ['Bearer rotated-access', 'Bearer rotated-access']); assert.equal(f.refreshed, 1);
  assert.equal([...f.rows.values()][0].version, 2);
  assert.equal(JSON.stringify([...f.rows.values()]).includes('rotated-refresh'), false);
  assert.equal(await createWebSessions(f.options).authorization(req(cookie)), 'Bearer rotated-access');
});

async function authHandler(sessions) {
  const source = readFileSync(new URL('../api/auth.js', import.meta.url), 'utf8').replace(/^import [\s\S]*?;\n/gm, '');
  const url = new URL('../src/web-session.mjs', import.meta.url).href;
  const prelude = `import {createWebSessions,expiredWebCookie} from ${JSON.stringify(url)}; const enforceXdr=()=>true;\n`;
  const { createAuthHandler } = await import('data:text/javascript;base64,' + Buffer.from(prelude + source).toString('base64'));
  return createAuthHandler({ sessions });
}

test('login response contains no tokens; refreshed page stays authenticated; logout clears server record', async () => {
  const f = fixture(), handler = await authHandler(f.sessions);
  const call = async (action, cookie, body) => { const r = req(cookie); r.method = action === 'session' ? 'GET' : 'POST';
    r.query = { action }; r.headers['content-type'] = 'application/json'; r.body = body;
    const res = response(); await handler(r, res); return res; };
  const login = await call('login', undefined, { email: 'fixture-user', password: 'fixture-only' });
  assert.equal(login.code, 200); assert.deepEqual(login.body, { authenticated: true });
  const cookie = login.headers['Set-Cookie'];
  const reloadedHandler = await authHandler(createWebSessions(f.options));
  const reload = req(cookie); reload.method = 'GET'; reload.query = { action: 'session' };
  const restored = response(); await reloadedHandler(reload, restored);
  assert.deepEqual(restored.body, { authenticated: true });
  const loggedOut = await call('logout', cookie); assert.equal(loggedOut.code, 200);
  assert.match(loggedOut.headers['Set-Cookie'], /Max-Age=0/);
  assert.deepEqual((await call('session', cookie)).body, { authenticated: false });
  const denied = await call('login', undefined, { email: 'fixture-user', password: 'wrong' });
  assert.equal(denied.code, 401); assert.equal(denied.body.code, 'invalid_credentials');
});

test('login CSRF, legacy token responses and forged profile inputs are rejected', async () => {
  const f = fixture(), handler = await authHandler(f.sessions);
  for (const [action, body, origin, expected] of [
    ['login', { email: 'fixture', password: 'fixture-only' }, 'https://other.invalid', 403],
    ['login', { email: 'fixture', password: 'fixture-only', role: 'instructor' }, 'https://vault.example.com', 400],
    ['token', { email: 'fixture', password: 'fixture-only' }, 'https://vault.example.com', 400],
  ]) {
    const r = req(); r.method = 'POST'; r.query = { action }; r.body = body;
    r.headers.origin = origin; r.headers['content-type'] = 'application/json';
    const res = response(); await handler(r, res); assert.equal(res.code, expected);
    assert.equal(res.headers['Set-Cookie'], undefined);
  }
  assert.equal(f.rows.size, 0);
});

test('cookie restored login still passes the original note verifier and owner filter', async () => {
  const f = fixture(), cookie = await f.sessions.issue(credentials, USER);
  const source = readFileSync(new URL('../api/notes.js', import.meta.url), 'utf8').replace(/^import [\s\S]*?;\n/gm, '');
  const prelude = `const config={},enforceXdr=()=>true,randomUUID=()=>'';
    const resolveSessionAuthorization=req=>globalThis.__webNote.sessions.authorization(req);
    const createLoginVerifier=()=>async auth=>{if(auth!=='Bearer fixture-access')throw Error('invalid');return {kind:'student',userId:'${USER}'}};
    const enforceApprovedDevice=async()=>true,decideAuthenticatedResource=async()=>({decision:'allow'}),exposeResourceDecision=()=>{};\n`;
  const original = { fetch:globalThis.fetch,url:process.env.SUPABASE_URL,key:process.env.SUPABASE_SECRET_KEY };
  let reads=0;
  globalThis.__webNote={sessions:createWebSessions(f.options)};
  process.env.SUPABASE_URL=env.SUPABASE_URL;process.env.SUPABASE_SECRET_KEY=env.SUPABASE_SECRET_KEY;
  globalThis.fetch=async url=>{assert.equal(url.searchParams.get('owner_id'),'eq.'+USER);reads++;return {ok:true,json:async()=>[]};};
  try {
    const {handleNotes}=await import('data:text/javascript;base64,'+Buffer.from(prelude+source).toString('base64'));
    const call=async value=>{const r=req(value);r.method='GET';r.url='/api/notes';const res=response();await handleNotes(r,res,null);return res;};
    assert.equal((await call(cookie)).code,200);assert.equal(reads,1);
    await f.sessions.revoke(req(cookie));
    assert.equal((await call(cookie)).code,401);assert.equal(reads,1);
  } finally {
    globalThis.fetch=original.fetch;delete globalThis.__webNote;
    for(const [name,value] of [['SUPABASE_URL',original.url],['SUPABASE_SECRET_KEY',original.key]]) {
      if(value===undefined)delete process.env[name];else process.env[name]=value;
    }
  }
});
