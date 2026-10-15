import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { createDeviceApprovalService, checkApprovedDevice, enforceApprovedDevice } from '../src/device-approval.mjs';
import { decideDeviceRegistration, RULE_IDS } from '../src/decider.mjs';

const USER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const DEVICE = '0123456789abcdef', OTHER_DEVICE = 'fedcba9876543210';
const NOTE = '11111111-1111-4111-8111-111111111111';
const identity = { kind: 'student', userId: USER };
const response = () => ({ code: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; }, end() { return this; } });
const request = (method = 'GET', body, session = 'first-login') => ({ method, url: '/api/device',
  headers: { authorization: 'Bearer ' + session, origin: 'https://vault.example.com',
    host: 'vault.example.com', 'content-type': 'application/json' }, body });
const moduleUrl = new URL('../src/device-approval.mjs', import.meta.url).href;
async function deviceHandler(extra) {
  const source = readFileSync(new URL('../api/device.js', import.meta.url), 'utf8').replace(/^import [\s\S]*?;\n/gm, '');
  const prelude = `import {readDeviceApproval,requestDeviceApproval} from ${JSON.stringify(moduleUrl)};\nconst config={},createLoginVerifier=()=>()=>null;\n`;
  const { createDeviceHandler } = await import('data:text/javascript;base64,' + Buffer.from(prelude + source).toString('base64'));
  return createDeviceHandler({ verify: async () => identity, ...extra });
}
function simulatedEngine() {
  // Test-only authenticated engine adapter, not a deployed enrollment service.
  const records = new Map(); let activeDevice = DEVICE, requests = 0;
  const key = user => user.userId + ':' + activeDevice;
  const provider = {
    async readVerifiedRegistration(_req, user) { return { deviceId: activeDevice,
      deviceRegistered: records.get(key(user)) === 'approved' }; },
    async readApprovalStatus(_deviceId, user) { return records.get(key(user)) ?? 'unverified'; },
    async requestApproval(_deviceId, user) { requests++; records.set(key(user), 'pending'); return { status: 'pending' }; },
  };
  return { provider, service: createDeviceApprovalService({ provider }),
    review(status) { records.set(USER + ':' + DEVICE, status); },
    useOtherDevice() { activeDevice = OTHER_DEVICE; }, get requests() { return requests; } };
}

test('same verified device keeps approval across logins; another device/user is not approved', async () => {
  const engine = simulatedEngine(), handler = await deviceHandler({ approvalService: engine.service });
  const call = async (method, body, session) => { const res = response(); await handler(request(method, body, session), res); return res; };
  assert.deepEqual((await call('GET')).body, { status: 'unverified' });
  for (const body of [{ action: 'request', status: 'approved' }, { action: 'request', owner_id: OTHER },
    { action: 'request', deviceRegistered: true }, { action: 'approve' }]) assert.equal((await call('POST', body)).code, 400);
  assert.deepEqual((await call('POST', { action: 'request' })).body, { status: 'pending' });
  assert.equal(await checkApprovedDevice(request(), identity, { approvalService: engine.service }), 'required');
  engine.review('approved');
  assert.equal((await call('GET')).body.status, 'approved');
  assert.equal((await call('GET', undefined, 'second-login')).body.status, 'approved');
  assert.equal((await call('POST', { action: 'request' }, 'second-login')).body.status, 'approved');
  assert.equal(engine.requests, 1); // No new review caused by login/session change.
  assert.equal(await checkApprovedDevice(request(), { kind: 'student', userId: OTHER }, { approvalService: engine.service }), 'required');
  engine.useOtherDevice(); assert.equal((await call('GET')).body.status, 'unverified');
});

test('unconfigured transport and forged browser claims never become verified registration', async () => {
  const fake = request(); Object.assign(fake.headers, { 'x-device-id': DEVICE,
    'x-device-registered': 'true', cookie: '__Host-vault_device=v2.fake' });
  fake.deviceRegistered = true; fake.deviceId = DEVICE;
  const res = response(); assert.equal(await enforceApprovedDevice(fake, res, identity), false);
  assert.equal(res.code, 503); assert.deepEqual(res.body, { error: 'DEVICE_REGISTRATION_NOT_CONNECTED' });
  assert.equal(res.headers['X-Device-Decision'], 'deny');
  const handler = await deviceHandler({});
  const status = response(); await handler(fake, status); assert.equal(status.code, 503);
  const requested = response(); await handler(request('POST', { action: 'request' }), requested);
  assert.equal(requested.code, 503); assert.match(requested.headers['Set-Cookie'], /Max-Age=0/);
  for (const value of [false, undefined, 'true', 1, {}]) assert.equal(decideDeviceRegistration(value).decision, 'deny');
  assert.ok(decideDeviceRegistration(true).ruleIds.every(id => RULE_IDS.includes(id)));
});

test('login failure, invalid engine context and a request that grants approval are rejected', async () => {
  const anon = await deviceHandler({ verify: async () => null });
  const res = response(); await anon(request('POST', { action: 'request' }), res); assert.equal(res.code, 401);
  const invalid = createDeviceApprovalService({ provider: { readVerifiedRegistration: async () => ({ deviceId: USER, deviceRegistered: true }) } });
  assert.equal(await checkApprovedDevice(request(), identity, { approvalService: invalid }), 'unavailable');
  const autoApprove = createDeviceApprovalService({ provider: {
    readVerifiedRegistration: async () => ({ deviceId: DEVICE, deviceRegistered: false }),
    requestApproval: async () => ({ status: 'approved' }) } });
  await assert.rejects(autoApprove.request(request(), identity), /device_registration_not_connected/);
  const cross = request('POST', { action: 'request' }); cross.headers.origin = 'https://other.invalid';
  const handler = await deviceHandler({}); const denied = response(); await handler(cross, denied); assert.equal(denied.code, 403);
});

test('actual note handler: unregistered denied, registered own read allowed, revocation denied', async () => {
  const engine = simulatedEngine();
  const source = readFileSync(new URL('../api/notes.js', import.meta.url), 'utf8').replace(/^import [\s\S]*?;\n/gm, '');
  const prelude = `import {enforceApprovedDevice as enforce} from ${JSON.stringify(moduleUrl)};\nconst config={},enforceXdr=()=>true,randomUUID=()=>'',createLoginVerifier=()=>globalThis.__deviceTest.verify;\nconst enforceApprovedDevice=(req,res,user)=>enforce(req,res,user,{approvalService:globalThis.__deviceTest.service});\nconst decideAuthenticatedResource=async()=>({decision:'allow'}),exposeResourceDecision=()=>{};\n`;
  let reads = 0;
  const original = { fetch: globalThis.fetch, url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY };
  globalThis.__deviceTest = { verify: async () => identity, service: engine.service };
  process.env.SUPABASE_URL = 'https://fixture.example.invalid'; process.env.SUPABASE_SECRET_KEY = 'fixture-only';
  globalThis.fetch = async endpoint => { assert.equal(endpoint.searchParams.get('owner_id'), 'eq.' + USER); reads++;
    return { ok: true, json: async () => [{ id: NOTE, title: 'fixture title', body: 'fixture body', owner_id: USER }] }; };
  try {
    const { handleNotes } = await import('data:text/javascript;base64,' + Buffer.from(prelude + source).toString('base64'));
    const call = async () => { const req = request(); req.url = '/api/notes'; const res = response(); await handleNotes(req, res, null); return res; };
    assert.equal((await call()).code, 403); assert.equal(reads, 0);
    engine.review('approved'); const allowed = await call(); assert.equal(allowed.code, 200);
    assert.deepEqual(allowed.body, [{ id: NOTE, title: 'fixture title', body: 'fixture body' }]); assert.equal(reads, 1);
    assert.equal(allowed.headers['X-Device-Decision'], 'allow');
    engine.review('rejected'); assert.equal((await call()).code, 403); assert.equal(reads, 1);
  } finally {
    globalThis.fetch = original.fetch; delete globalThis.__deviceTest;
    if (original.url === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = original.url;
    if (original.key === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = original.key;
  }
});

test('screen requests pending, checks approval and clears protected data on logout without a key prompt', async () => {
  const elements = new Map();
  class Element {
    hidden = false; textContent = ''; value = ''; children = []; listeners = new Map();
    addEventListener(type, fn) { this.listeners.set(type, fn); }
    replaceChildren(...v) { this.children = v; } append(...v) { this.children.push(...v); }
    reset() {} focus() {}
  }
  const document = { querySelector(selector) { if (!elements.has(selector)) elements.set(selector, new Element()); return elements.get(selector); },
    createElement() { return new Element(); } };
  let status = 'unverified', reads = 0, requests = 0, authChanged, connected = true;
  const session = { user: { id: USER }, access_token: 'example-token' };
  const client = { auth: { onAuthStateChange(callback) { authChanged = callback; }, getSession: async () => ({ data: { session } }) } };
  const fetch = async (path, init) => {
    if (path === '/api/device') {
      if (!connected) return { ok: false, status: 503, json: async () => ({ error: 'DEVICE_REGISTRATION_NOT_CONNECTED' }) };
      if (init.method === 'POST') { assert.deepEqual(JSON.parse(init.body), { action: 'request' }); requests++; status = 'pending'; }
      return { ok: true, json: async () => ({ status, requestId: '1'.repeat(64) }) };
    }
    assert.equal(path, '/api/notes'); assert.equal(status, 'approved'); reads++;
    return { ok: true, status: 200, json: async () => [{ id: NOTE, title: 'fixture title', body: 'fixture body' }] };
  };
  const source = readFileSync(new URL('../public/auth.js', import.meta.url), 'utf8');
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.equal(/registerPasskey|PublicKeyCredential|navigator\.credentials|experimental.*passkey/.test(source), false);
  assert.equal(html.includes('register-device'), false);
  assert.match(html, /id="protected-vault" hidden/);
  const removed = [];
  const storage = { removeItem(key) { removed.push(key); }, getItem() { throw new Error('storage_read'); }, setItem() { throw new Error('token_persisted'); } };
  let sdkOptions;
  const context = { localStorage: storage, sessionStorage: storage, document, fetch, navigator: { onLine: true }, window: { addEventListener() {} },
    location: { origin: 'https://fixture.invalid' }, URL, Headers, sdk: { createClient: (_url, _key, options) => { sdkOptions = options; return client; } } };
  await vm.runInNewContext('(async()=>{' + source.replace("await import('https://esm.sh/@supabase/supabase-js@2.117.2')", 'globalThis.sdk') + '})()', context);
  assert.equal(sdkOptions.auth.persistSession, false);
  assert.equal(sdkOptions.auth.detectSessionInUrl, false);
  assert.ok(removed.includes('sb-cysbomadvuwrqsteohuq-auth-token'));
  const flush = () => new Promise(resolve => setImmediate(resolve)); await flush();
  const vault = elements.get('#protected-vault'), list = elements.get('#notes');
  assert.equal(vault.hidden, true); assert.equal(reads, 0);
  await elements.get('#request-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(requests, 1); assert.equal(vault.hidden, true); assert.equal(reads, 0);
  status = 'approved'; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, false); assert.equal(reads, 1); assert.equal(list.children[0].children[0].textContent, 'fixture title');
  status = 'rejected'; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, true); assert.equal(reads, 1); assert.match(list.children[0].textContent, /기기 승인 후/);
  connected = false; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, true); assert.match(elements.get('#device-message').textContent, /아직 연결되지/);
  authChanged('SIGNED_OUT', null); await flush(); assert.equal(vault.hidden, true);
});
