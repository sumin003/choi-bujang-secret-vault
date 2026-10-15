import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { checkApprovedDevice, credentialHash, enforceApprovedDevice, makeDeviceCookie } from '../src/device-approval.mjs';

const USER = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const KEY = 'AQIDBAUGBwgJCgsMDQ4PEA';
const HASH = credentialHash(KEY);
const SECRET = 'fixture-server-secret';
const SUPABASE_URL = 'https://fixture.example.invalid';
const token = 'Bearer example-token';
const identity = { kind: 'student', userId: USER };
const response = () => ({ code: 200, headers: {}, setHeader(k, v) { this.headers[k] = v; },
  status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } });
const request = (method = 'GET', body, cookie = '') => ({ method, url: '/api/device',
  headers: { authorization: token, cookie, origin: 'https://vault.example.com',
    host: 'vault.example.com', 'content-type': 'application/json' }, body });

test('an approval button and a forged cookie cannot reveal data; approval revocation takes effect', async () => {
  let status = 'approved', lookups = 0;
  const fetchImpl = async (_endpoint, options) => {
    lookups++;
    assert.equal(options.headers.apikey, SECRET);
    return { ok: true, json: async () => [{ credential_hash: HASH, status }] };
  };
  const options = { secret: SECRET, url: SUPABASE_URL, fetchImpl, now: 1_000_000 };
  const bare = request();
  assert.equal(await checkApprovedDevice(bare, identity, options), 'required');
  assert.equal(lookups, 0);
  const denied = response();
  assert.equal(await enforceApprovedDevice(bare, denied, identity, options), false);
  assert.equal(denied.code, 403);
  assert.deepEqual(denied.body, { error: 'DEVICE_APPROVAL_REQUIRED' });
  const cookie = makeDeviceCookie({ authorization: token, userId: USER, hash: HASH, secret: SECRET, now: options.now }).split(';')[0];
  assert.equal(await checkApprovedDevice(request('GET', null, cookie), identity, options), 'approved');
  assert.equal(await checkApprovedDevice(request('GET', null, cookie.replace(/.$/, 'X')), identity, options), 'required');
  assert.equal(await checkApprovedDevice(request('GET', null, cookie), { kind: 'student', userId: OTHER }, options), 'required');
  status = 'rejected';
  assert.equal(await checkApprovedDevice(request('GET', null, cookie), identity, options), 'required');
  assert.equal(await checkApprovedDevice(request('GET', null, cookie), identity, { ...options, now: options.now + 301000 }), 'required');
});

test('only a Supabase-verified, device-bound assertion creates pending; review plus new proof unlocks', async () => {
  const source = readFileSync(new URL('../api/device.js', import.meta.url), 'utf8')
    .replace(/^import [\s\S]*?;\n/gm, '');
  const moduleUrl = new URL('../src/device-approval.mjs', import.meta.url).href;
  const prelude = `import { checkApprovedDevice, credentialHash, deviceRecord, makeDeviceCookie, requestDeviceApproval } from ${JSON.stringify(moduleUrl)};\nconst config={},createLoginVerifier=()=>()=>null;\n`;
  const { createDeviceHandler } = await import('data:text/javascript;base64,' + Buffer.from(prelude + source).toString('base64'));
  let status = null, writes = 0;
  const fetchImpl = async (endpoint, options) => {
    if (endpoint.pathname.endsWith('/authentication/options'))
      return { ok: true, json: async () => ({ challenge_id: USER, options: { challenge: 'AQIDBA' } }) };
    if (endpoint.pathname.endsWith('/authentication/verify'))
      return { ok: true, json: async () => ({ access_token: 'proof-from-auth' }) };
    if (endpoint.pathname.endsWith('/learning_device_approvals')) {
      if (options.method === 'POST') {
        const body = JSON.parse(options.body);
        assert.deepEqual(body, { user_id: USER, credential_hash: HASH, status: 'pending' });
        writes++;
        status = 'pending';
        return { ok: true, status: 201 };
      }
      return { ok: true, json: async () => status ? [{ credential_hash: HASH, status }] : [] };
    }
    throw new Error('unexpected endpoint');
  };
  const handler = createDeviceHandler({ verify: async value => value === 'Bearer proof-from-auth'
    ? identity : identity, fetchImpl, secret: SECRET, url: SUPABASE_URL });
  const call = async (method, body, cookie = '') => {
    const res = response();
    await handler(request(method, body, cookie), res);
    return res;
  };
  assert.deepEqual((await call('GET')).body, { status: 'unverified' });
  assert.equal((await call('POST', { action: 'verify', status: 'approved' })).code, 400);
  const started = await call('POST', { action: 'start' });
  assert.equal(started.code, 200);
  const flags = Buffer.alloc(37);
  flags[32] = 0x04;
  const credential = { id: KEY, rawId: KEY, type: 'public-key', response: {
    authenticatorData: flags.toString('base64url'), clientDataJSON: 'AQID', signature: 'AQID',
  } };
  const input = { action: 'verify', challengeId: started.body.challengeId, credential };
  const first = await call('POST', input);
  assert.equal(first.body.status, 'pending');
  assert.equal(first.headers['Set-Cookie'], undefined);
  assert.equal(writes, 1);
  flags[32] = 0x0c;
  const backedUp = await call('POST', { ...input, credential: { ...credential,
    response: { ...credential.response, authenticatorData: flags.toString('base64url') } } });
  assert.equal(backedUp.code, 403);
  assert.equal(writes, 1);
  status = 'approved';
  const approved = await call('POST', input);
  assert.equal(approved.body.status, 'approved');
  assert.match(approved.headers['Set-Cookie'], /HttpOnly; Secure; SameSite=Strict/);
  const cookie = approved.headers['Set-Cookie'].split(';')[0];
  assert.deepEqual((await call('GET', undefined, cookie)).body, { status: 'approved' });
  status = 'rejected';
  assert.deepEqual((await call('GET', undefined, cookie)).body, { status: 'unverified' });
});
