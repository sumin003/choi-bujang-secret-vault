import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const USER='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',NOTE='11111111-1111-4111-8111-111111111111';

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
  let status = 'unverified', reads = 0, requests = 0, connected = true, authenticated = true;
  const fetch = async (path, init) => {
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.headers.Authorization, 'Bearer fixture-token');
    if (path === '/api/device') {
      if (!connected) return { ok: false, status: 503, json: async () => ({ error: 'DEVICE_REGISTRATION_NOT_CONNECTED' }) };
      if (init.method === 'POST') { assert.deepEqual(JSON.parse(init.body), { action: 'request' }); requests++; status = 'pending'; }
      return { ok: true, json: async () => ({ status, requestId: '11111111-1111-4111-8111-111111111111' }) };
    }
    assert.equal(path, '/api/notes'); assert.equal(status, 'approved'); reads++;
    return { ok: true, status: 200, json: async () => [{ id: NOTE, title: 'fixture title', body: 'fixture body' }] };
  };
  const originalSource = readFileSync(new URL('../public/auth.js', import.meta.url), 'utf8');
  const source = originalSource.replace("await import('https://esm.sh/@supabase/supabase-js@2.117.2')", 'fixtureSdk');
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.equal(/registerPasskey|PublicKeyCredential|navigator\.credentials|experimental.*passkey/.test(source), false);
  assert.equal(html.includes('register-device'), false);
  assert.match(html, /id="protected-vault" hidden/);
  const removed = [];
  const storage = { removeItem(key) { removed.push(key); }, getItem() { throw new Error('storage_read'); }, setItem() { throw new Error('token_persisted'); } };
  const windowEvents = new Map();
  const context = { localStorage: storage, sessionStorage: storage, document, fetch, navigator: { onLine: true }, window: { addEventListener(name,fn) { windowEvents.set(name,fn); } },
    location: { origin: 'https://fixture.invalid' }, URL, Headers,
    fixtureSdk: {createClient(_url,_key,config){assert.equal(config.auth.persistSession,false);return {auth:{
      onAuthStateChange(){},getSession:async()=>({data:{session:authenticated?{access_token:'fixture-token',user:{id:USER}}:null}}),
      signOut:async()=>{authenticated=false;return {}},
    }}}} };
  await vm.runInNewContext('(async()=>{' + source + '})()', context);
  assert.match(originalSource, /persistSession: false/);
  assert.doesNotMatch(originalSource, /localStorage\.setItem|sessionStorage\.setItem|indexedDB|document\.cookie/);
  assert.ok(removed.includes('sb-cysbomadvuwrqsteohuq-auth-token'));
  const flush = () => new Promise(resolve => setImmediate(resolve)); await flush();
  const vault = elements.get('#protected-vault'), list = elements.get('#notes');
  assert.equal(vault.hidden, true); assert.equal(reads, 0);
  await elements.get('#request-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(requests, 1); assert.equal(vault.hidden, true); assert.equal(reads, 0);
  assert.equal(html.includes('device-request-row'),false);
  assert.match(elements.get('#device-message').textContent,/요청 번호: 11111111-1111-4111-8111-111111111111/);
  status = 'approved'; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, false); assert.equal(reads, 1); assert.equal(list.children[0].children[0].textContent, 'fixture title');
  context.navigator.onLine = false; windowEvents.get('offline')();
  assert.equal(vault.hidden,true); assert.equal(reads,1);
  assert.match(elements.get('#connection-status').textContent,/오프라인에서는 볼 수 없습니다/);
  context.navigator.onLine = true; windowEvents.get('online')();
  status = 'rejected'; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, true); assert.equal(reads, 1); assert.match(list.children[0].textContent, /기기 승인 후/);
  connected = false; await elements.get('#check-device').listeners.get('click')(); await flush(); await flush();
  assert.equal(vault.hidden, true); assert.match(elements.get('#device-message').textContent, /아직 연결되지/);
  await elements.get('#logout-button').listeners.get('click')(); await flush(); assert.equal(vault.hidden, true);
  assert.equal(authenticated, false);
});
