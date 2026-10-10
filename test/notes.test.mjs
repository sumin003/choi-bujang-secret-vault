import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

test('notes API rejects missing or invalid tokens without reading notes', async () => {
  const originalFetch = globalThis.fetch;
  const savedUrl = process.env.SUPABASE_URL;
  const savedKey = process.env.SUPABASE_SECRET_KEY;
  let status, body, requests = 0;
  const headers = new Map();
  const res = { setHeader: (k, v) => headers.set(k, v), status: value => {
    status = value; return { json: value => { body = value; } };
  } };
  try {
    process.env.SUPABASE_URL = 'https://cysbomadvuwrqsteohuq.supabase.co';
    process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
    globalThis.fetch = async () => { requests++; throw new Error('unexpected request'); };
    await handler({ method: 'DELETE' }, res);
    assert.equal(status, 405);
    for (const authorization of [undefined, 'invalid', 'Bearer invalid']) {
      await handler({ method: 'GET', headers: { authorization },
        query: { userId: 'untrusted', role: 'admin' },
        body: { userId: 'untrusted', role: 'admin' } }, res);
      assert.equal(status, 401);
      assert.deepEqual(body, { error: 'LOGIN_REQUIRED' });
      assert.equal(requests, 0);
    }
    assert.equal(headers.get('Cache-Control'), 'no-store');
  } finally {
    globalThis.fetch = originalFetch;
    if (savedUrl === undefined) delete process.env.SUPABASE_URL; else process.env.SUPABASE_URL = savedUrl;
    if (savedKey === undefined) delete process.env.SUPABASE_SECRET_KEY; else process.env.SUPABASE_SECRET_KEY = savedKey;
  }
});

test('identity retains configured stage after stage 1 and rejects invalid stages', () => {
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'sumin003',
    VERCEL_GIT_REPO_SLUG: 'choi-bujang-secret-vault', VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
    VERCEL_URL: 'vault-test.vercel.app' };
  const config = { judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge', sampleMarker: 'SAMPLE_NOTE_1' };
  for (const step of [1, 2, 3, 9]) assert.equal(deploymentIdentity(env, { ...config, step }).step, step);
  for (const step of [0, -1, 2.5, '2']) assert.throws(() => deploymentIdentity(env, { ...config, step }));
});
