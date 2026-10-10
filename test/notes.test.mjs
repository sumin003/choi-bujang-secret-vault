import assert from 'node:assert/strict';
import { test } from 'node:test';
import handler from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

test('notes API restricts methods and strips private fields and upstream errors', async () => {
  const originalFetch = globalThis.fetch;
  const savedUrl = process.env.SUPABASE_URL;
  const savedKey = process.env.SUPABASE_SECRET_KEY;
  let status, body;
  const headers = new Map();
  const res = { setHeader: (k, v) => headers.set(k, v), status: value => {
    status = value; return { json: value => { body = value; } };
  } };
  try {
    await handler({ method: 'POST' }, res);
    assert.equal(status, 405);
    assert.equal(headers.get('Allow'), 'GET');
    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SECRET_KEY;
    await handler({ method: 'GET' }, res);
    assert.equal(status, 503);
    process.env.SUPABASE_URL = 'https://example.supabase.co';
    process.env.SUPABASE_SECRET_KEY = 'test-only-placeholder';
    globalThis.fetch = async (url, init) => {
      assert.equal(url.searchParams.get('id'), 'in.(1,2,3,4)');
      assert.equal(init.headers.apikey, process.env.SUPABASE_SECRET_KEY);
      assert.equal(init.redirect, 'error');
      return Response.json([1, 2, 3, 4].map(id => ({ id, title: 'fixture', content: 'fixture', owner_id: 'private' })));
    };
    await handler({ method: 'GET' }, res);
    assert.equal(status, 200);
    assert.equal(body.notes.length, 4);
    assert.deepEqual(Object.keys(body.notes[0]), ['id', 'title', 'content']);
    assert.equal(headers.get('Cache-Control'), 'no-store');
    globalThis.fetch = async () => { throw new Error('upstream private details'); };
    await handler({ method: 'GET' }, res);
    assert.equal(status, 502);
    assert.deepEqual(body, { error: 'NOTES_UNAVAILABLE' });
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
