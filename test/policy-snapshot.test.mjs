import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { previewSafePolicy, SAFE_POLICY_COMMIT, SNAPSHOT_PATH, verifySafePolicySnapshot } from '../scripts/policy-snapshot.mjs';

test('기본 안전 정책 사본을 다시 검증하고 변경 경로만 미리보기한다', async () => {
  const verified = verifySafePolicySnapshot();
  const result = previewSafePolicy();
  assert.equal(verified.snapshot.commit, SAFE_POLICY_COMMIT);
  assert.equal(result.mode, 'preview_only');
  assert.equal(result.restoreVersion, SAFE_POLICY_COMMIT);
  assert.match(result.verification, /historical file hashes/);
  assert.ok(Array.isArray(result.changes));
  assert.ok(result.changes.every(group => group.changes.every(change => change.path && change.currentSha256)));
  assert.equal(JSON.stringify(result).includes('content'), false);
  assert.ok((await readFile(new URL(`../${SNAPSHOT_PATH}`, import.meta.url))).byteLength < 64 * 1024);
});

test('안전 사본이 없거나 변조되면 변경 범위를 표시하지 않고 중단한다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'policy-snapshot-'));
  try {
    const missing = join(dir, 'missing.json');
    assert.throws(() => verifySafePolicySnapshot({ snapshotPath: missing }), /safe_policy_snapshot_missing/);
    const original = JSON.parse(await readFile(new URL(`../${SNAPSHOT_PATH}`, import.meta.url), 'utf8'));
    original.files['src/decider.mjs'] = '0'.repeat(64);
    const tampered = join(dir, 'tampered.json');
    await writeFile(tampered, JSON.stringify(original));
    assert.throws(() => previewSafePolicy({ snapshotPath: tampered }), /safe_policy_snapshot_hash_mismatch/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
