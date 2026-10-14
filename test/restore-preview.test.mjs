import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createRestorePreview, MAX_POLICY_BYTES } from '../src/restore-preview.mjs';
import { runRestorePreview } from '../scripts/restore-preview.mjs';

const version = '1234567890abcdef1234567890abcdef12345678';
const sha = value => createHash('sha256').update(value).digest('hex');
const snapshot = files => Buffer.from(JSON.stringify({ schema: 'aleph.policy.backup.v1', version, files }));
const preview = (backupBytes, trialFiles) => createRestorePreview({ backupBytes, trialFiles, verifiedSha256: sha(backupBytes) });

test('복원 버전과 파일별 변경 줄 범위를 실행 없이 표시한다', () => {
  const backup = snapshot([{ path: 'src/decider.mjs', content: 'same\ndeny unknown\nshared\nowner required\nend\n' }]);
  const trial = Buffer.from('same\nallow unknown\nshared\nowner optional\nend\n');
  const result = preview(backup, { 'src/decider.mjs': trial });
  assert.equal(result.restoreVersion, version);
  assert.equal(result.mode, 'preview_only');
  assert.equal(result.changes.length, 1);
  assert.equal(result.changes[0].path, 'src/decider.mjs');
  assert.equal(result.changes[0].operation, 'replace');
  assert.equal(result.changes[0].beforeSha256, sha(trial));
  assert.deepEqual(result.changes[0].ranges, [
    { trial: { startLine: 2, lineCount: 1 }, backup: { startLine: 2, lineCount: 1 } },
    { trial: { startLine: 4, lineCount: 1 }, backup: { startLine: 4, lineCount: 1 } },
  ]);
});

test('차이 없는 정책은 제외하고 누락 파일은 생성 예정만 표시한다', () => {
  const content = '{"rules":[]}\n';
  const backup = snapshot([{ path: 'src/decider.mjs', content: '' },
    { path: 'xdr/brute-force/deny-rules.json', content }]);
  const result = preview(backup, { 'src/decider.mjs': Buffer.from(''), 'xdr/brute-force/deny-rules.json': null });
  assert.deepEqual(result.changes, [{ path: 'xdr/brute-force/deny-rules.json', operation: 'create',
    beforeSha256: null, afterSha256: sha(content),
    ranges: [{ trial: { startLine: 1, lineCount: 0 }, backup: { startLine: 1, lineCount: 1 } }] }]);
});

test('검증 해시 누락·불일치면 복원 계획을 반환하지 않는다', () => {
  const backupBytes = snapshot([{ path: 'src/decider.mjs', content: 'deny\n' }]);
  const trialFiles = { 'src/decider.mjs': Buffer.from('allow\n') };
  assert.throws(() => createRestorePreview({ backupBytes, trialFiles }), /^Error: verified_hash_required$/);
  assert.throws(() => createRestorePreview({ backupBytes, trialFiles, verifiedSha256: sha('wrong') }),
    /^Error: backup_verification_failed$/);
});

test('검증된 형식에서도 알 수 없는 경로·중복·빈 사본·추가 필드는 거부한다', () => {
  for (const files of [[], [{ path: '../api/notes.js', content: 'allow' }],
    [{ path: '.env', content: 'private' }],
    [{ path: 'src/decider.mjs', content: 'a' }, { path: 'src/decider.mjs', content: 'b' }],
    [{ path: 'src/decider.mjs', content: 'a', token: 'synthetic-private-marker' }]]) {
    const backup = snapshot(files);
    assert.throws(() => preview(backup, {}), /^Error: backup_input_invalid$/);
  }
});

test('줄·용량·UTF-8 제한을 지키고 실제 정책 원문을 실행하거나 출력하지 않는다', () => {
  const backup = snapshot([{ path: 'src/decider.mjs', content: 'throw new Error("synthetic-private-marker");\n' }]);
  const trial = Buffer.from('throw new Error("another-private-marker");\n');
  const copy = Buffer.from(trial);
  const serialized = JSON.stringify(preview(backup, { 'src/decider.mjs': trial }));
  assert.equal(serialized.includes('private-marker'), false);
  assert.equal(serialized.includes('throw'), false);
  assert.deepEqual(trial, copy);
  assert.throws(() => preview(backup, { 'src/decider.mjs': Buffer.from([0xff]) }), /policy_input_invalid/);
  assert.throws(() => preview(backup, { 'src/decider.mjs': Buffer.alloc(MAX_POLICY_BYTES + 1) }), /policy_input_invalid/);
  assert.throws(() => preview(backup, { 'src/decider.mjs': Buffer.from('a\n'.repeat(2001)) }), /policy_input_too_large/);
});

test('검증된 사본도 복원 버전이 없거나 변조되면 중단한다', () => {
  const backup = snapshot([{ path: 'src/decider.mjs', content: 'deny' }]);
  const invalid = JSON.parse(backup);
  delete invalid.version;
  assert.throws(() => preview(Buffer.from(JSON.stringify(invalid)), {}), /backup_input_invalid/);
  const changed = Buffer.from(backup);
  changed[0] = '['.charCodeAt(0);
  assert.throws(() => createRestorePreview({ backupBytes: changed, verifiedSha256: sha(backup), trialFiles: {} }),
    /backup_verification_failed/);
});

test('CLI는 누락·검증 실패를 먼저 중단하고 성공 시 버전·범위만 출력하며 파일을 보존한다', async () => {
  const folder = await mkdtemp(join(tmpdir(), 'restore-preview-test-'));
  try {
    const backupPath = join(folder, 'safe.json');
    const trialDir = join(folder, 'trial');
    await mkdir(join(trialDir, 'src'), { recursive: true });
    const policyPath = join(trialDir, 'src/decider.mjs');
    const backup = snapshot([{ path: 'src/decider.mjs', content: 'deny unknown\n' },
      { path: 'src/detect.mjs', content: 'observe\n' }]);
    const trial = Buffer.from('allow unknown\n');
    await writeFile(backupPath, backup);
    await writeFile(policyPath, trial);
    await assert.rejects(runRestorePreview({ backupPath: join(folder, 'missing'), trialDir, verifiedSha256: sha(backup) }),
      /^Error: safe_backup_unavailable$/);
    await assert.rejects(runRestorePreview({ backupPath, trialDir: join(folder, 'missing'), verifiedSha256: sha('wrong') }),
      /^Error: backup_verification_failed$/);
    const command = fileURLToPath(new URL('../scripts/restore-preview.mjs', import.meta.url));
    const run = hash => spawnSync(process.execPath, [command, '--backup', backupPath,
      '--verified-sha256', hash, '--trial-dir', trialDir], { encoding: 'utf8' });
    const ok = run(sha(backup));
    assert.equal(ok.status, 0);
    assert.equal(ok.stderr, '');
    const result = JSON.parse(ok.stdout);
    assert.equal(result.restoreVersion, version);
    assert.deepEqual(result.changes.map(file => [file.path, file.operation]),
      [['src/decider.mjs', 'replace'], ['src/detect.mjs', 'create']]);
    const denied = run(sha('wrong'));
    assert.equal(denied.status, 1);
    assert.equal(denied.stdout, '');
    assert.deepEqual(JSON.parse(denied.stderr), { error: 'backup_verification_failed' });
    assert.equal(denied.stderr.includes(folder), false);
    assert.deepEqual(await readFile(backupPath), backup);
    assert.deepEqual(await readFile(policyPath), trial);
    assert.deepEqual(await readdir(join(trialDir, 'src')), ['decider.mjs']);
  } finally { await rm(folder, { recursive: true, force: true }); }
});
