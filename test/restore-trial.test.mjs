import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir, symlink, link } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { runRestorePreview, applyTrialRestore } from '../src/restore-workflow.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const version = '1234567890abcdef1234567890abcdef12345678';

async function fixture(t, { missing = false } = {}) {
  const folder = await mkdtemp(join(tmpdir(), 'restore-trial-test-'));
  t.after(() => rm(folder, { recursive: true, force: true }));
  const trialDir = join(folder, 'trial');
  await mkdir(join(trialDir, 'src'), { recursive: true });
  await mkdir(join(trialDir, 'xdr'), { recursive: true });
  await writeFile(join(trialDir, 'trial-policy.json'), JSON.stringify({ schema: 'aleph.trial.policy.v1', purpose: 'isolated_test' }));
  const content = 'service-a deny\nseparator\nservice-b deny\n';
  const trial = 'service-a allow\nseparator\nservice-b allow\n';
  const backupBytes = Buffer.from(JSON.stringify({ schema: 'aleph.policy.backup.v1', version,
    verifiedAt: '2026-10-01T00:00:00.000Z', incidentAt: '2026-10-13T00:00:00.000Z',
    files: [{ path: 'src/decider.mjs', content }] }));
  const backupPath = join(folder, 'safe.json');
  await writeFile(backupPath, backupBytes);
  const policyPath = join(trialDir, 'src/decider.mjs');
  if (!missing) await writeFile(policyPath, trial);
  const auditPath = join(trialDir, 'restore-audit.jsonl');
  const oldAudit = '{"earlier":"retain"}\n';
  await writeFile(auditPath, oldAudit);
  const otherPath = join(trialDir, 'xdr/alerts.log');
  const otherContent = 'old audit history\n';
  await writeFile(otherPath, otherContent);
  const options = { backupPath, trialDir, verifiedSha256: sha(backupBytes) };
  return { folder, trialDir, content, trial, policyPath, backupBytes, backupPath,
    auditPath, oldAudit, otherPath, otherContent, options };
}

test('표시한 선택 항목만 복원하고 같은 파일의 다른 서비스 규칙과 감사 이력을 보존한다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  assert.equal(plan.restoreVersion, version);
  assert.deepEqual(plan.items.map(item => item.id), ['c0r0', 'c0r1']);
  const result = await applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] });
  assert.equal(result.status, 'restored_selected_items');
  assert.equal(await readFile(f.policyPath, 'utf8'), 'service-a deny\nseparator\nservice-b allow\n');
  assert.equal(await readFile(f.otherPath, 'utf8'), f.otherContent);
  assert.deepEqual(await readFile(f.backupPath), f.backupBytes);
  const audit = await readFile(f.auditPath, 'utf8');
  assert.ok(audit.startsWith(f.oldAudit));
  assert.deepEqual(audit.trim().split('\n').slice(1).map(line => JSON.parse(line).status), ['started', 'completed']);
  assert.equal(audit.includes('service-a deny'), false);
  assert.equal(audit.includes('service-b allow'), false);
  assert.deepEqual((await readdir(join(f.trialDir, 'src'))).sort(), ['decider.mjs']);
  assert.equal((await readdir(f.trialDir)).includes('.restore.lock'), false);
});

test('한 파일의 확인한 항목을 모두 선택하면 검증된 내용으로 돌아온다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  const result = await applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken,
    itemIds: plan.items.map(item => item.id) });
  assert.equal(await readFile(f.policyPath, 'utf8'), f.content);
  assert.equal(result.afterSha256, sha(f.content));
  assert.equal((await runRestorePreview(f.options)).changes.length, 0);
});

test('승인 없음·선택 없음·알 수 없는 항목이면 정책과 감사 이력을 바꾸지 않는다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  await assert.rejects(applyTrialRestore({ ...f.options, itemIds: ['c0r0'] }), /restore_approval_required/);
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: [] }), /restore_items_required/);
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c9r9'] }), /restore_items_invalid/);
  assert.equal(await readFile(f.policyPath, 'utf8'), f.trial);
  assert.equal(await readFile(f.auditPath, 'utf8'), f.oldAudit);
});

test('확인 후 정책 변경이나 사본 변조가 있으면 기존 승인으로 복원하지 않는다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  await writeFile(f.policyPath, 'a later edit\n');
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /restore_plan_changed/);
  assert.equal(await readFile(f.policyPath, 'utf8'), 'a later edit\n');
  await writeFile(f.backupPath, '{}');
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /backup_verification_failed/);
  assert.equal(await readFile(f.auditPath, 'utf8'), f.oldAudit);
});

test('시험용 표시가 없으면 실행하지 않는다', async t => {
  const f = await fixture(t);
  await rm(join(f.trialDir, 'trial-policy.json'));
  const plan = await runRestorePreview(f.options);
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /trial_marker_required/);
  assert.equal(await readFile(f.policyPath, 'utf8'), f.trial);
  assert.equal(await readFile(f.auditPath, 'utf8'), f.oldAudit);
});

test('없는 시험 정책은 확인 후 생성하며 다른 파일은 보존한다', async t => {
  const f = await fixture(t, { missing: true });
  const plan = await runRestorePreview(f.options);
  assert.equal(plan.items[0].operation, 'create');
  await applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: [plan.items[0].id] });
  assert.equal(await readFile(f.policyPath, 'utf8'), f.content);
  assert.equal(await readFile(f.otherPath, 'utf8'), f.otherContent);
});

test('감사 기록을 쓸 수 없으면 정책을 바꾸지 않고 중단한다', async t => {
  const f = await fixture(t);
  await rm(f.auditPath);
  await mkdir(f.auditPath);
  const plan = await runRestorePreview(f.options);
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /restore_audit_unavailable/);
  assert.equal(await readFile(f.policyPath, 'utf8'), f.trial);
  assert.deepEqual(await readdir(join(f.trialDir, 'src')), ['decider.mjs']);
});

test('다른 폴더의 승인을 재사용할 수 없고 심볼릭 링크로 외부 정책을 쓰지 않는다', async t => {
  const f = await fixture(t);
  const g = await fixture(t);
  const plan = await runRestorePreview(f.options);
  await assert.rejects(applyTrialRestore({ ...g.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /restore_plan_changed/);
  await rm(join(f.trialDir, 'src'), { recursive: true });
  await symlink(join(g.trialDir, 'src'), join(f.trialDir, 'src'), 'dir');
  await assert.rejects(runRestorePreview(f.options), /trial_policy_unavailable/);
  assert.equal(await readFile(g.policyPath, 'utf8'), g.trial);
});

test('CLI 시험 복원은 확인한 승인값과 항목이 필요하며 이전 감사 이력을 보존한다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  const command = fileURLToPath(new URL('../scripts/restore-trial.mjs', import.meta.url));
  const run = token => spawnSync(process.execPath, [command, '--backup', f.backupPath,
    '--verified-sha256', f.options.verifiedSha256, '--trial-dir', f.trialDir,
    '--approve', token, '--items', 'c0r0'], { encoding: 'utf8' });
  const denied = run('0'.repeat(64));
  assert.equal(denied.status, 1);
  assert.equal(denied.stdout, '');
  assert.deepEqual(JSON.parse(denied.stderr), { error: 'restore_plan_changed' });
  assert.equal(denied.stderr.includes(f.folder), false);
  const ok = run(plan.approvalToken);
  assert.equal(ok.status, 0);
  assert.equal(ok.stderr, '');
  assert.equal(JSON.parse(ok.stdout).status, 'restored_selected_items');
  assert.equal(await readFile(f.policyPath, 'utf8'), 'service-a deny\nseparator\nservice-b allow\n');
  assert.ok((await readFile(f.auditPath, 'utf8')).startsWith(f.oldAudit));
});

test('감사 파일이 다른 이력과 하드 링크로 연결돼 있으면 양쪽 이력을 보존하고 중단한다', async t => {
  const f = await fixture(t);
  const external = join(f.folder, 'other-audit.jsonl');
  await link(f.auditPath, external);
  const plan = await runRestorePreview(f.options);
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /restore_audit_unavailable/);
  assert.equal(await readFile(f.auditPath, 'utf8'), f.oldAudit);
  assert.equal(await readFile(external, 'utf8'), f.oldAudit);
  assert.equal(await readFile(f.policyPath, 'utf8'), f.trial);
});

test('실제 프로젝트 폴더를 복원 대상으로 지정하면 정책을 쓰기 전에 거부한다', async t => {
  const f = await fixture(t);
  const trialDir = fileURLToPath(new URL('../', import.meta.url));
  const path = join(trialDir, 'src/decider.mjs');
  const original = await readFile(path);
  const options = { ...f.options, trialDir };
  const plan = await runRestorePreview(options);
  await assert.rejects(applyTrialRestore({ ...options, approvalToken: plan.approvalToken, itemIds: [plan.items[0].id] }),
    /operating_policy_protected/);
  assert.deepEqual(await readFile(path), original);
});

test('다른 복원의 잠금 파일을 지우지 않고 중단한다', async t => {
  const f = await fixture(t);
  const plan = await runRestorePreview(f.options);
  const lock = join(f.trialDir, '.restore.lock');
  await writeFile(lock, 'another operation');
  await assert.rejects(applyTrialRestore({ ...f.options, approvalToken: plan.approvalToken, itemIds: ['c0r0'] }), /restore_locked/);
  assert.equal(await readFile(lock, 'utf8'), 'another operation');
  assert.equal(await readFile(f.policyPath, 'utf8'), f.trial);
  assert.equal(await readFile(f.auditPath, 'utf8'), f.oldAudit);
});

test('시험 소유권 규칙을 훼손했다가 복원하면 B의 A 자료를 다시 거부하고 A 정상 요청은 유지한다', async t => {
  const f = await fixture(t);
  // Only synthetic copies are modified. This is not a pre-incident backup claim.
  const safeSource = await readFile(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  const corrupted = safeSource.replace('NOTE_OWNERS[id]===request.subjectId', 'true');
  assert.notEqual(corrupted, safeSource);
  const backup = Buffer.from(JSON.stringify({ schema: 'aleph.policy.backup.v1', version,
    verifiedAt: '2026-10-01T00:00:00.000Z', incidentAt: '2026-10-13T00:00:00.000Z',
    files: [{ path: 'src/decider.mjs', content: safeSource }] }));
  await writeFile(f.backupPath, backup);
  await writeFile(f.policyPath, corrupted);
  const options = { ...f.options, verifiedSha256: sha(backup) };
  const fromSource = async source => import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
  const own = method => ({ ...fixtureRequests().normal, method, route: method + ' /notes/:id' });
  const other = method => ({ ...own(method), subjectId: 'other_learner_fixture' });
  const broken = await fromSource(corrupted);
  assert.equal((await broken.decide(other('GET'))).decision, 'allow');
  assert.equal((await broken.decide(own('GET'))).decision, 'allow');
  const plan = await runRestorePreview(options);
  await applyTrialRestore({ ...options, approvalToken: plan.approvalToken,
    itemIds: plan.items.map(item => item.id) });
  const restoredSource = await readFile(f.policyPath, 'utf8');
  assert.equal(restoredSource, safeSource);
  const restored = await fromSource(restoredSource);
  for (const method of ['GET', 'PUT', 'DELETE']) {
    assert.equal((await restored.decide(own(method))).decision, 'allow');
    const denied = await restored.decide(other(method));
    assert.equal(denied.decision, 'deny');
    assert.deepEqual(denied.ruleIds, ['resource_zone']);
  }
  assert.equal((await restored.decide({ ...own('GET'), deviceRegistered: false })).reasonCode, 'device_not_registered');
  const suspicious = fixtureRequests().suspicious;
  assert.equal((await restored.decide(suspicious)).decision, 'step_up');
  assert.equal(await readFile(f.otherPath, 'utf8'), f.otherContent);
});
