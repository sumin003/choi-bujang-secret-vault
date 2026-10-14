import { open, realpath, stat, lstat, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, relative, isAbsolute, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { readVerifiedBackup, createRestorePreview, MAX_BACKUP_BYTES, MAX_POLICY_BYTES, MAX_POLICY_LINES } from './restore-preview.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const fail = code => { throw new Error(code); };
const inside = (root, path) => {
  const child = relative(root, path);
  return !isAbsolute(child) && child !== '..' && !child.startsWith('..' + sep);
};
const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));

async function readOnly(path, maxBytes, code, allowMissing = false) {
  let file;
  try {
    file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | constants.O_NONBLOCK);
    const info = await file.stat();
    if (!info.isFile() || info.size > maxBytes) fail(code);
    const bytes = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const read = await file.read(bytes, length, bytes.length - length, null);
      if (!read.bytesRead) break;
      length += read.bytesRead;
    }
    if (length > maxBytes) fail(code);
    return bytes.subarray(0, length);
  } catch (error) {
    if (allowMissing && error?.code === 'ENOENT') return null;
    fail(code);
  } finally { await file?.close(); }
}

// Reject symlinked directories too, including when the final file is absent.
async function containedPath(root, path, allowMissing = true) {
  const pieces = relative(root, path).split(sep);
  if (!inside(root, path)) fail('trial_policy_unavailable');
  let part = root;
  for (const piece of pieces) {
    part = join(part, piece);
    let info;
    try { info = await lstat(part); }
    catch (error) {
      if (allowMissing && error?.code === 'ENOENT') return;
      fail('trial_policy_unavailable');
    }
    if (info.isSymbolicLink()) fail('trial_policy_unavailable');
  }
}

async function loadInputs({ backupPath, verifiedSha256, trialDir }) {
  if (!backupPath || !trialDir) fail('preview_arguments_invalid');
  if (!/^[a-f0-9]{64}$/i.test(verifiedSha256 ?? '')) fail('verified_hash_required');
  const backupBytes = await readOnly(backupPath, MAX_BACKUP_BYTES, 'safe_backup_unavailable');
  const backup = readVerifiedBackup(backupBytes, verifiedSha256);
  let root;
  try {
    root = await realpath(trialDir);
    if (!(await stat(root)).isDirectory()) fail('trial_policy_unavailable');
  } catch { fail('trial_policy_unavailable'); }
  const trialFiles = {};
  for (const entry of backup.files) {
    const path = join(root, entry.path);
    await containedPath(root, path);
    trialFiles[entry.path] = await readOnly(path, MAX_POLICY_BYTES, 'trial_policy_unavailable', true);
  }
  const preview = createRestorePreview({ backupBytes, verifiedSha256, trialFiles });
  const items = preview.changes.flatMap((change, fileIndex) => change.operation === 'create'
    ? [{ id: `c${fileIndex}create`, path: change.path, operation: 'create' }]
    : change.ranges.map((range, rangeIndex) => ({ id: `c${fileIndex}r${rangeIndex}`,
      path: change.path, operation: 'replace', ...range })));
  // Bind approval to the verified snapshot, full file state, and exact directory.
  const approvalToken = hash(JSON.stringify({ root, preview, items }));
  return { backup, trialFiles, root, preview: { ...preview, items, approvalToken } };
}

export async function runRestorePreview(options) { return (await loadInputs(options)).preview; }

async function requireTrial(root, backupPath) {
  const ownRoot = await realpath(repositoryRoot);
  if (inside(root, ownRoot)) fail('operating_policy_protected');
  if (inside(root, await realpath(backupPath))) fail('safe_backup_must_be_separate');
  const bytes = await readOnly(join(root, 'trial-policy.json'), 4096, 'trial_marker_required');
  let marker;
  try { marker = JSON.parse(bytes); } catch { fail('trial_marker_required'); }
  if (!marker || Object.keys(marker).length !== 2 || marker.schema !== 'aleph.trial.policy.v1'
    || marker.purpose !== 'isolated_test') fail('trial_marker_required');
}

async function stageFile(path, bytes, mode) {
  const staging = join(dirname(path), '.restore-stage-' + randomUUID());
  let file;
  try {
    file = await open(staging, 'wx', mode);
    await file.writeFile(bytes);
    await file.sync();
    return staging;
  } catch {
    await unlink(staging).catch(() => {});
    fail('restore_write_failed');
  } finally { await file?.close(); }
}

async function appendAudit(file, record) {
  const info = await file.stat();
  let prefix = '';
  if (info.size) {
    const last = Buffer.alloc(1);
    await file.read(last, 0, 1, info.size - 1);
    if (last[0] !== 10) prefix = '\n';
  }
  await file.writeFile(prefix + JSON.stringify(record) + '\n');
  await file.sync();
}

export async function applyTrialRestore(options) {
  if (!/^[a-f0-9]{64}$/.test(options.approvalToken ?? '')) fail('restore_approval_required');
  if (!Array.isArray(options.itemIds) || !options.itemIds.length
    || new Set(options.itemIds).size !== options.itemIds.length) fail('restore_items_required');
  let input = await loadInputs(options);
  await requireTrial(input.root, options.backupPath);
  if (input.preview.approvalToken !== options.approvalToken) fail('restore_plan_changed');
  const selected = input.preview.items.filter(item => options.itemIds.includes(item.id));
  if (selected.length !== options.itemIds.length) fail('restore_items_invalid');
  // One file per execution gives a single atomic policy switch. Repeat the
  // preview/approval step for another service; never overwrite every file.
  if (new Set(selected.map(item => item.path)).size !== 1) fail('one_policy_file_required');
  const pathName = selected[0].path;
  const path = join(input.root, pathName);
  const lockPath = join(input.root, '.restore.lock');
  let lock;
  let audit;
  let staged;
  let switched = false;
  let oldBytes;
  let newBytes;
  let mode = 0o600;
  const event = { schema: 'aleph.restore.audit.v1', eventId: randomUUID(),
    restoreVersion: input.preview.restoreVersion, approvalToken: options.approvalToken,
    items: [...options.itemIds].sort(), path: pathName };
  try {
    try { lock = await open(lockPath, 'wx', 0o600); } catch { fail('restore_locked'); }
    input = await loadInputs(options);
    await requireTrial(input.root, options.backupPath);
    if (input.preview.approvalToken !== options.approvalToken) fail('restore_plan_changed');
    await containedPath(input.root, dirname(path), false);
    oldBytes = input.trialFiles[pathName];
    const safeContent = input.backup.files.find(file => file.path === pathName).content;
    if (oldBytes === null) newBytes = Buffer.from(safeContent);
    else {
      mode = (await lstat(path)).mode & 0o777;
      const currentLines = oldBytes.toString('utf8').match(/[^\n]*\n|[^\n]+$/g) ?? [];
      const safeLines = safeContent.match(/[^\n]*\n|[^\n]+$/g) ?? [];
      for (const item of [...selected].sort((a, b) => b.trial.startLine - a.trial.startLine)) {
        currentLines.splice(item.trial.startLine - 1, item.trial.lineCount,
          ...safeLines.slice(item.backup.startLine - 1, item.backup.startLine - 1 + item.backup.lineCount));
      }
      newBytes = Buffer.from(currentLines.join(''));
    }
    if (newBytes.length > MAX_POLICY_BYTES
      || (newBytes.toString('utf8').match(/[^\n]*\n|[^\n]+$/g) ?? []).length > MAX_POLICY_LINES)
      fail('policy_input_too_large');
    staged = await stageFile(path, newBytes, mode);
    const flags = constants.O_RDWR | constants.O_CREAT | constants.O_APPEND
      | (constants.O_NOFOLLOW ?? 0) | constants.O_NONBLOCK;
    let candidate;
    try {
      const auditPath = join(input.root, 'restore-audit.jsonl');
      await containedPath(input.root, auditPath);
      candidate = await open(auditPath, flags, 0o600);
      const info = await candidate.stat();
      if (!info.isFile() || info.nlink !== 1) fail('restore_audit_unavailable');
      audit = candidate;
      candidate = undefined;
    } catch { await candidate?.close(); fail('restore_audit_unavailable'); }
    await appendAudit(audit, { ...event, at: new Date().toISOString(), status: 'started' });
    await containedPath(input.root, path);
    const latest = await readOnly(path, MAX_POLICY_BYTES, 'trial_policy_unavailable', true);
    if (oldBytes === null ? latest !== null : latest === null || !oldBytes.equals(latest)) fail('restore_plan_changed');
    await rename(staged, path);
    staged = undefined;
    switched = true;
    const restored = await readOnly(path, MAX_POLICY_BYTES, 'trial_policy_unavailable');
    if (!restored.equals(newBytes)) fail('restore_postcheck_failed');
    await appendAudit(audit, { ...event, at: new Date().toISOString(), status: 'completed', afterSha256: hash(newBytes) });
    return { schema: 'aleph.restore.result.v1', status: 'restored_selected_items',
      restoreVersion: input.preview.restoreVersion, items: event.items, path: pathName,
      afterSha256: hash(newBytes) };
  } catch (error) {
    let rolledBack = false;
    if (switched) {
      try {
        await containedPath(input.root, path);
        const latest = await readOnly(path, MAX_POLICY_BYTES, 'trial_policy_unavailable');
        if (!latest.equals(newBytes)) fail('restore_rollback_failed');
        if (oldBytes === null) await unlink(path);
        else {
          const rollback = await stageFile(path, oldBytes, mode);
          try { await rename(rollback, path); } finally { await unlink(rollback).catch(() => {}); }
        }
        rolledBack = true;
      } catch { fail('restore_rollback_failed'); }
    }
    if (audit) await appendAudit(audit, { ...event, at: new Date().toISOString(),
      status: rolledBack ? 'rolled_back' : 'aborted' }).catch(() => {});
    throw error;
  } finally {
    if (staged) await unlink(staged).catch(() => {});
    await audit?.close();
    if (lock) { await lock.close(); await unlink(lockPath).catch(() => {}); }
  }
}
