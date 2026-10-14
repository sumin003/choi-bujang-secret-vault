import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export const REPOSITORY_ROOT = resolve(import.meta.dirname, '..');
export const SAFE_POLICY_COMMIT = '78b2ae8f6d478db8f331da5d001acb2844a28b0c';
export const SNAPSHOT_PATH = 'restore/safe-policy.json';
export const SNAPSHOT_SCHEMA = 'aleph.policy.snapshot.v1';
export const POLICY_GROUPS = Object.freeze({
  notes: ['src/decider.mjs', 'aleph.config.json'],
  detection: ['src/detect.mjs'],
  'xdr-brute-force': ['xdr/brute-force/decide.mjs', 'xdr/brute-force/patterns.json', 'xdr/brute-force/deny-rules.json'],
  'xdr-web-injection': ['xdr/web-injection/decide.mjs', 'xdr/web-injection/patterns.json', 'xdr/web-injection/deny-rules.json'],
});

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const normalize = bytes => Buffer.from(bytes.toString('utf8').replace(/\r\n/gu, '\n'), 'utf8');
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(',')}]`
  : value !== null && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`
    : JSON.stringify(value);
const fail = code => { throw new Error(code); };
const git = (...args) => execFileSync('git', ['-C', REPOSITORY_ROOT, ...args], {
  encoding: 'utf8', timeout: 10000, maxBuffer: 12 * 1024 * 1024, windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
}).trim();
const gitBuffer = (...args) => execFileSync('git', ['-C', REPOSITORY_ROOT, ...args], {
  timeout: 10000, maxBuffer: 12 * 1024 * 1024, windowsHide: true,
  stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_OPTIONAL_LOCKS: '0' },
});

function policyAtCommit(commit) {
  const files = {};
  for (const paths of Object.values(POLICY_GROUPS)) for (const path of paths) {
    try { files[path] = sha256(normalize(gitBuffer('show', `${commit}:${path}`))); }
    catch { files[path] = null; }
  }
  return files;
}

export function createSafePolicySnapshot(commit = SAFE_POLICY_COMMIT) {
  if (commit !== SAFE_POLICY_COMMIT) fail('safe_policy_commit_mismatch');
  try { git('cat-file', '-e', `${commit}^{commit}`); } catch { fail('safe_policy_commit_missing'); }
  try { git('merge-base', '--is-ancestor', commit, 'HEAD'); } catch { fail('safe_policy_commit_not_ancestor'); }
  const files = policyAtCommit(commit);
  if (Object.values(files).some(hash => typeof hash !== 'string')) fail('safe_policy_files_missing');
  const payload = { schema: SNAPSHOT_SCHEMA, commit, files };
  return { ...payload, sha256: sha256(Buffer.from(canonical(payload))) };
}

export function verifySafePolicySnapshot({ snapshotPath = resolve(REPOSITORY_ROOT, SNAPSHOT_PATH) } = {}) {
  let bytes;
  try {
    const info = lstatSync(snapshotPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 64 * 1024) fail('safe_policy_snapshot_invalid');
    bytes = readFileSync(snapshotPath);
  } catch (error) {
    if (error?.message === 'safe_policy_snapshot_invalid') throw error;
    fail('safe_policy_snapshot_missing');
  }
  let snapshot;
  try { snapshot = JSON.parse(bytes.toString('utf8')); } catch { fail('safe_policy_snapshot_invalid'); }
  const expectedKeys = ['commit', 'files', 'schema', 'sha256'];
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)
    || Object.keys(snapshot).sort().join(',') !== expectedKeys.join(',')
    || snapshot.schema !== SNAPSHOT_SCHEMA || snapshot.commit !== SAFE_POLICY_COMMIT
    || !/^[a-f0-9]{64}$/.test(snapshot.sha256)
    || !snapshot.files || typeof snapshot.files !== 'object' || Array.isArray(snapshot.files))
    fail('safe_policy_snapshot_invalid');
  const expectedPaths = Object.values(POLICY_GROUPS).flat().sort();
  if (Object.keys(snapshot.files).sort().join('\n') !== expectedPaths.join('\n')
    || Object.values(snapshot.files).some(hash => typeof hash !== 'string' || !/^[a-f0-9]{64}$/.test(hash)))
    fail('safe_policy_snapshot_invalid');
  const payload = { schema: snapshot.schema, commit: snapshot.commit, files: snapshot.files };
  if (sha256(Buffer.from(canonical(payload))) !== snapshot.sha256) fail('safe_policy_snapshot_hash_mismatch');
  try { git('cat-file', '-e', `${snapshot.commit}^{commit}`); } catch { fail('safe_policy_commit_missing'); }
  try { git('merge-base', '--is-ancestor', snapshot.commit, 'HEAD'); } catch { fail('safe_policy_commit_not_ancestor'); }
  const historical = policyAtCommit(snapshot.commit);
  if (canonical(historical) !== canonical(snapshot.files)) fail('safe_policy_commit_content_mismatch');
  return { snapshot, commitDate: git('show', '-s', '--format=%cI', snapshot.commit) };
}

export function previewSafePolicy({ snapshotPath } = {}) {
  const { snapshot, commitDate } = verifySafePolicySnapshot({ snapshotPath });
  const current = {};
  for (const path of Object.values(POLICY_GROUPS).flat()) {
    try { current[path] = sha256(normalize(readFileSync(resolve(REPOSITORY_ROOT, path)))); }
    catch { current[path] = null; }
  }
  const groups = Object.entries(POLICY_GROUPS).map(([name, paths]) => ({
    name,
    changes: paths.filter(path => current[path] !== snapshot.files[path]).map(path => ({
      path, operation: current[path] === null ? 'create' : 'replace',
      currentSha256: current[path], safeSha256: snapshot.files[path],
    })),
  }));
  return { schema: 'aleph.restore.preview.v1', mode: 'preview_only', restoreVersion: snapshot.commit,
    restoreCommitDate: commitDate, snapshotSha256: snapshot.sha256,
    verification: 'passed: snapshot hash, existing commit, ancestry, and historical file hashes',
    changes: groups.filter(group => group.changes.length) };
}
