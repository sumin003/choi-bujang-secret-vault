import { createHash } from 'node:crypto';

export const POLICY_PATHS = Object.freeze([
  'src/decider.mjs', 'src/detect.mjs', 'src/xdr-gate.mjs',
  'xdr/brute-force/deny-rules.json', 'xdr/web-injection/deny-rules.json',
]);
export const MAX_POLICY_BYTES = 1024 * 1024;
export const MAX_BACKUP_BYTES = 8 * 1024 * 1024;
export const MAX_POLICY_LINES = 2000;
const fail = code => { throw new Error(code); };
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => plain(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key));
const utcMillis = value => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value))
    return Number.NaN;
  const millis = Date.parse(value);
  return Number.isFinite(millis) && new Date(millis).toISOString() === value ? millis : Number.NaN;
};

function policyLines(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length > MAX_POLICY_BYTES) fail('policy_input_invalid');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { fail('policy_input_invalid'); }
  const lines = text.match(/[^\n]*\n|[^\n]+$/g) ?? [];
  if (lines.length > MAX_POLICY_LINES) fail('policy_input_too_large');
  return lines;
}

// The hash must have been retained independently at the earlier safety review.
// Integrity verification cannot establish a policy's safety or review date.
export function readVerifiedBackup(backupBytes, verifiedSha256) {
  if (typeof verifiedSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(verifiedSha256))
    fail('verified_hash_required');
  if (!Buffer.isBuffer(backupBytes) || backupBytes.length > MAX_BACKUP_BYTES)
    fail('backup_input_invalid');
  if (sha256(backupBytes) !== verifiedSha256.toLowerCase()) fail('backup_verification_failed');
  let backup;
  try { backup = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(backupBytes)); }
  catch { fail('backup_input_invalid'); }
  if (!exactKeys(backup, ['schema', 'version', 'verifiedAt', 'incidentAt', 'files'])
    || backup.schema !== 'aleph.policy.backup.v1' || typeof backup.version !== 'string'
    || !/^[a-f0-9]{40}$/i.test(backup.version) || !Array.isArray(backup.files)
    || backup.files.length < 1 || backup.files.length > POLICY_PATHS.length) fail('backup_input_invalid');
  const verifiedAt = utcMillis(backup.verifiedAt);
  const incidentAt = utcMillis(backup.incidentAt);
  if (!Number.isFinite(verifiedAt) || !Number.isFinite(incidentAt) || verifiedAt >= incidentAt)
    fail('backup_verification_failed');
  const seen = new Set();
  for (const file of backup.files) {
    if (!exactKeys(file, ['path', 'content']) || !POLICY_PATHS.includes(file.path)
      || seen.has(file.path) || typeof file.content !== 'string') fail('backup_input_invalid');
    policyLines(Buffer.from(file.content));
    seen.add(file.path);
  }
  return backup;
}

function changedRanges(trial, backup) {
  const width = backup.length + 1;
  const table = new Uint16Array((trial.length + 1) * width);
  for (let i = trial.length - 1; i >= 0; i--) {
    for (let j = backup.length - 1; j >= 0; j--) {
      table[i * width + j] = trial[i] === backup[j]
        ? 1 + table[(i + 1) * width + j + 1]
        : Math.max(table[(i + 1) * width + j], table[i * width + j + 1]);
    }
  }
  const ranges = [];
  let i = 0;
  let j = 0;
  while (i < trial.length || j < backup.length) {
    if (i < trial.length && j < backup.length && trial[i] === backup[j]) { i++; j++; continue; }
    const trialStart = i;
    const backupStart = j;
    while (i < trial.length || j < backup.length) {
      if (i < trial.length && j < backup.length && trial[i] === backup[j]) break;
      if (j < backup.length && (i === trial.length
        || table[i * width + j + 1] > table[(i + 1) * width + j])) j++;
      else i++;
    }
    ranges.push({ trial: { startLine: trialStart + 1, lineCount: i - trialStart },
      backup: { startLine: backupStart + 1, lineCount: j - backupStart } });
  }
  return ranges;
}

// Only constructs a plan. Never imports policy code, writes files, or applies it.
export function createRestorePreview({ backupBytes, verifiedSha256, trialFiles }) {
  const backup = readVerifiedBackup(backupBytes, verifiedSha256);
  if (!exactKeys(trialFiles, backup.files.map(file => file.path))) fail('trial_policy_input_invalid');
  const changes = [];
  for (const file of backup.files) {
    const desiredBytes = Buffer.from(file.content);
    const trialBytes = trialFiles[file.path];
    const before = trialBytes === null ? [] : policyLines(trialBytes);
    const after = policyLines(desiredBytes);
    const ranges = changedRanges(before, after);
    if (trialBytes !== null && trialBytes.equals(desiredBytes)) continue;
    changes.push({ path: file.path, operation: trialBytes === null ? 'create' : 'replace',
      beforeSha256: trialBytes === null ? null : sha256(trialBytes),
      afterSha256: sha256(desiredBytes), ranges });
  }
  return { schema: 'aleph.restore.preview.v1', mode: 'preview_only',
    restoreVersion: backup.version.toLowerCase(), verifiedAt: backup.verifiedAt,
    incidentAt: backup.incidentAt,
    verifiedBackupSha256: verifiedSha256.toLowerCase(), changes };
}
