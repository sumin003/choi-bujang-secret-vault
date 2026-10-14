import { applyTrialRestore } from '../src/restore-workflow.mjs';

try {
  const args = process.argv.slice(2);
  const names = new Map([['--backup', 'backupPath'], ['--verified-sha256', 'verifiedSha256'],
    ['--trial-dir', 'trialDir'], ['--approve', 'approvalToken'], ['--items', 'itemIds']]);
  const options = {};
  if (args.length !== 10) throw new Error('restore_arguments_invalid');
  for (let i = 0; i < args.length; i += 2) {
    const name = names.get(args[i]);
    if (!name || Object.hasOwn(options, name) || !args[i + 1]) throw new Error('restore_arguments_invalid');
    options[name] = name === 'itemIds' ? args[i + 1].split(',') : args[i + 1];
  }
  process.stdout.write(JSON.stringify(await applyTrialRestore(options), null, 2) + '\n');
} catch (error) {
  const codes = new Set(['restore_arguments_invalid', 'preview_arguments_invalid', 'verified_hash_required',
    'safe_backup_unavailable', 'backup_verification_failed', 'backup_input_invalid', 'trial_policy_unavailable',
    'trial_policy_input_invalid', 'policy_input_invalid', 'policy_input_too_large', 'restore_approval_required',
    'restore_items_required', 'restore_items_invalid', 'one_policy_file_required', 'restore_plan_changed',
    'operating_policy_protected', 'safe_backup_must_be_separate', 'trial_marker_required', 'restore_locked',
    'restore_write_failed', 'restore_audit_unavailable', 'restore_postcheck_failed', 'restore_rollback_failed']);
  process.stderr.write(JSON.stringify({ error: codes.has(error?.message) ? error.message : 'restore_failed' }) + '\n');
  process.exitCode = 1;
}
