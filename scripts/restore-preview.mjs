import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runRestorePreview } from '../src/restore-workflow.mjs';
import { previewSafePolicy } from './policy-snapshot.mjs';
export { runRestorePreview };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length === 0) {
      process.stdout.write(JSON.stringify(previewSafePolicy(), null, 2) + '\n');
      process.exit(0);
    }
    const names = new Map([['--backup', 'backupPath'], ['--verified-sha256', 'verifiedSha256'], ['--trial-dir', 'trialDir']]);
    const options = {};
    if (args.length !== 6) throw new Error('preview_arguments_invalid');
    for (let i = 0; i < args.length; i += 2) {
      const name = names.get(args[i]);
      if (!name || Object.hasOwn(options, name) || !args[i + 1]) throw new Error('preview_arguments_invalid');
      options[name] = args[i + 1];
    }
    process.stdout.write(JSON.stringify(await runRestorePreview(options), null, 2) + '\n');
  } catch (error) {
    const codes = new Set(['preview_arguments_invalid', 'verified_hash_required', 'safe_backup_unavailable',
      'backup_verification_failed', 'backup_input_invalid', 'trial_policy_unavailable',
      'trial_policy_input_invalid', 'policy_input_invalid', 'policy_input_too_large']);
    process.stderr.write(JSON.stringify({ error: codes.has(error?.message) ? error.message : 'preview_failed' }) + '\n');
    process.exitCode = 1;
  }
}
