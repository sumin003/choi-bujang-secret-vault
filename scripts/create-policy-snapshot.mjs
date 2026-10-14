import { mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSafePolicySnapshot, REPOSITORY_ROOT, SNAPSHOT_PATH } from './policy-snapshot.mjs';

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const destination = resolve(REPOSITORY_ROOT, SNAPSHOT_PATH);
    if (existsSync(destination)) throw new Error('snapshot_already_exists');
    const snapshot = createSafePolicySnapshot();
    mkdirSync(dirname(destination), { recursive: true });
    writeFileSync(destination, `${JSON.stringify(snapshot, null, 2)}\n`, { flag: 'wx', mode: 0o644 });
    process.stdout.write(JSON.stringify({ created: SNAPSHOT_PATH, commit: snapshot.commit, sha256: snapshot.sha256 }) + '\n');
  } catch (error) {
    process.stderr.write(JSON.stringify({ error: error?.message === 'snapshot_already_exists' ? error.message : 'snapshot_creation_failed' }) + '\n');
    process.exitCode = 1;
  }
}
