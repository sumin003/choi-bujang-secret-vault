import { randomUUID } from 'node:crypto';
import { enforceApprovedDevice } from '../src/device-approval.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import config from '../aleph.config.json' with { type: 'json' };
import snapshot from '../restore/safe-policy.json' with { type: 'json' };
import brute from '../xdr/brute-force/result.json' with { type: 'json' };
import web from '../xdr/web-injection/result.json' with { type: 'json' };
import cve from '../xdr/known-cve/result.json' with { type: 'json' };

export function createOperationsHandler({ verify, approve = enforceApprovedDevice,
  writeRecord = record => console.log(JSON.stringify(record)) } = {}) {
  let verifier;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization, Cookie');
    if (req.url !== '/api/operations') return res.status(400).json({error:'INVALID_ROUTE'});
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
    }
    let identity;
    try {
      if (!verifier) {
        if (verify) verifier = verify;
        else {
          const {createLoginVerifier} = await import('../src/verify-login.mjs');
          verifier = createLoginVerifier({config, supabaseSecretKey:process.env.SUPABASE_SECRET_KEY});
        }
      }
      identity = await verifier(req.headers?.authorization);
    } catch {}
    if (identity?.kind !== 'student') return res.status(401).json({error:'LOGIN_REQUIRED'});
    try {
      if (!await approve(req, res, identity)) return;
      // Explicit allowlist only: never return decisions, events, notes or identities.
      const summary = {
        schema:'aleph.operations.summary.v1', requestId:randomUUID(), checkedAt:new Date().toISOString(),
        access:{status:'confirmed', source:'server_login_and_device_approval'},
        rules:{status:'configuration_loaded', ids:[...RULE_IDS], execution:'not_run'},
        detection:{status:'not_run', source:'no_live_event_query', savedFixtureResults:
          [brute,web,cve].map(result=>({moduleKey:result.moduleKey,
            counts:{block:result.counts.block,alert:result.counts.alert,record:result.counts.record},
            source:'saved_fixture_result'}))},
        revocation:{status:'not_run', reason:'no_execution_receipt'},
        recovery:{status:'not_run', candidateVersion:snapshot.commit,
          verification:'not_run', source:'repository_policy_snapshot',
          reason:'version_is_not_proof_of_verified_backup_or_restore'},
      };
      // Construct once from allowlisted metadata, then record exactly what is returned.
      // Never pass req, identity, headers, cookies or upstream error objects to the logger.
      await writeRecord({event:'operations_summary', httpStatus:200,
        requestId:summary.requestId, checkedAt:summary.checkedAt, summary});
      res.setHeader('X-Request-ID', summary.requestId);
      return res.status(200).json(summary);
    } catch { return res.status(503).json({error:'OPERATIONS_UNAVAILABLE'}); }
  };
}
export default createOperationsHandler();
