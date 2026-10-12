import { decide as existingDecide, createBaseDecider } from '../../src/decider.mjs';
import { withXdrDenies } from './respond.mjs';

// Adds a deny-only check to the real base decider. IP stays in trusted server context,
// outside the eighteen-field request contract. No fixture allow function is substituted.
export function createConnectedDecider({getVerifiedSource,denyReasonCode='starter_not_ready',loadRules,now,mode}={}) {
  const baseline = now ? createBaseDecider({now}) : existingDecide;
  return withXdrDenies(baseline,{getVerifiedSource,denyReasonCode,denyRuleId:'xdr.brute_force.deny',
    ...(loadRules?{loadRules}:{}),...(now?{now}:{}),...(mode?{mode}:{})});
}
