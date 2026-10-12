import { decide as existingDecide } from '../../src/decider.mjs';
import { withXdrDenies } from './respond.mjs';

// The engine supplies these functions/settings from its trusted server context.
// This module never changes existing ZTNA policy or accepts browser-supplied IPs.
export function createConnectedDecider({getVerifiedSource,denyReasonCode,loadRules,now,mode}={}) {
  return withXdrDenies(existingDecide,{getVerifiedSource,denyReasonCode,
    ...(loadRules?{loadRules}:{}),...(now?{now}:{}),...(mode?{mode}:{})});
}
