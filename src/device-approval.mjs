import { decideDeviceRegistration } from './decider.mjs';
import { createBrowserRegistration } from './browser-registration.mjs';

const DEVICE_ID = /^[a-f0-9]{16}$/;
const REVIEW_STATES = new Set(['unverified', 'pending', 'rejected']);
const unavailable = () => { throw new Error('device_registration_not_connected'); };

// Optional adapter for separately authenticated engine context. The deployed
// application below uses the operator-reviewed server registration service.
// Browser headers, login/session IDs and fingerprints are never engine proof.
export function createDeviceApprovalService({ provider = null } = {}) {
  async function verifiedDevice(req, identity) {
    if (!identity || !['student', 'judge'].includes(identity.kind))
      throw new Error('login_required');
    if (typeof provider?.readVerifiedRegistration !== 'function') return unavailable();
    const result = await provider.readVerifiedRegistration(req, identity);
    if (!result || !DEVICE_ID.test(result.deviceId ?? '')
        || typeof result.deviceRegistered !== 'boolean') return unavailable();
    return { deviceId: result.deviceId, deviceRegistered: result.deviceRegistered };
  }
  async function status(req, identity) {
    const device = await verifiedDevice(req, identity);
    const decision = decideDeviceRegistration(device.deviceRegistered);
    if (decision.decision === 'allow') return { status: 'approved' };
    if (typeof provider.readApprovalStatus !== 'function') return { status: 'unverified' };
    const review = await provider.readApprovalStatus(device.deviceId, identity);
    if (!REVIEW_STATES.has(review)) return unavailable();
    return { status: review };
  }
  async function request(req, identity) {
    const device = await verifiedDevice(req, identity);
    if (device.deviceRegistered) return { status: 'approved' };
    if (typeof provider.requestApproval !== 'function') return unavailable();
    // A request may create a review only. It must not turn a click into approval.
    const result = await provider.requestApproval(device.deviceId, identity);
    if (result?.status !== 'pending') return unavailable();
    return { status: 'pending' };
  }
  return Object.freeze({ status, request });
}

// The browser-cookie registration is separate from engine device evidence.
const service = createBrowserRegistration();
export const readDeviceApproval = (req, identity, options) => service.status(req, identity, options);
export const requestDeviceApproval = (req, identity, res) => service.request(req, identity, res);

export async function checkApprovedDevice(req, identity, { approvalService = service } = {}) {
  try { return (await approvalService.status(req, identity)).status === 'approved' ? 'approved' : 'required'; }
  catch { return 'unavailable'; }
}

export async function enforceApprovedDevice(req, res, identity, options) {
  const result = await checkApprovedDevice(req, identity, options);
  const decision = decideDeviceRegistration(result === 'approved');
  res.setHeader('X-Device-Decision', decision.decision);
  res.setHeader('X-Device-Rule', decision.ruleIds[0]);
  res.setHeader('X-Device-Reason', result === 'unavailable' ? 'device_registration_not_connected' : decision.reasonCode);
  if (decision.decision === 'allow') return true;
  res.status(result === 'unavailable' ? 503 : 403).json({
    error: result === 'unavailable' ? 'DEVICE_REGISTRATION_NOT_CONNECTED' : 'DEVICE_APPROVAL_REQUIRED',
  });
  return false;
}
