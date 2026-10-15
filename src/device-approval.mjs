import { createBrowserRegistration } from './browser-registration.mjs';

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
  res.setHeader('X-Device-Decision', result === 'approved' ? 'allow' : 'deny');
  res.setHeader('X-Device-Reason', result === 'unavailable' ? 'device_registration_not_connected' : result === 'approved' ? 'approved' : 'device_not_approved');
  if (result === 'approved') return true;
  res.status(result === 'unavailable' ? 503 : 403).json({
    error: result === 'unavailable' ? 'DEVICE_REGISTRATION_NOT_CONNECTED' : 'DEVICE_NOT_APPROVED',
  });
  return false;
}
