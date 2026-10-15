import { createLoginVerifier } from '../src/verify-login.mjs';
import { readDeviceApproval, requestDeviceApproval } from '../src/device-approval.mjs';
import config from '../aleph.config.json' with { type: 'json' };

let verifyLogin;

export function createDeviceHandler({ verify,
  approvalService = { status: readDeviceApproval, request: requestDeviceApproval },
  secret = process.env.SUPABASE_SECRET_KEY } = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization');
    // Clear only the obsolete cookie from the earlier, incorrect implementation.
    res.setHeader('Set-Cookie', '__Host-vault_device=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict');
    let target;
    try { if (typeof req.url === 'string') target = new URL(req.url, 'https://request.invalid'); } catch {}
    if (!target || target.pathname !== '/api/device' || target.search || target.hash)
      return res.status(400).json({ error: 'INVALID_ROUTE' });
    if (!['GET', 'POST'].includes(req.method)) {
      res.setHeader('Allow', 'GET, POST');
      return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    if (req.method === 'POST' && req.headers?.origin
        && req.headers.origin !== 'https://' + req.headers.host)
      return res.status(403).json({ error: 'INVALID_ORIGIN' });
    let identity;
    try {
      if (!verify) verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secret });
      identity = await (verify ?? verifyLogin)(req.headers?.authorization);
    } catch { /* Do not log credentials or upstream errors. */ }
    if (identity?.kind !== 'student') return res.status(401).json({ error: 'LOGIN_REQUIRED' });
    try {
      if (req.method === 'GET') return res.status(200).json(await approvalService.status(req, identity));
      if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type'] ?? ''))
        return res.status(415).json({ error: 'JSON_REQUIRED' });
      let input;
      try { input = typeof req.body === 'string' && req.body.length <= 128
        ? JSON.parse(req.body) : req.body; } catch {}
      if (!input || typeof input !== 'object' || Array.isArray(input)
          || Object.keys(input).length !== 1 || input.action !== 'request')
        return res.status(400).json({ error: 'INVALID_REQUEST' });
      return res.status(200).json(await approvalService.request(req, identity));
    } catch {
      return res.status(503).json({ error: 'DEVICE_REGISTRATION_NOT_CONNECTED' });
    }
  };
}

export default createDeviceHandler();
