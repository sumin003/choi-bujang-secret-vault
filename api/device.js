import { createLoginVerifier } from '../src/verify-login.mjs';
import { checkApprovedDevice, credentialHash, deviceRecord,
  makeDeviceCookie, requestDeviceApproval } from '../src/device-approval.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[a-f0-9]{64}$/;
let verifyLogin;

export function createDeviceHandler({ verify, fetchImpl = fetch,
  secret = process.env.SUPABASE_SECRET_KEY, url = process.env.SUPABASE_URL } = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization, Cookie');
    let target;
    try { if (typeof req.url === 'string') target = new URL(req.url, 'https://request.invalid'); } catch {}
    if (!target || target.pathname !== '/api/device' || target.search)
      return res.status(400).json({ error: 'INVALID_ROUTE' });
    if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    if (req.method === 'POST' && req.headers?.origin
        && req.headers.origin !== 'https://' + req.headers.host)
      return res.status(403).json({ error: 'INVALID_ORIGIN' });
    if (!url || !secret) return res.status(503).json({ error: 'DEVICE_STATUS_UNAVAILABLE' });
    let identity;
    try {
      if (!verify) verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: secret });
      identity = await (verify ?? verifyLogin)(req.headers?.authorization);
    } catch { /* Never log credentials or upstream errors. */ }
    if (identity?.kind !== 'student') return res.status(401).json({ error: 'LOGIN_REQUIRED' });
    try {
      if (req.method === 'GET') {
        const checked = await checkApprovedDevice(req, identity, { secret, url, fetchImpl });
        if (checked === 'approved') return res.status(200).json({ status: 'approved' });
        if (checked === 'unavailable') throw new Error();
        const hash = req.headers?.['x-device-request-id'];
        if (!hash) return res.status(200).json({ status: 'unverified' });
        if (typeof hash !== 'string' || !HASH.test(hash)) return res.status(400).json({ error: 'INVALID_REQUEST' });
        const status = await deviceRecord({ userId: identity.userId, hash, secret, url, fetchImpl });
        return res.status(200).json({ status: status === 'approved' ? 'approved_needs_verification' : status ?? 'unverified' });
      }
      if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type'] ?? ''))
        return res.status(415).json({ error: 'JSON_REQUIRED' });
      let input;
      try { input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
      catch { return res.status(400).json({ error: 'INVALID_REQUEST' }); }
      if (!input || Array.isArray(input) || typeof input !== 'object'
          || JSON.stringify(input).length > 16000)
        return res.status(400).json({ error: 'INVALID_REQUEST' });
      if (!['start', 'verify'].includes(input.action)) return res.status(400).json({ error: 'INVALID_REQUEST' });
      const base = new URL(url);
      if (base.protocol !== 'https:' || base.username || base.password) throw new Error();
      const endpoint = new URL('/auth/v1/passkeys/authentication/' +
        (input.action === 'start' ? 'options' : 'verify'), base);
      let payload;
      if (input.action === 'verify') {
        const credential = input.credential;
        if (!UUID.test(input.challengeId ?? '') || !credential || credential.type !== 'public-key'
            || typeof credential.id !== 'string' || credential.rawId !== credential.id
            || !credentialHash(credential.id) || !credential.response?.authenticatorData
            || !credential.response?.clientDataJSON || !credential.response?.signature)
          return res.status(400).json({ error: 'INVALID_REQUEST' });
        payload = { challenge_id: input.challengeId, credential };
      }
      const upstream = await fetchImpl(endpoint, { method: 'POST',
        headers: { apikey: secret, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload ?? {}), cache: 'no-store', redirect: 'error',
        signal: AbortSignal.timeout(10000) });
      if (!upstream.ok) return res.status(403).json({ error: 'DEVICE_PROOF_FAILED' });
      const data = await upstream.json();
      if (input.action === 'start') {
        if (!UUID.test(data.challenge_id ?? '') || !data.options?.challenge) throw new Error();
        return res.status(200).json({ challengeId: data.challenge_id, options: data.options });
      }
      // Supabase Auth verifies the signed WebAuthn assertion and consumes its
      // challenge before a credential can become a pending approval request.
      if (typeof data.access_token !== 'string') throw new Error();
      const proved = await (verify ?? verifyLogin)('Bearer ' + data.access_token);
      if (proved?.kind !== 'student' || proved.userId !== identity.userId)
        return res.status(403).json({ error: 'DEVICE_PROOF_FAILED' });
      const flags = Buffer.from(input.credential.response.authenticatorData, 'base64url');
      // Synced passkeys can be used on other devices, so only accept an
      // authenticator-reported device-bound credential for a device approval.
      if (flags.length < 37 || (flags[32] & 0x08) !== 0 || (flags[32] & 0x04) === 0)
        return res.status(403).json({ error: 'DEVICE_BOUND_KEY_REQUIRED' });
      const hash = credentialHash(input.credential.id);
      const status = await requestDeviceApproval({ userId: identity.userId, hash, secret, url, fetchImpl });
      if (status === 'approved') res.setHeader('Set-Cookie', makeDeviceCookie({
        authorization: req.headers.authorization, userId: identity.userId, hash, secret,
      }));
      return res.status(200).json({ status, requestId: hash });
    } catch {
      return res.status(503).json({ error: 'DEVICE_STATUS_UNAVAILABLE' });
    }
  };
}

export default createDeviceHandler();
