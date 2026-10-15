import { enforceXdr } from '../src/xdr-gate.mjs';
import { createWebSessions, expiredWebCookie } from '../src/web-session.mjs';

const safeCodes = new Set(['invalid_credentials', 'email_not_confirmed', 'user_banned',
  'over_request_rate_limit', 'over_email_send_rate_limit', 'provider_disabled', 'email_provider_disabled']);
export function createAuthHandler({ sessions = createWebSessions(), enforceRequest = enforceXdr } = {}) {
  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Vary', 'Cookie');
    if (!enforceRequest(req, res)) return;
    const action = req.query?.action;
    if (!(action === 'session' && req.method === 'GET')
        && !(['login', 'logout'].includes(action) && req.method === 'POST'))
      return res.status(400).json({ code: 'invalid_request', msg: '지원하지 않는 인증 요청입니다.' });
    if (req.method === 'POST' && ((req.headers?.origin && req.headers.origin !== 'https://' + req.headers.host)
        || req.headers?.['sec-fetch-site'] === 'cross-site'))
      return res.status(403).json({ code: 'invalid_request', msg: '인증 요청 출처가 올바르지 않습니다.' });
    try {
      if (action === 'logout') {
        await sessions.revoke(req);
        res.setHeader('Set-Cookie', expiredWebCookie());
        return res.status(200).json({ authenticated: false });
      }
      if (action === 'session') {
        const session = await sessions.load(req);
        if (!session) {
          res.setHeader('Set-Cookie', expiredWebCookie());
          return res.status(200).json({ authenticated: false });
        }
        const sdk = await sessions.client();
        const { data, error } = await sdk.auth.getUser(session.tokens.access_token);
        if (error && (!error.status || error.status >= 500)) throw new Error('AUTH_UNAVAILABLE');
        if (error || data?.user?.id !== session.row.user_id) {
          await sessions.revoke(req); res.setHeader('Set-Cookie', expiredWebCookie());
          return res.status(200).json({ authenticated: false });
        }
        return res.status(200).json({ authenticated: true });
      }
      if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type'] ?? ''))
        return res.status(415).json({ code: 'invalid_request', msg: 'JSON 요청이 필요합니다.' });
      let body;
      try { body = typeof req.body === 'string' && req.body.length <= 8192 ? JSON.parse(req.body) : req.body; } catch {}
      if (!body || typeof body !== 'object' || Array.isArray(body)
          || Object.keys(body).sort().join(',') !== 'email,password'
          || typeof body.email !== 'string' || !body.email || body.email.length > 320
          || typeof body.password !== 'string' || !body.password || body.password.length > 4096)
        return res.status(400).json({ code: 'invalid_request', msg: '이메일과 비밀번호를 확인해 주세요.' });
      const sdk = await sessions.client();
      const { data, error } = await sdk.auth.signInWithPassword({ email: body.email, password: body.password });
      if (error) return res.status(error.status === 429 ? 429 : 401).json({
        code: safeCodes.has(error.code) ? error.code : 'unexpected_failure', msg: '로그인하지 못했습니다.' });
      const cookie = await sessions.issue(data?.session, data?.user?.id);
      await sessions.revoke(req);
      res.setHeader('Set-Cookie', cookie);
      return res.status(200).json({ authenticated: true });
    } catch {
      return res.status(503).json({ code: 'unexpected_failure', msg: '인증 서버에 연결할 수 없습니다.' });
    }
  };
}
export default createAuthHandler();
