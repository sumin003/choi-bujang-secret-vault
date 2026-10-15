import { enforceXdr } from '../src/xdr-gate.mjs';
// Only the official SDK's password, refresh, user and local logout requests are relayed.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (!enforceXdr(req, res)) return;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const action = req.query?.action;
  const grant = req.query?.grant_type;
  const method = req.method;
  const tokenRequest = action === 'token' && method === 'POST'
    && ['password', 'refresh_token'].includes(grant);
  const logoutRequest = action === 'logout' && method === 'POST';
  const userRequest = action === 'user' && method === 'GET';
  if (!tokenRequest && !logoutRequest && !userRequest)
    return res.status(400).json({ code: 'invalid_request', msg: '지원하지 않는 인증 요청입니다.' });
  const source = req.headers?.origin;
  const host = req.headers?.host;
  if (source && source !== 'https://' + host)
    return res.status(403).json({ code: 'invalid_request', msg: '인증 요청 출처가 올바르지 않습니다.' });
  const base = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!base || !key) return res.status(503).json({ code: 'unexpected_failure', msg: '인증 서버 설정을 확인해 주세요.' });
  let payload;
  if (tokenRequest) {
    if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type'] ?? ''))
      return res.status(415).json({ code: 'invalid_request', msg: 'JSON 요청이 필요합니다.' });
    let input;
    try { input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch {}
    if (!input || typeof input !== 'object' || Array.isArray(input))
      return res.status(400).json({ code: 'invalid_request', msg: '인증 요청이 올바르지 않습니다.' });
    if (grant === 'password') {
      if (typeof input.email !== 'string' || !input.email || input.email.length > 320
          || typeof input.password !== 'string' || !input.password || input.password.length > 4096)
        return res.status(400).json({ code: 'invalid_request', msg: '이메일과 비밀번호를 확인해 주세요.' });
      payload = { email: input.email, password: input.password };
    } else {
      if (typeof input.refresh_token !== 'string' || !input.refresh_token || input.refresh_token.length > 8192)
        return res.status(400).json({ code: 'invalid_request', msg: '세션 갱신 요청이 올바르지 않습니다.' });
      payload = { refresh_token: input.refresh_token };
    }
  }
  const headers = { apikey: key, 'Content-Type': 'application/json' };
  if (!tokenRequest) {
    const bearer = req.headers?.authorization;
    if (typeof bearer !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(bearer))
      return res.status(401).json({ code: 'invalid_credentials', msg: '다시 로그인해 주세요.' });
    headers.Authorization = bearer;
  }
  try {
    const origin = new URL(base);
    if (origin.protocol !== 'https:' || origin.username || origin.password) throw new Error();
    const endpoint = new URL('/auth/v1/' + action, origin);
    if (tokenRequest) endpoint.searchParams.set('grant_type', grant);
    if (logoutRequest) endpoint.searchParams.set('scope', 'local');
    const upstream = await fetch(endpoint, { method, headers,
      body: payload ? JSON.stringify(payload) : undefined,
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store' });
    if (upstream.status === 204) return res.status(204).end();
    const data = await upstream.json();
    if (!upstream.ok) {
      const permitted = ['invalid_credentials', 'email_not_confirmed', 'user_banned',
        'over_request_rate_limit', 'over_email_send_rate_limit', 'provider_disabled',
        'email_provider_disabled', 'refresh_token_not_found', 'refresh_token_already_used'];
      const code = permitted.includes(data.code ?? data.error_code) ? (data.code ?? data.error_code) : 'unexpected_failure';
      return res.status(upstream.status).json({ code, msg: '인증 요청을 완료하지 못했습니다.' });
    }
    if (tokenRequest) {
      if (typeof data.access_token !== 'string' || typeof data.refresh_token !== 'string' || !data.user) throw new Error();
      return res.status(200).json({ access_token: data.access_token, refresh_token: data.refresh_token,
        token_type: data.token_type, expires_in: data.expires_in, expires_at: data.expires_at, user: data.user });
    }
    if (userRequest) return res.status(200).json(data);
    return res.status(200).json({});
  } catch {
    return res.status(502).json({ code: 'unexpected_failure', msg: '인증 서버에 연결할 수 없습니다.' });
  }
}
