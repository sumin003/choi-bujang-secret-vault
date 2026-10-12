import { isIP } from 'node:net';
import policy from '../xdr/brute-force/deny-rules.json' with { type: 'json' };

// Vercel supplies this header at its trusted proxy boundary.
// Outside Vercel, only the TCP peer is accepted, never a client forwarding header.
export function requestSource(req, { vercel = process.env.VERCEL === '1' } = {}) {
  const raw = vercel ? req.headers?.['x-vercel-forwarded-for'] : req.socket?.remoteAddress;
  if (typeof raw !== 'string' || raw.includes(',')) return null;
  const ip = raw.trim().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, '');
  return isIP(ip) ? ip : null;
}

export function checkXdr(req, { rules = policy.rules, now = Date.now(), vercel } = {}) {
  if (!Array.isArray(rules)) throw new Error('INVALID_XDR_POLICY');
  const active = rules.filter(rule => rule?.mode === 'live' && rule.action === 'deny'
    && typeof rule.ip === 'string' && isIP(rule.ip)
    && typeof rule.ruleId === 'string' && /^xdr\.brute-force\.[a-z0-9.-]+$/i.test(rule.ruleId)
    && Number.isFinite(rule.confidence) && rule.confidence >= 0.85 && rule.confidence <= 1
    && Array.isArray(rule.alertIds) && rule.alertIds.length > 0
    && rule.alertIds.every(id => typeof id === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(id))
    && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now
    && Date.parse(rule.expiresAt) - Date.parse(rule.createdAt) <= 15 * 60 * 1000);
  if (!active.length) return 'no-active-rules';
  const ip = requestSource(req, { vercel });
  if (!ip) return 'source-unavailable';
  return active.some(rule => rule.ip === ip) ? 'blocked' : 'allowed';
}

export function enforceXdr(req, res, options) {
  let state;
  try { state = checkXdr(req, options); } catch { state = 'policy-unavailable'; }
  res.setHeader('X-XDR-Check', state);
  if (state === 'blocked') {
    res.status(403).json({ error: 'XDR_BLOCKED', code: 'xdr_blocked',
      msg: '이 출발 주소의 접근이 일시적으로 제한되었습니다.' });
    return false;
  }
  if (state === 'source-unavailable' || state === 'policy-unavailable') {
    res.status(503).json({ error: 'XDR_UNAVAILABLE', code: 'unexpected_failure',
      msg: '접근 검사를 완료하지 못했습니다.' });
    return false;
  }
  return true;
}

