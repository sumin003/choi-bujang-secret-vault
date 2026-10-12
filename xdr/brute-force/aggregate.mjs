import { isIP } from 'node:net';

export const LIMITS = Object.freeze({ windowMs: 180000 });

// Aggregate only: action/confidence are calculated exclusively by decide.mjs.
// Counts must be non-overlapping batches; duplicate alert IDs are counted once.
export function aggregateFailures(alerts, { now = Date.now() } = {}) {
  const groups = new Map(), seen = new Set();
  for (const a of alerts) {
    if (!a || typeof a.id !== 'string' || seen.has(a.id)) continue;
    seen.add(a.id);
    const at = Date.parse(a.timestamp), ip = a.data?.srcip, account = a.data?.srcuser;
    if (!Number.isFinite(at) || at > now || at <= now - LIMITS.windowMs
        || typeof ip !== 'string' || !isIP(ip)
        || typeof account !== 'string' || !account || account.length > 128
        || /[^A-Za-z0-9_.@-]/.test(account)
        || typeof a.rule?.description !== 'string') continue;
    const description = a.rule.description.slice(0,4096);
    const spraying = /(?:같은|동일한?)\s*비밀번호/.test(description)
      && /여러\s*계정|서로\s*다른\s*계정|계정\s*(?:[2-9]|\d{2,})\s*개/.test(description);
    if (!/실패|failed|failure/i.test(description) && !spraying) continue;
    const raw = a.data?.count;
    const count = raw === undefined ? 1 : typeof raw === 'number' ? raw
      : typeof raw === 'string' && /^\d{1,9}$/.test(raw) ? Number(raw) : NaN;
    if (!Number.isSafeInteger(count) || count < 1) continue;
    const key = JSON.stringify([ip,account]);
    const g = groups.get(key) ?? { ip, account, failures: 0, alertIds: [], firstAt: at,
      lastAt: at, descriptions: [], maxLevel: 0 };
    if (!Number.isSafeInteger(g.failures + count)) throw Error('실패 집계 범위를 초과했습니다.');
    g.failures += count;g.alertIds.push(a.id);
    g.firstAt = Math.min(g.firstAt,at);g.lastAt = Math.max(g.lastAt,at);
    if (!g.descriptions.includes(description)) g.descriptions.push(description);
    if (Number.isInteger(a.rule.level) && a.rule.level>=0 && a.rule.level<=16)
      g.maxLevel = Math.max(g.maxLevel,a.rule.level);
    groups.set(key,g);
  }
  return [...groups.values()].map(g => ({...g,
    alert: { timestamp: new Date(g.lastAt).toISOString(),
      data: { srcip:g.ip,srcuser:g.account,count:String(g.failures) },
      rule: {level:g.maxLevel,description:g.descriptions.join(' ').slice(0,4096)} }
  }));
}

// A successful login on the same IP makes address-wide blocking unsafe.
export function normalSourceAddresses(alerts, {now=Date.now()}={}) {
  const ips=new Set();
  for(const a of alerts){
    const at=Date.parse(a?.timestamp),ip=a?.data?.srcip,d=a?.rule?.description;
    if(Number.isFinite(at)&&at<=now&&at>now-LIMITS.windowMs
      &&typeof ip==='string'&&isIP(ip)&&typeof d==='string'
      &&/로그인.*성공|로그인\s*상태.*유지|세션\s*유지|로그아웃|자료실\s*화면/.test(d)
      &&(!/실패/.test(d)||/뒤에?\s*성공|그\s*뒤\s*성공/.test(d)))ips.add(ip);
  }
  return ips;
}
