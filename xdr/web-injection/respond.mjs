import { readFile, writeFile, appendFile, mkdir, rename } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { decide as classify } from './decide.mjs';
import { decide as existingDecide, createBaseDecider, RULE_IDS as BASE_RULE_IDS } from '../../src/decider.mjs';
import { withXdrDenies } from '../brute-force/respond.mjs';

const fixtureUrl = new URL('../fixtures/web-injection.json', import.meta.url);
const rulesUrl = new URL('./deny-rules.json', import.meta.url);
const alertsUrl = new URL('../alerts.log', import.meta.url);
const WINDOW_MS = 3 * 60 * 1000;
const TTL_MS = 15 * 60 * 1000;
const rulePrefix = 'xdr.web-injection.';
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(value)
  && !/sb_(?:secret|publishable)_|eyJ[A-Za-z0-9_-]+\.|gh[pousr]_/i.test(value);
export const RULE_IDS = Object.freeze([...BASE_RULE_IDS, 'xdr.web_injection.deny']);

// Classification stays in decide.mjs. This module owns persistence and response wiring.
export async function respond({ fixture: supplied, now = Date.now(), mode = 'live',
  outputRulesUrl = rulesUrl, outputAlertsUrl = alertsUrl } = {}) {
  if (!Number.isFinite(now) || !['live', 'isolated_learning_replay'].includes(mode))
    throw new Error('응답 설정이 올바르지 않습니다.');
  const fixture = supplied ?? JSON.parse(await readFile(fixtureUrl, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) throw new Error('웹 주입 경보 형식이 올바르지 않습니다.');
  const entries = [], seen = new Set();
  for (const alert of fixture.alerts) {
    if (!safeId(alert?.id)) throw new Error('근거 경보 번호가 올바르지 않습니다.');
    if (seen.has(alert.id)) continue;
    seen.add(alert.id);
    const decision = classify(alert);
    const ip = alert?.data?.srcip;
    const at = Date.parse(alert?.timestamp);
    const current = Number.isFinite(at) && at <= now && at > now - WINDOW_MS;
    entries.push({ alertId: alert.id, decision,
      ip: typeof ip === 'string' && isIP(ip) ? ip : null, at, current });
  }
  // Address-wide blocking cannot safely distinguish users sharing that address.
  const protectedIps = new Set(entries.filter(e => e.current && e.ip
    && e.decision.action === 'record').map(e => e.ip));
  let previous = [];
  try {
    previous = JSON.parse(await readFile(outputRulesUrl, 'utf8')).rules;
    if (!Array.isArray(previous)) throw new Error();
  } catch (error) {
    if (error.code !== 'ENOENT') throw new Error('웹 주입 규칙을 읽을 수 없습니다.');
  }
  const rules = previous.filter(r => r?.moduleKey === 'web-injection' && r.mode === mode
    && Date.parse(r.expiresAt) > now && !protectedIps.has(r.ip));
  const candidates = new Map();
  const lines = [];
  for (const e of entries) {
    const candidate = e.decision.action === 'block' && e.decision.confidence >= 0.85;
    const suppressed = candidate && e.ip && protectedIps.has(e.ip);
    const accepted = candidate && e.current && e.ip && !suppressed;
    if (accepted) {
      const g = candidates.get(e.ip) ?? { alertIds: [], lastAt: e.at, confidence: 0 };
      g.alertIds.push(e.alertId); g.lastAt = Math.max(g.lastAt, e.at);
      g.confidence = Math.max(g.confidence, e.decision.confidence);
      candidates.set(e.ip, g);
    }
    // Never log URL/query/account/body or original descriptions, including rejected inputs.
    lines.push(JSON.stringify({ at: new Date(now).toISOString(), mode, moduleKey: 'web-injection',
      alertId: e.alertId, action: suppressed ? 'alert' : e.decision.action,
      confidence: e.decision.confidence, pattern: e.decision.reason,
      ruleState: accepted ? 'active' : suppressed ? 'shared_ip_suppressed'
        : candidate ? 'expired_or_unusable' : 'not_candidate' }));
  }
  for (const [ip, group] of candidates) {
    const ruleId = rulePrefix + createHash('sha256').update(ip).digest('hex').slice(0,16);
    const existing = rules.find(r => r.ruleId === ruleId);
    const rule = { moduleKey: 'web-injection', ruleId, action: 'deny', mode, ip,
      confidence: group.confidence,
      alertIds: [...new Set([...(existing?.alertIds ?? []), ...group.alertIds])].filter(safeId),
      createdAt: new Date(now).toISOString(), expiresAt: new Date(group.lastAt + TTL_MS).toISOString() };
    const index = rules.findIndex(r => r.ruleId === ruleId);
    if (index < 0) rules.push(rule); else rules[index] = rule;
  }
  await mkdir(new URL('./', outputRulesUrl), { recursive: true });
  const temporary = new URL('./.deny-rules-' + randomUUID() + '.json', outputRulesUrl);
  await writeFile(temporary, JSON.stringify({ rules }, null, 2) + '\n', 'utf8');
  await rename(temporary, outputRulesUrl);
  await mkdir(new URL('./', outputAlertsUrl), { recursive: true });
  if (lines.length) await appendFile(outputAlertsUrl, lines.join('\n') + '\n', 'utf8');
  return { alerts: entries.length, blockCandidates: entries.filter(e => e.decision.action === 'block').length,
    activeRules: rules.length, notifications: lines.length };
}

// Append the web check after the existing brute-force connected decider when both are used.
// If no base is supplied, use the actual ZTNA decider. Never substitute a fake allow policy.
export function createConnectedDecider({ baseDecide, getVerifiedSource,
  denyReasonCode = 'starter_not_ready', now, mode = 'live', loadRules = async () => {
    try { return JSON.parse(await readFile(rulesUrl, 'utf8')).rules; }
    catch (error) { if (error.code === 'ENOENT') return []; throw new Error('웹 주입 규칙을 읽을 수 없습니다.'); }
  } } = {}) {
  const baseline = baseDecide ?? (now ? createBaseDecider({ now }) : existingDecide);
  const ownRules = async () => {
    const rules = await loadRules();
    if (!Array.isArray(rules)) throw new Error('웹 주입 규칙 형식이 올바르지 않습니다.');
    return rules.filter(r => r?.moduleKey === 'web-injection' && r.mode === mode
      && typeof r.ruleId === 'string' && r.ruleId.startsWith(rulePrefix)
      && typeof r.ip === 'string' && isIP(r.ip)
      && Date.parse(r.expiresAt) > Date.parse(r.createdAt)
      && Date.parse(r.expiresAt) - Date.parse(r.createdAt) <= TTL_MS);
  };
  return withXdrDenies(baseline, { getVerifiedSource, denyReasonCode,
    denyRuleId: 'xdr.web_injection.deny', mode, loadRules: ownRules, ...(now ? { now } : {}) });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await respond())); }
  catch { console.error('웹 주입 경보 응답을 처리하지 못했습니다.'); process.exitCode = 1; }
}
