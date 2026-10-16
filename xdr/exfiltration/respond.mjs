import { readFile, writeFile, appendFile, mkdir, rename, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { decide as classify } from './decide.mjs';
import { createBaseDecider, RULE_IDS as BASE_RULE_IDS } from '../../src/decider.mjs';

const fixtureUrl = new URL('../fixtures/exfiltration.json', import.meta.url);
const rulesUrl = new URL('./deny-rules.json', import.meta.url);
const alertsUrl = new URL('../alerts.log', import.meta.url);
const WINDOW_MS = 3 * 60 * 1000;
const TTL_MS = 15 * 60 * 1000;
const PREFIX = 'xdr.exfiltration.';
const DENY_RULE = 'xdr.exfiltration.deny';
const MODES = new Set(['live', 'isolated_learning_replay']);
const safeId = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(value)
  && !/sb_(?:secret|publishable)_|eyJ[A-Za-z0-9_-]+\.|gh[pousr]_|github_pat_|[A-Za-z0-9_+=/]{32,}/i.test(value);
export const RULE_IDS = Object.freeze([...BASE_RULE_IDS, DENY_RULE]);

function validRule(rule, mode) {
  const created = Date.parse(rule?.createdAt), expires = Date.parse(rule?.expiresAt);
  return rule?.moduleKey === 'exfiltration' && rule.mode === mode && rule.action === 'deny' && rule.target === 'destination_ip'
    && typeof rule.ruleId === 'string' && new RegExp('^' + PREFIX.replace(/\./g, '\\.') + '[a-f0-9]{16}$').test(rule.ruleId)
    && typeof rule.destinationIp === 'string' && isIP(rule.destinationIp) !== 0
    && Number.isFinite(rule.confidence) && rule.confidence >= 0.85 && rule.confidence <= 1
    && Array.isArray(rule.alertIds) && rule.alertIds.length > 0 && rule.alertIds.every(safeId)
    && Number.isFinite(created) && Number.isFinite(expires) && expires > created && expires - created <= TTL_MS;
}
async function readRules(url) {
  try {
    const parsed = JSON.parse(await readFile(url, 'utf8'));
    if (!parsed || !Array.isArray(parsed.rules)) throw new Error();
    return parsed.rules;
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('자료 유출 차단 규칙을 읽을 수 없습니다.');
  }
}

// Defaults write only this module's deny file and append sanitized alert lines.
// Historic fixtures are not made live by changing their timestamps.
export async function respond({ fixture: supplied, now = Date.now(), mode = 'live',
  outputRulesUrl = rulesUrl, outputAlertsUrl = alertsUrl } = {}) {
  if (!Number.isFinite(now) || !Number.isFinite(new Date(now).getTime()) || !MODES.has(mode))
    throw new Error('응답 설정이 올바르지 않습니다.');
  let fixture = supplied;
  if (fixture === undefined) {
    try { fixture = JSON.parse(await readFile(fixtureUrl, 'utf8')); }
    catch { throw new Error('자료 유출 경보를 읽을 수 없습니다.'); }
  }
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'exfiltration'
      || !Array.isArray(fixture.alerts)) throw new Error('자료 유출 경보 형식이 올바르지 않습니다.');
  const entries = [], seen = new Set();
  for (const alert of fixture.alerts) {
    if (!safeId(alert?.id) || seen.has(alert.id)) throw new Error('근거 경보 번호가 올바르지 않습니다.');
    seen.add(alert.id);
    const decision = classify(alert), destinationIp = alert?.data?.dstip, at = Date.parse(alert?.timestamp);
    entries.push({ alertId: alert.id, decision, destinationIp: typeof destinationIp === 'string' && isIP(destinationIp) ? destinationIp : null,
      at, current: Number.isFinite(at) && at <= now && at > now - WINDOW_MS });
  }
  // A shared destination with a normal current event is never blocked by this batch.
  const protectedIps = new Set(entries.filter(e => e.current && e.destinationIp && e.decision.action === 'record').map(e => e.destinationIp));
  const previous = await readRules(outputRulesUrl);
  const rules = previous.filter(rule => {
    if (rule?.moduleKey !== 'exfiltration' || rule.mode !== mode) return true;
    return validRule(rule, mode) && Date.parse(rule.expiresAt) > now && Date.parse(rule.createdAt) <= now && !protectedIps.has(rule.destinationIp);
  });
  const groups = new Map(), lines = [];
  for (const entry of entries) {
    const candidate = entry.decision.action === 'block' && entry.decision.confidence >= 0.85;
    const suppressed = candidate && entry.destinationIp && protectedIps.has(entry.destinationIp);
    const eligible = candidate && entry.current && entry.destinationIp && !suppressed;
    if (eligible) {
      const group = groups.get(entry.destinationIp) ?? { alertIds: [], lastAt: entry.at, confidence: 0 };
      group.alertIds.push(entry.alertId); group.lastAt = Math.max(group.lastAt, entry.at);
      group.confidence = Math.max(group.confidence, entry.decision.confidence); groups.set(entry.destinationIp, group);
    }
    // No original payload, header, URL, account, description or source IP is logged.
    lines.push(JSON.stringify({ at: new Date(now).toISOString(), moduleKey:'exfiltration', mode,
      alertId:entry.alertId, action:suppressed ? 'alert' : entry.decision.action,
      confidence:entry.decision.confidence, pattern:entry.decision.reason,
      ruleState:eligible ? 'eligible_candidate' : suppressed ? 'shared_destination_suppressed'
        : candidate ? 'stale_or_unusable' : 'not_candidate' }));
  }
  for (const [destinationIp, group] of groups) {
    const ruleId = PREFIX + createHash('sha256').update(mode + ':destination:' + destinationIp).digest('hex').slice(0,16);
    const index = rules.findIndex(rule => rule?.ruleId === ruleId && rule.moduleKey === 'exfiltration' && rule.mode === mode);
    const prior = index >= 0 ? rules[index] : null;
    const rule = { moduleKey:'exfiltration', ruleId, action:'deny', target:'destination_ip', mode, destinationIp, confidence:group.confidence,
      alertIds:[...new Set([...(prior?.alertIds ?? []), ...group.alertIds])],
      createdAt:new Date(now).toISOString(), expiresAt:new Date(group.lastAt + TTL_MS).toISOString() };
    if (index < 0) rules.push(rule); else rules[index] = rule;
  }
  await mkdir(new URL('./', outputRulesUrl), { recursive:true });
  await mkdir(new URL('./', outputAlertsUrl), { recursive:true });
  const temporary = new URL('./.exfiltration-rules-' + randomUUID() + '.json', outputRulesUrl);
  try {
    await writeFile(temporary, JSON.stringify({rules}, null, 2) + '\n', {encoding:'utf8',flag:'wx'});
    if (lines.length) await appendFile(outputAlertsUrl, lines.join('\n') + '\n', 'utf8');
    await rename(temporary, outputRulesUrl);
  } finally { await rm(temporary, {force:true}); }
  return { alerts:entries.length, blockCandidates:entries.filter(e => e.decision.action === 'block').length,
    activeRules:rules.filter(r => validRule(r, mode) && Date.parse(r.createdAt) <= now && Date.parse(r.expiresAt) > now).length,
    notifications:lines.length };
}

// Add only a destination deny check. The caller must supply the server-verified
// destination separately; never derive it from browser headers/body or source IP.
export function createConnectedDecider({ baseDecide, getVerifiedDestination, denyReasonCode = 'starter_not_ready',
  now = () => Date.now(), mode = 'live', loadRules = () => readRules(rulesUrl) } = {}) {
  if (!MODES.has(mode) || typeof getVerifiedDestination !== 'function'
    || typeof now !== 'function' || typeof loadRules !== 'function'
    || typeof denyReasonCode !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(denyReasonCode))
    throw new Error('기존 판정기와 서버 검증 목적지 연결을 확인해 주세요.');
  const baseline = baseDecide ?? createBaseDecider({now});
  if (typeof baseline !== 'function') throw new Error('기존 판정기가 필요합니다.');
  return async request => {
    const original = await baseline(request);
    if (original?.decision !== 'allow') return original;
    const rules = await loadRules();
    if (!Array.isArray(rules)) throw new Error('차단 규칙 형식이 올바르지 않습니다.');
    const at = now();
    const active = rules.filter(rule => validRule(rule, mode)
      && Date.parse(rule.createdAt) <= at && Date.parse(rule.expiresAt) > at);
    if (!active.length) return original;
    const destination = await getVerifiedDestination(request);
    if (typeof destination !== 'string' || !isIP(destination))
      throw new Error('서버 검증 목적지가 없습니다.');
    if (!active.some(rule => rule.destinationIp === destination)) return original;
    return {schema:'aleph.decision.v1',requestId:original.requestId,decision:'deny',
      reasonCode:denyReasonCode,ruleIds:[DENY_RULE]};
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await respond())); }
  catch { console.error('자료 유출 경보 응답을 처리하지 못했습니다.'); process.exitCode = 1; }
}
