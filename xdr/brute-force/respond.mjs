import { readFile, writeFile, appendFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { aggregateFailures, normalSourceAddresses } from './aggregate.mjs';
import { decide as classify } from './decide.mjs';

const fixtureUrl=new URL('../fixtures/brute-force.json',import.meta.url);
const rulesUrl=new URL('./deny-rules.json',import.meta.url);
const alertsUrl=new URL('../alerts.log',import.meta.url);
const ttlMs=15*60*1000;
const idOK=v=>typeof v==='string'&&/^[A-Za-z0-9_.:-]{1,128}$/.test(v);

export async function respond({fixture: supplied, now=Date.now(), mode='live',
  outputRulesUrl=rulesUrl,outputAlertsUrl=alertsUrl}={}) {
  const fixture=supplied??JSON.parse(await readFile(fixtureUrl,'utf8'));
  if(fixture?.schema!=='aleph.xdr.fixture.v1'||fixture.moduleKey!=='brute-force'
     ||!Array.isArray(fixture.alerts)||!Number.isFinite(now))throw Error('경보 형식이 올바르지 않습니다.');
  const groups=aggregateFailures(fixture.alerts,{now});
  const protectedIps=normalSourceAddresses(fixture.alerts,{now});
  let previous=[];
  try{previous=JSON.parse(await readFile(outputRulesUrl,'utf8')).rules;
    if(!Array.isArray(previous))throw Error();
  }catch(e){if(e.code!=='ENOENT')throw Error('규칙 파일을 읽을 수 없습니다.');}
  const rules=previous.filter(r=>r.mode===mode&&Date.parse(r.expiresAt)>now&&!protectedIps.has(r.ip));
  const lines=[];
  for(const group of groups){
    const decision=classify(group.alert);
    const sharedAddress=protectedIps.has(group.ip);
    const action=decision.action==='block'&&sharedAddress?'alert':decision.action;
    const evidenceIds=group.alertIds.filter(idOK);
    if(evidenceIds.length!==group.alertIds.length)throw Error('경보 번호가 올바르지 않습니다.');
    const groupId=createHash('sha256').update(JSON.stringify([group.ip,group.account])).digest('hex');
    if(action==='block'&&decision.confidence>=.85){
      const ruleId='xdr.brute-force.'+groupId.slice(0,16);
      const rule={ruleId,action:'deny',ip:group.ip,mode,confidence:decision.confidence,
        alertIds:evidenceIds,createdAt:new Date(now).toISOString(),
        expiresAt:new Date(group.lastAt+ttlMs).toISOString()};
      const i=rules.findIndex(r=>r.ruleId===ruleId);if(i<0)rules.push(rule);else rules[i]=rule;
    }
    // No account, credentials or original description is copied to alerts.log.
    lines.push(JSON.stringify({at:new Date(now).toISOString(),mode,
      moduleKey:'brute-force',groupId,alertIds:evidenceIds,failures:group.failures,
      action,confidence:decision.confidence,pattern:decision.reason,
      suppression:sharedAddress&&decision.action==='block'?'normal_login_on_shared_ip':null}));
  }
  await mkdir(new URL('./',outputRulesUrl),{recursive:true});
  await writeFile(outputRulesUrl,JSON.stringify({rules},null,2)+'\n');
  if(lines.length)await appendFile(outputAlertsUrl,lines.join('\n')+'\n');
  return {groups:groups.length,active:rules.length,notifications:lines.length};
}

// The trusted server integration supplies an IP from its transport context.
// Never derive it from the request body, raw X-Forwarded-For, account or browser input.
export function withXdrDenies(baseDecide,{getVerifiedSource,denyReasonCode,denyRuleId,
  now=()=>Date.now(),mode='live',loadRules=async()=>{
    try{return JSON.parse(await readFile(rulesUrl,'utf8')).rules;}
    catch(e){if(e.code==='ENOENT')return [];throw Error('XDR 규칙을 읽을 수 없습니다.');}
  }}={}){
  if(typeof baseDecide!=='function'||typeof getVerifiedSource!=='function'||!idOK(denyReasonCode))
    throw Error('기존 판정기·서버 검증 출발 주소·등록된 거부 사유 코드가 필요합니다.');
  return async function decide(request){
    const baseline=await baseDecide(request);
    if(baseline?.decision!=='allow')return baseline;
    const source=await getVerifiedSource(request);
    if(typeof source!=='string'||!isIP(source))throw Error('서버 검증 출발 주소가 없습니다.');
    const rules=await loadRules();if(!Array.isArray(rules))throw Error('규칙 형식이 올바르지 않습니다.');
    const at=now();
    const match=rules.find(r=>r.mode===mode&&r.action==='deny'&&r.ip===source
      &&idOK(r.ruleId)&&r.confidence>=.85&&r.confidence<=1
      &&Array.isArray(r.alertIds)&&r.alertIds.length>0&&r.alertIds.every(idOK)
      &&Date.parse(r.createdAt)<=at&&Date.parse(r.expiresAt)>at);
    return match?{schema:'aleph.decision.v1',requestId:request.requestId,decision:'deny',
      reasonCode:denyReasonCode,ruleIds:[denyRuleId??match.ruleId]}:baseline;
  };
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{console.log(JSON.stringify(await respond()));}
  catch{console.error('XDR 응답 연결을 실행하지 못했습니다.');process.exitCode=1;}
}
