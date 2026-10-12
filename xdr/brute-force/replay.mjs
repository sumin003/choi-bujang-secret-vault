import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
import {respond,withXdrDenies} from './respond.mjs';
import {createConnectedDecider} from './connected-decider.mjs';
import {aggregateFailures} from './aggregate.mjs';
import {decide as classify} from './decide.mjs';

const fixtureUrl=new URL('../fixtures/brute-force.json',import.meta.url);
const original=await readFile(fixtureUrl);
const fixture=JSON.parse(original),now=Date.now();
const replay=structuredClone(fixture);
for(const alert of replay.alerts)alert.timestamp=new Date(now).toISOString();
const temp=await mkdtemp(join(tmpdir(),'xdr-replay-'));
try{
  const rulesUrl=pathToFileURL(join(temp,'rules.json'));
  const summary=await respond({fixture:replay,now,mode:'isolated_learning_replay',
    outputRulesUrl:rulesUrl,outputAlertsUrl:new URL('../alerts.log',import.meta.url)});
  const contexts=new Map();let clock=now;
  // Simulates an already-authorized engine request, not an alternative production policy.
  const existingPolicy=async request=>({schema:'aleph.decision.v1',requestId:request.requestId,
    decision:'allow',reasonCode:'approved',ruleIds:['fixture_existing_policy']});
  const adapter=withXdrDenies(existingPolicy,{getVerifiedSource:async r=>contexts.get(r.requestId),
    denyReasonCode:'fixture_xdr_deny',mode:'isolated_learning_replay',now:()=>clock,
    loadRules:async()=>JSON.parse(await readFile(rulesUrl,'utf8')).rules});
  const results=[];
  for(const a of replay.alerts){
    const request={schema:'aleph.decision.v1',requestId:randomUUID()};
    contexts.set(request.requestId,a.data.srcip);
    const output=await adapter(request);
    const expected=classify(a).action==='block'?'deny':'allow';
    assert.equal(output.decision,expected);
    results.push({alertId:a.id,classification:classify(a).action,expected,observed:output.decision,passed:true});
  }
  const request={requestId:randomUUID()};contexts.set(request.requestId,replay.alerts[0].data.srcip);
  clock+=900001;assert.equal((await adapter(request)).decision,'allow');
  const originalDeny={decision:'deny',reasonCode:'existing_deny',ruleIds:['original']};
  const preserve=withXdrDenies(async()=>originalDeny,{getVerifiedSource:async()=>{throw Error();},denyReasonCode:'fixture_xdr_deny'});
  assert.deepEqual(await preserve(request),originalDeny);
  const event=(id,ip,account,count)=>({id,timestamp:new Date(now).toISOString(),data:{srcip:ip,srcuser:account,count},rule:{level:12,description:'같은 주소와 같은 계정에서 로그인 실패가 연속되었습니다.'}});
  const events=[event('t1','192.0.2.1','user01','12'),event('t2','192.0.2.1','user01','12'),event('t3','192.0.2.1','user02','2')];
  const groups=aggregateFailures([...events,events[0]],{now});
  assert.equal(groups.find(g=>g.account==='user01').failures,24);assert.equal(classify(groups.find(g=>g.account==='user01').alert).action,'block');
  assert.equal(classify(groups.find(g=>g.account==='user02').alert).action,'alert');
  assert.equal(aggregateFailures(events,{now:now+180001}).length,0);
  assert.deepEqual(await readFile(fixtureUrl),original);
  const normalShared={id:'shared-normal',timestamp:new Date(now).toISOString(),data:{srcip:replay.alerts[0].data.srcip,srcuser:'normal_user'},rule:{level:3,description:'로그인이 성공했습니다.'}};
  await respond({fixture:{...replay,alerts:[...replay.alerts,normalShared]},now,mode:'isolated_learning_replay',outputRulesUrl:rulesUrl,outputAlertsUrl:new URL('../alerts.log',import.meta.url)});
  const sharedRules=JSON.parse(await readFile(rulesUrl,'utf8')).rules;
  assert.ok(!sharedRules.some(r=>r.ip===normalShared.data.srcip));
  clock=now;assert.equal((await adapter(request)).decision,'allow');
  // Test the real current ZTNA baseline as well; do not hide its all-deny starter state.
  const realConnected=createConnectedDecider({getVerifiedSource:async()=>normalShared.data.srcip,denyReasonCode:'starter_not_ready',loadRules:async()=>[],now:()=>now});
  const realNormal=await realConnected({schema:'aleph.decision.v1',requestId:randomUUID()});
  assert.equal(realNormal.decision,'deny');
  const output={productionBaselineReady:realNormal.decision==='allow',productionBlocker:realNormal.reasonCode,
    sharedIpProtectionPassed:true,mode:'isolated_learning_replay',activeDuringReplay:summary.active,
    attackDenied:results.filter(r=>r.observed==='deny').length,
    ambiguousAllowed:results.filter(r=>r.classification==='alert'&&r.observed==='allow').length,
    normalAllowed:results.filter(r=>r.classification==='record'&&r.observed==='allow').length,
    expiryPassed:true,existingPolicyPreserved:true,ipAccountAggregationPassed:true,
    duplicateDeduplicationPassed:true,windowExpiryPassed:true,fixtureUnchanged:true,results};
  await writeFile(new URL('./replay-result.json',import.meta.url),JSON.stringify(output,null,2)+'\n');
  console.log(JSON.stringify({...output,results:undefined}));
}finally{await rm(temp,{recursive:true,force:true});}
