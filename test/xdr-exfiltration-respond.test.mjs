import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {respond,createConnectedDecider,RULE_IDS} from '../xdr/exfiltration/respond.mjs';
import {createBaseDecider} from '../src/decider.mjs';
import {fixtureRequests} from '../scripts/fixture-7.mjs';
const fixture=JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json',import.meta.url),'utf8'));
const mode='isolated_learning_replay';
async function sandbox(fn){const dir=await mkdtemp(join(tmpdir(),'exfiltration-response-'));try{await fn(dir)}finally{await rm(dir,{recursive:true,force:true})}}
const bundle=alerts=>({schema:fixture.schema,moduleKey:'exfiltration',alerts});
const requestAt=at=>({...fixtureRequests().normal,at:new Date(at).toISOString()});
const getRules=async url=>JSON.parse(await readFile(url,'utf8')).rules;

test('actual ZTNA baseline plus deny-only connection: attacks denied, ambiguous and normal retained',()=>sandbox(async dir=>{
 const preservedPaths=['../src/decider.mjs','../xdr/fixtures/exfiltration.json','../xdr/exfiltration/decide.mjs','../xdr/brute-force/deny-rules.json','../xdr/web-injection/deny-rules.json','../xdr/alerts.log'];
 const hashes=await Promise.all(preservedPaths.map(async p=>createHash('sha256').update(await readFile(new URL(p,import.meta.url))).digest('hex')));
 const log=pathToFileURL(join(dir,'alerts.log'));let denied=0,allowed=0;
 for(const [index,alert]of fixture.alerts.entries()){
  const clock=Date.parse(alert.timestamp),rulesUrl=pathToFileURL(join(dir,'rules-'+index+'.json'));
  const report=await respond({fixture:bundle([alert]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
  const baseline=createBaseDecider({now:()=>clock});const request=requestAt(clock);
  assert.equal((await baseline(request)).decision,'allow');
  const connected=createConnectedDecider({getVerifiedDestination:()=>alert.data.dstip,now:()=>clock,mode,loadRules:()=>getRules(rulesUrl)});
  const decision=await connected(request),rules=await getRules(rulesUrl);
  if(index<10){assert.equal(decision.decision,'deny');assert.equal(report.activeRules,1);denied++;
   assert.equal(rules[0].target,'destination_ip');assert.equal(rules[0].destinationIp,alert.data.dstip);assert.equal(rules[0].ip,undefined);assert.ok(rules[0].alertIds.includes(alert.id));assert.ok(Date.parse(rules[0].expiresAt)>clock);
   assert.ok(Date.parse(rules[0].expiresAt)-Date.parse(rules[0].createdAt)<=15*60000);
  }else{assert.equal(decision.decision,'allow');assert.equal(report.activeRules,0);allowed++}
  assert.ok(decision.ruleIds.every(id=>RULE_IDS.includes(id)));
 }
 assert.equal(denied,10);assert.equal(allowed,20);
 const lines=(await readFile(log,'utf8')).trim().split('\n');assert.equal(lines.length,30);
 for(const line of lines){const entry=JSON.parse(line);assert.equal(entry.moduleKey,'exfiltration');for(const key of ['url','useragent','srcuser','ip','description','password'])assert.equal(entry[key],undefined)}
 for(const [i,p]of preservedPaths.entries())assert.equal(createHash('sha256').update(await readFile(new URL(p,import.meta.url))).digest('hex'),hashes[i]);
}));

test('normal events on shared destinations suppress new denies and remove own active denies while preserving other rules and logs',()=>sandbox(async dir=>{
 const attack=fixture.alerts[0],clock=Date.parse(attack.timestamp),rulesUrl=pathToFileURL(join(dir,'rules.json')),log=pathToFileURL(join(dir,'alerts.log'));
 await writeFile(log,'previous audit entry\n');
 await respond({fixture:bundle([attack]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
 const rules=await getRules(rulesUrl),other={moduleKey:'other-module',ruleId:'keep-this-rule'};
 await writeFile(rulesUrl,JSON.stringify({rules:[...rules,other]}));
 const normal={...fixture.alerts[20],timestamp:attack.timestamp,data:{...fixture.alerts[20].data,dstip:attack.data.dstip}};
 const report=await respond({fixture:bundle([attack,normal]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
 assert.equal(report.activeRules,0);assert.deepEqual(await getRules(rulesUrl),[other]);
 const lines=(await readFile(log,'utf8')).trim().split('\n');assert.equal(lines[0],'previous audit entry');assert.equal(lines.length,4);
 assert.equal(JSON.parse(lines[2]).ruleState,'shared_destination_suppressed');assert.equal(JSON.parse(lines[2]).action,'alert');
}));

test('stale, future and unusable destinations cannot create denies; modes and expiration remain isolated',()=>sandbox(async dir=>{
 const attack=fixture.alerts[0],at=Date.parse(attack.timestamp),log=pathToFileURL(join(dir,'alerts.log'));
 for(const [n,clock,alert]of [[0,at+180001,attack],[1,at-1,attack],[2,at,{...attack,data:{...attack.data,dstip:'not-an-address'}}]]){
  const report=await respond({fixture:bundle([alert]),now:clock,mode,outputRulesUrl:pathToFileURL(join(dir,n+'.json')),outputAlertsUrl:log});assert.equal(report.activeRules,0);
 }
 const rulesUrl=pathToFileURL(join(dir,'active.json'));let clock=at;
 await respond({fixture:bundle([attack]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
 const connected=createConnectedDecider({getVerifiedDestination:()=>attack.data.dstip,now:()=>clock,mode,loadRules:()=>getRules(rulesUrl)});
 assert.equal((await connected(requestAt(clock))).decision,'deny');
 const live=createConnectedDecider({getVerifiedDestination:()=>attack.data.dstip,now:()=>clock,mode:'live',loadRules:()=>getRules(rulesUrl)});
 assert.equal((await live(requestAt(clock))).decision,'allow');
 clock+=15*60000;assert.equal((await connected(requestAt(clock))).decision,'allow');
}));

test('existing deny and step-up results are preserved before consulting the destination',async()=>{
 let reads=0;const clock=Date.now();const connected=createConnectedDecider({now:()=>clock,mode,getVerifiedDestination:()=>{reads++;throw Error('must not read')},loadRules:async()=>[]});
 const unregistered={...requestAt(clock),deviceRegistered:false};assert.equal((await connected(unregistered)).reasonCode,'device_not_registered');
 const unusual={...fixtureRequests().suspicious,at:new Date(clock).toISOString()};assert.equal((await connected(unusual)).decision,'step_up');assert.equal(reads,0);
});

test('duplicate or credential-like evidence IDs fail before writing; private payloads never enter logs',()=>sandbox(async dir=>{
 const attack=fixture.alerts[0],clock=Date.parse(attack.timestamp),rulesUrl=pathToFileURL(join(dir,'rules.json')),log=pathToFileURL(join(dir,'alerts.log'));
 for(const alerts of [[attack,attack],[{...attack,id:'sb_secret_test'}]]){
  await assert.rejects(respond({fixture:bundle(alerts),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log}),/근거 경보 번호/);
 }
 await assert.rejects(readFile(rulesUrl),{code:'ENOENT'});await assert.rejects(readFile(log),{code:'ENOENT'});
 const secret='fixture-private-value';const dirty={...attack,data:{...attack.data,password:secret,srcuser:secret},full_log:secret};
 await respond({fixture:bundle([dirty]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
 assert.equal((await readFile(log,'utf8')).includes(secret),false);assert.equal((await readFile(rulesUrl,'utf8')).includes(secret),false);
}));

test('same PC retains normal destinations; attack destinations are denied across sources without source fallback',()=>sandbox(async dir=>{
 const attack=fixture.alerts[0],clock=Date.parse(attack.timestamp);
 const normal={...fixture.alerts[20],timestamp:attack.timestamp,data:{...fixture.alerts[20].data,srcip:attack.data.srcip}};
 const second={...fixture.alerts[2],timestamp:attack.timestamp};
 const rulesUrl=pathToFileURL(join(dir,'destination-rules.json')),log=pathToFileURL(join(dir,'alerts.log'));
 await respond({fixture:bundle([attack,second,normal]),now:clock,mode,outputRulesUrl:rulesUrl,outputAlertsUrl:log});
 const rules=await getRules(rulesUrl);
 assert.equal(rules.length,1);assert.equal(rules[0].destinationIp,attack.data.dstip);
 assert.ok(rules[0].alertIds.includes(attack.id)&&rules[0].alertIds.includes(second.id));
 let destination=attack.data.dstip;
 const connected=createConnectedDecider({now:()=>clock,mode,getVerifiedDestination:()=>destination,loadRules:()=>getRules(rulesUrl)});
 assert.equal((await connected(requestAt(clock))).decision,'deny');
 destination=normal.data.dstip;assert.equal((await connected(requestAt(clock))).decision,'allow');
 destination=attack.data.srcip;assert.equal((await connected(requestAt(clock))).decision,'allow');
 destination=undefined;await assert.rejects(connected(requestAt(clock)),/서버 검증 목적지/);
 assert.throws(()=>createConnectedDecider({getVerifiedSource:()=>attack.data.srcip}),/서버 검증 목적지/);
 const missing={...attack,data:{srcip:attack.data.srcip}};
 const report=await respond({fixture:bundle([missing]),now:clock,mode,outputRulesUrl:pathToFileURL(join(dir,'missing.json')),outputAlertsUrl:log});
 assert.equal(report.activeRules,0);
}));
