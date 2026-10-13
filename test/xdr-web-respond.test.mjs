import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash,randomUUID} from 'node:crypto';
import {respond,createConnectedDecider,RULE_IDS} from '../xdr/web-injection/respond.mjs';
import {createConnectedDecider as connectBruteForce} from '../xdr/brute-force/connected-decider.mjs';
const fixtureUrl=new URL('../xdr/fixtures/web-injection.json',import.meta.url);

test('web candidates connect to real ZTNA; ambiguous and normal requests pass; original rules stay intact',async()=>{
  const original=await readFile(fixtureUrl);
  const baseBefore=await readFile(new URL('../src/decider.mjs',import.meta.url));
  const classifyBefore=await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url));
  const fixture=JSON.parse(original),now=Date.now();let clock=now;
  fixture.alerts.forEach(a=>a.timestamp=new Date(now).toISOString());
  const temp=await mkdtemp(join(tmpdir(),'xdr-web-'));
  try{
    const rulesUrl=pathToFileURL(join(temp,'rules.json')),logUrl=pathToFileURL(join(temp,'alerts.log'));
    const opts={fixture,now,mode:'isolated_learning_replay',outputRulesUrl:rulesUrl,outputAlertsUrl:logUrl};
    const summary=await respond(opts);assert.equal(summary.blockCandidates,8);assert.equal(summary.activeRules,7);assert.equal(summary.notifications,26);
    const policies=JSON.parse(await readFile(rulesUrl,'utf8')).rules;
    assert.ok(policies.every(r=>r.alertIds.length>0&&Date.parse(r.expiresAt)>now));
    const contexts=new Map();
    const getVerifiedSource=async r=>contexts.get(r.requestId);
    const brute=connectBruteForce({getVerifiedSource,now:()=>clock,mode:'isolated_learning_replay',loadRules:async()=>[]});
    const connected=createConnectedDecider({baseDecide:brute,getVerifiedSource,now:()=>clock,mode:'isolated_learning_replay',
      loadRules:async()=>JSON.parse(await readFile(rulesUrl,'utf8')).rules});
    const request=ip=>{const r={schema:'aleph.decision.v1',requestId:randomUUID(),classId:'class_fixture',projectId:'project_fixture',subjectId:'subject_fixture',
      deviceId:'a'.repeat(16),service:'notes',method:'GET',path:'/notes/test',route:'GET /notes/:id',queryLength:0,
      querySha256:createHash('sha256').update('').digest('hex'),at:new Date(clock).toISOString(),policyRevision:1,
      deviceRegistered:true,stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],
      signals:{source:'judge_fixture',region:'unknown',network:'unknown',hour:0}};contexts.set(r.requestId,ip);return r;};
    for(let i=0;i<fixture.alerts.length;i++){
      const r=await connected(request(fixture.alerts[i].data.srcip));assert.equal(r.decision,i<8?'deny':'allow');
      assert.ok(r.ruleIds.every(id=>RULE_IDS.includes(id)));
      assert.deepEqual(Object.keys(r).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
    }
    const invalid={...request(fixture.alerts[0].data.srcip),deviceRegistered:false};
    assert.deepEqual((await connected(invalid)).ruleIds,['device_registered']);
    clock=now+900001;assert.equal((await connected(request(fixture.alerts[0].data.srcip))).decision,'allow');clock=now;
    const shared={id:'wi-shared-normal',timestamp:new Date(now).toISOString(),rule:{level:3,description:'자료 목록을 조회했습니다.'},
      data:{srcip:fixture.alerts[0].data.srcip,url:'/api/notes'}};
    await respond({...opts,fixture:{...fixture,alerts:[...fixture.alerts,shared]}});
    assert.equal((await connected(request(shared.data.srcip))).decision,'allow');
    const lines=(await readFile(logUrl,'utf8')).trim().split('\n');lines.forEach(line=>JSON.parse(line));
    assert.ok(!lines.join('').includes('doc-sql-chain'));
    const sharedLog=lines.map(l=>JSON.parse(l)).find(l=>l.ruleState==='shared_ip_suppressed');assert.equal(sharedLog.action,'alert');
    assert.deepEqual(await readFile(fixtureUrl),original);
    assert.deepEqual(await readFile(new URL('../src/decider.mjs',import.meta.url)),baseBefore);
    assert.deepEqual(await readFile(new URL('../xdr/web-injection/decide.mjs',import.meta.url)),classifyBefore);
  }finally{await rm(temp,{recursive:true,force:true});}
});
test('past fixture never creates a current ban and malformed evidence does not get logged',async()=>{
  const temp=await mkdtemp(join(tmpdir(),'xdr-web-old-'));
  try{
    const rules=pathToFileURL(join(temp,'rules.json')),logs=pathToFileURL(join(temp,'alerts.log'));
    const result=await respond({outputRulesUrl:rules,outputAlertsUrl:logs});assert.equal(result.activeRules,0);assert.equal(result.notifications,26);
    const fixture=JSON.parse(await readFile(fixtureUrl,'utf8'));fixture.alerts[0].id='sb_secret_synthetic';
    const before=await readFile(logs);
    await assert.rejects(respond({fixture,outputRulesUrl:rules,outputAlertsUrl:logs}));
    assert.deepEqual(await readFile(logs),before);
  }finally{await rm(temp,{recursive:true,force:true});}
});
