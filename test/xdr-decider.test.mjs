import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {createBaseDecider,RULE_IDS} from '../src/decider.mjs';
import {createConnectedDecider} from '../xdr/brute-force/connected-decider.mjs';
const now=Date.now();
const normal=()=>({schema:'aleph.decision.v1',requestId:randomUUID(),classId:'class_fixture',
  projectId:'project_fixture',subjectId:'subject_fixture',deviceId:'a'.repeat(16),service:'notes',
  method:'GET',path:'/notes/test',route:'GET /notes/:id',queryLength:0,
  querySha256:createHash('sha256').update('').digest('hex'),at:new Date(now).toISOString(),
  policyRevision:1,deviceRegistered:true,stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],
  signals:{source:'judge_fixture',region:'unknown',network:'unknown',hour:0}});
const decide=createBaseDecider({now:()=>now});
test('real base decider permits only valid engine-confirmed notes routes',async()=>{
  for(const prefix of ['/notes','/api/notes'])for(const method of ['GET','POST','PUT','DELETE']){
    const path=method==='POST'?prefix:prefix+'/test';
    const request={...normal(),method,path,route:method+' '+prefix+(method==='POST'?'':'/:id')};
    const r=await decide(request);assert.equal(r.decision,'allow');
    assert.deepEqual(Object.keys(r).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
    assert.ok(r.ruleIds.every(id=>RULE_IDS.includes(id)));
  }
});
test('existing starter denial is retained for malformed and unauthorized requests',async()=>{
  const cases=[{deviceRegistered:false},{subjectId:''},{service:'admin'},{path:'/admin',route:'GET /admin'},
    {at:new Date(now-6000).toISOString()},{userId:'forged'},{role:'admin'},
    {stepUp:{verified:true,authAgeSeconds:901}},{requestId:'not-a-uuid'},
    {signals:{source:'browser',region:'unknown',network:'unknown',hour:0}}];
  for(const patch of cases){const r=await decide({...normal(),...patch});
    assert.equal(r.decision,'deny');assert.deepEqual(r.ruleIds,patch.deviceRegistered===false?['device_registered']:['starter.deny']);assert.equal(r.reasonCode,patch.deviceRegistered===false?'device_not_registered':'starter_not_ready');}
});
test('XDR wraps real base: attack deny, normal allow, expiry release, base denial preserved',async()=>{
  let clock=now;
  const r={mode:'isolated_learning_replay',action:'deny',ip:'192.0.2.10',confidence:.95,
    ruleId:'xdr.brute-force.fixture',alertIds:['bf-01'],createdAt:new Date(now).toISOString(),expiresAt:new Date(now+1000).toISOString()};
  const contexts=new Map();
  const connected=createConnectedDecider({mode:'isolated_learning_replay',now:()=>clock,
    getVerifiedSource:async q=>contexts.get(q.requestId),loadRules:async()=>[r]});
  const attack=normal(),good=normal();contexts.set(attack.requestId,r.ip);contexts.set(good.requestId,'192.0.2.60');
  assert.equal((await connected(attack)).decision,'deny');assert.equal((await connected(good)).decision,'allow');
  assert.deepEqual((await connected(attack)).ruleIds,['xdr.brute_force.deny']);
  assert.deepEqual((await connected({...attack,deviceRegistered:false})).ruleIds,['device_registered']);
  clock+=1001;attack.at=new Date(clock).toISOString();assert.equal((await connected(attack)).decision,'allow');
});
