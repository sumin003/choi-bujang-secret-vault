import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {decide, RULE_IDS} from '../src/decider.mjs';
import {fixtureRequests} from '../scripts/fixture-7.mjs';

const doc=readFileSync(new URL('../docs/DECIDER_REQUEST.md',import.meta.url),'utf8');
const requestSection=doc.split('## 요청')[1].split('현재 계약에는')[0];
const fields=new Set(requestSection.split('\n').filter(l=>l.startsWith('| `'))
  .flatMap(l=>[...l.split('|')[1].matchAll(/`([^`]+)`/g)].map(m=>m[1])));
const responseKeys=['decision','reasonCode','requestId','ruleIds','schema'];

function responseContract(request,output) {
  // Validate serialized form too: no undefined field may disappear in transit.
  const encoded=JSON.parse(JSON.stringify(output));
  assert.deepEqual(Object.keys(encoded).sort(),responseKeys);
  assert.equal(encoded.schema,'aleph.decision.v1');
  assert.equal(encoded.requestId,request.requestId);
  assert.ok(['allow','deny','step_up'].includes(encoded.decision));
  assert.match(encoded.reasonCode,/^[a-z][a-z0-9_]{0,63}$/);
  assert.ok(Array.isArray(encoded.ruleIds)&&encoded.ruleIds.length>0);
  assert.ok(encoded.ruleIds.every(id=>RULE_IDS.includes(id)));
}

test('the documented eighteen request fields are the only properties read',async()=>{
  assert.equal(fields.size,18);
  const {normal,suspicious}=fixtureRequests();
  for(const request of [normal,suspicious,{...normal,deviceRegistered:false},
    {...suspicious,stepUp:{verified:true,authAgeSeconds:60}}]) {
    let forbiddenReads=0;
    const guarded=new Proxy(request,{get(target,key,receiver){
      if(typeof key==='string'&&!fields.has(key)) {
        forbiddenReads++;throw Error('undocumented_request_field');
      }
      return Reflect.get(target,key,receiver);
    }});
    responseContract(request,await decide(guarded));
    assert.equal(forbiddenReads,0);
  }
});

test('extra identity/device/role fields are refused without reading their values',async()=>{
  const {normal}=fixtureRequests();
  for(const field of ['role','identity','device','geo','headers','token']) {
    let accessed=0;const request={...normal};
    Object.defineProperty(request,field,{enumerable:true,get(){accessed++;throw Error('private_value_read');}});
    const output=await decide(request);
    responseContract(request,output);
    assert.equal(output.decision,'deny');assert.equal(accessed,0);
  }
});

test('all virtual request cases return five valid fields and registered rule IDs',async()=>{
  const {normal,suspicious}=fixtureRequests();
  const cases=[normal,suspicious,{...suspicious,stepUp:{verified:true,authAgeSeconds:60}},
    {...normal,deviceRegistered:false},{...normal,deviceRegistered:undefined},
    {...normal,subjectId:'other_learner_fixture'},
    {...normal,path:'/notes',route:'GET /notes'},
    {...normal,service:'instructor_announcements',method:'PUT',path:'/announcements/notice-demo',route:'PUT /announcements/:id'},
    ...[{method:'TRACE'},{path:'/notes/export'},{queryLength:1},{signals:null},
      {stepUp:null},{recentEvents:null},{at:'invalid'},{schema:'invalid'}].map(patch=>({...normal,...patch}))];
  for(const request of cases)responseContract(request,await decide(request));
  assert.equal(new Set(RULE_IDS).size,RULE_IDS.length);
});

test('stage-nine configuration retains the deployment and trust settings',()=>{
  const config=JSON.parse(readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8'));
  assert.ok(Number.isInteger(config.step)&&config.step>=9);
  assert.match(config.repoUrl,/^https:\/\/github\.com\//);
  assert.match(config.publicAppUrl,/^https:\/\//);
  assert.ok(config.allowedRoutes.length>0);
  assert.match(config.originalApiUrl,/^https:\/\//);
  assert.ok(config.identityProvider.issuer&&config.identityProvider.audience&&config.identityProvider.jwksUrl);
});
