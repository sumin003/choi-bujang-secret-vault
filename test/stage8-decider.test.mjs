import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { decide, createBaseDecider } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

function own(patch={}) {return {...fixtureRequests().normal,...patch};}
function single(subjectId,id,method='GET',notice=false) {
  const prefix=notice?'/announcements':'/notes';
  return own({subjectId,service:notice?'instructor_announcements':'notes',method,
    path:prefix+'/'+id,route:method+' '+prefix+'/:id'});
}
async function expect(request,decision) {
  const output=await decide(request);
  assert.equal(output.decision,decision);
  assert.deepEqual(Object.keys(output).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(output.requestId,request.requestId);
  return output;
}

test('supplied original normal /notes/demo is allowed by the exported decider',async()=>{
  await expect(own(),'allow');
});
test('the owner can read and update the registered fixture note',async()=>{
  for(const method of ['GET','PUT'])await expect(single('learner_fixture','demo',method),'allow');
});
test('B cannot read or update A note by reusing the exact same resource path',async()=>{
  for(const method of ['GET','PUT','DELETE']) {
    const r=await expect(single('other_learner_fixture','demo',method),'deny');
    assert.deepEqual(r.ruleIds,['resource_zone']);
  }
});
test('B own registered fixture note remains allowed',async()=>{
  for(const method of ['GET','PUT'])await expect(single('other_learner_fixture','other-demo',method),'allow');
});
test('students cannot create, update or delete instructor announcements',async()=>{
  for(const subjectId of ['learner_fixture','other_learner_fixture']) {
    for(const method of ['PUT','DELETE'])await expect(single(subjectId,'notice-demo',method,true),'deny');
    await expect(own({subjectId,service:'instructor_announcements',method:'POST',
      path:'/announcements',route:'POST /announcements'}),'deny');
  }
});
test('no engine subject can write notices, including a synthetic instructor',async()=>{
  for(const subjectId of ['learner_fixture','other_learner_fixture','teacher_fixture'])
    for(const prefix of ['/announcements','/api/announcements'])
      for(const method of ['POST','PUT','PATCH','DELETE']) {
        const collection=method==='POST';
        await expect(own({subjectId,service:'instructor_announcements',method,
          path:prefix+(collection?'':'/notice-demo'),
          route:method+' '+prefix+(collection?'':'/:id')}),'deny');
      }
});
test('engine denies note collection reads while preserving creation and individual reads',async()=>{
  for(const subjectId of ['learner_fixture','other_learner_fixture'])
    for(const path of ['/notes','/api/notes']) {
      const denied=await expect(own({subjectId,method:'GET',path,route:'GET '+path}),'deny');
      assert.deepEqual(denied.ruleIds,['resource_zone']);
      await expect(own({subjectId,method:'POST',path,route:'POST '+path}),'allow');
    }
  await expect(own(),'allow');
});
test('stored or injected authorization cannot bypass forbidden engine zones',async()=>{
  let checked=0;
  const engine=createBaseDecider({authorizeResource:async()=>{checked++;return true;}});
  for(const r of [own({path:'/notes',route:'GET /notes'}),
    single('teacher_fixture','notice-demo','PUT',true)]) {
    const denied=await engine(r);
    assert.equal(denied.decision,'deny');assert.deepEqual(denied.ruleIds,['resource_zone']);
  }
  assert.equal(checked,0);
});
test('unregistered IDs and substring-like subject names never grant ownership',async()=>{
  for(const r of [single('learner_fixture_evil','demo'),single('other_learner_fixture','learner_fixture-demo'),
    single('learner_fixture','unknown-resource'),single('unknown_subject','demo')])await expect(r,'deny');
});
test('unknown routes, additional path depth, feature names and method mismatch are refused',async()=>{
  for(const r of [own({path:'/notes/export'}),own({path:'/notes/EXPORT'}),
    own({path:'/notes/demo/export'}),own({path:'/other/demo',route:'GET /other/:id'}),
    own({method:'PUT'}),own({method:'POST',route:'POST /notes/:id'})])await expect(r,'deny');
});
test('function query or extra client claims cannot bypass the policy',async()=>{
  for(const patch of [{queryLength:12},{role:'instructor'},{headers:{role:'instructor'}},
    {owner_id:'learner_fixture'}])await expect(own(patch),'deny');
});
test('device and step-up rules precede final access',async()=>{
  assert.equal((await expect(own({deviceRegistered:false}),'deny')).reasonCode,'device_not_registered');
  const {suspicious}=fixtureRequests();
  assert.equal((await expect(suspicious,'step_up')).reasonCode,'step_up_required');
  await expect({...suspicious,stepUp:{verified:true,authAgeSeconds:60}},'allow');
});
test('synthetic policy cannot be promoted to an unrelated class or project',async()=>{
  for(const patch of [{classId:'other_class'},{projectId:'other_project'},
    {signals:{source:'none',region:'unknown',network:'unknown',hour:14}}])await expect(own(patch),'deny');
});

test('decider alone loads and evaluates without sibling modules, packages or server globals',()=>{
  const source=readFileSync(new URL('../src/decider.mjs',import.meta.url),'utf8');
  assert.doesNotMatch(source,/^\s*import\b/m);
  const {normal,suspicious}=fixtureRequests();
  const program=`
    import {readFileSync} from 'node:fs';
    const {source,normal,suspicious}=JSON.parse(readFileSync(0,'utf8'));
    const emit=process.stdout.write.bind(process.stdout);
    const url='data:text/javascript;base64,'+Buffer.from(source).toString('base64');
    globalThis.process=undefined;
    globalThis.fetch=undefined;
    globalThis.URL=undefined;
    globalThis.URLSearchParams=undefined;
    globalThis.AbortSignal=undefined;
    const {decide,decideAuthenticatedResource}=await import(url);
    const cases=[normal,{...normal,subjectId:'other_learner_fixture'},
      {...normal,deviceRegistered:false},suspicious,
      {...suspicious,stepUp:{verified:true,authAgeSeconds:60}},
      {...normal,path:'/notes/export'}, {...normal,classId:'unregistered_class'},
      {...normal,path:'/notes',route:'GET /notes'},
      {...normal,path:'/api/notes',route:'GET /api/notes'},
      {...normal,subjectId:'teacher_fixture',service:'instructor_announcements',method:'PUT',
        path:'/announcements/notice-demo',route:'PUT /announcements/:id'}];
    const results=[];
    for(const request of cases)results.push(await decide(request));
    const unavailable=await decideAuthenticatedResource({
      identity:{userId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',kind:'student'},
      service:'notes',method:'GET',path:'/api/notes/11111111-1111-4111-8111-111111111111',
      route:'GET /api/notes/:id'});
    emit(JSON.stringify({results,unavailable}));
  `;
  const output=execFileSync(process.execPath,['--input-type=module','-e',program],{
    input:JSON.stringify({source,normal,suspicious}),encoding:'utf8',timeout:5000});
  const {results,unavailable}=JSON.parse(output);
  assert.deepEqual(results.map(r=>r.decision),['allow','deny','deny','step_up','allow','deny','deny','deny','deny','deny']);
  assert.equal(results[1].ruleIds[0],'resource_zone');
  assert.equal(results[2].reasonCode,'device_not_registered');
  for(const r of results)assert.deepEqual(Object.keys(r).sort(),['decision','reasonCode','requestId','ruleIds','schema']);
  assert.equal(unavailable.decision,'deny');
  assert.equal(unavailable.reasonCode,'resource_lookup_unavailable');
});
