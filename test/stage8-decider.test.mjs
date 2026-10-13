import test from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../src/decider.mjs';
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
test('explicitly registered synthetic instructor can update its own announcement',async()=>{
  await expect(single('teacher_fixture','notice-demo','PUT',true),'allow');
});
test('student collection requests preserve list and creation routes',async()=>{
  for(const subjectId of ['learner_fixture','other_learner_fixture'])for(const method of ['GET','POST'])
    await expect(own({subjectId,method,path:'/notes',route:method+' /notes'}),'allow');
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
