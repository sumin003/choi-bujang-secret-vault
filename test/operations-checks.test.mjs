import test from 'node:test';
import assert from 'node:assert/strict';
import {runOperationsChecks} from '../src/operations-checks.mjs';
const publicAppUrl='https://fixture.vercel.app';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'Content-Type':'application/json','x-vercel-id':'fixture-request'}});
test('three anonymous GETs produce two measured table rows, one supplementary probe and 39 NOT_RUN',async()=>{
 const calls=[];
 const result=await runOperationsChecks({publicAppUrl,fetchImpl:async(url,init)=>{
  calls.push(url.pathname);assert.equal(url.origin,publicAppUrl);assert.equal(init.method,'GET');assert.equal(init.redirect,'manual');
  assert.equal(init.headers.Authorization,undefined);assert.equal(init.headers.Cookie,undefined);assert.equal(init.credentials,'omit');
  assert.match(init.headers['X-Request-Id'],/^[a-f0-9-]{36}$/);
  return url.pathname==='/aleph.json'?json({schema:'aleph.defense.deployment.v1',step:12,commit:'a'.repeat(40)}):json({error:'LOGIN_REQUIRED'},401);
 }});
 assert.equal(calls.length,3);assert.equal(result.rows.length,41);
 assert.deepEqual(result.counts,{PASS:2,FAIL:0,NOT_RUN:39});
 assert.equal(result.supplementary.length,1);assert.equal(result.supplementary[0].status,'PASS');
 assert.equal(result.rows.find(r=>r.id==='T13').status,'NOT_RUN');
 assert.ok(result.rows.filter(r=>r.status==='PASS').every(r=>r.checkedAt&&r.targetRequestId==='fixture-request'));
});
test('protection HTML and connection failures stay NOT_RUN; successful anonymous data response is FAIL without recording data',async()=>{
 const blocked=await runOperationsChecks({publicAppUrl,fetchImpl:async()=>new Response('private-protection',{status:403})});
 assert.deepEqual(blocked.counts,{PASS:0,FAIL:0,NOT_RUN:41});
 assert.doesNotMatch(JSON.stringify(blocked),/private-protection/);
 const failed=await runOperationsChecks({publicAppUrl,fetchImpl:async()=>{throw Error('private-error');}});
 assert.deepEqual(failed.counts,{PASS:0,FAIL:0,NOT_RUN:41});
 const exposed=await runOperationsChecks({publicAppUrl,fetchImpl:async()=>json([{title:'private-title',body:'private-note'}])});
 assert.equal(exposed.rows.find(r=>r.id==='T07').status,'FAIL');
 assert.doesNotMatch(JSON.stringify(exposed),/private-title|private-note/);
});
test('untrusted origins rejected before any request',async()=>{
 for(const url of ['http://fixture.vercel.app','https://evil.invalid','https://fixture.vercel.app/path'])
  await assert.rejects(runOperationsChecks({publicAppUrl:url,fetchImpl:()=>{throw Error('must not fetch');}}));
});
