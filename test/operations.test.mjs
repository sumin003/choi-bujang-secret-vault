import test from 'node:test';
import assert from 'node:assert/strict';
import {createOperationsHandler as makeHandler} from '../api/operations.js';
const createOperationsHandler = options => makeHandler({runChecks:async()=>({rows:[],counts:{PASS:0,FAIL:0,NOT_RUN:41},supplementary:[]}),...options});
const response=()=>({headers:{},setHeader(k,v){this.headers[k]=v;},status(s){this.code=s;return this;},json(data){this.data=data;return this;}});
test('summary requires login and server device approval, with no partial data on refusal',async()=>{
  for(const mode of ['anonymous','pending','unavailable']){
    const res=response();
    await createOperationsHandler({verify:async()=>mode==='anonymous'?null:{kind:'student'},
      approve:async(req,res)=>{if(mode==='unavailable')throw Error('private');res.status(403).json({error:'DEVICE_NOT_APPROVED'});return false;}})({url:'/api/operations',method:'GET'},res);
    assert.equal(res.code,mode==='anonymous'?401:mode==='pending'?403:503);
    assert.deepEqual(Object.keys(res.data),['error']);
    assert.equal(res.headers['Cache-Control'],'no-store');
  }
});
test('approved GET returns only configuration and saved aggregate results; execution stays not_run',async()=>{
  const res=response();
  await createOperationsHandler({verify:async()=>({kind:'student',sub:'private-identity'}),approve:async()=>true,writeRecord:()=>{}})({url:'/api/operations',method:'GET'},res);
  assert.equal(res.code,200);
  assert.ok(res.data.rules.ids.includes('device_registered'));
  for(const key of ['detection','revocation','recovery'])assert.equal(res.data[key].status,'not_run');
  assert.equal(res.data.recovery.verification,'not_run');
  assert.deepEqual(res.data.detection.savedFixtureResults.find(x=>x.moduleKey==='known-cve').counts,{block:8,alert:8,record:8});
  assert.match(res.data.recovery.candidateVersion,/^[a-f0-9]{40}$/);
  assert.doesNotMatch(JSON.stringify(res.data),/private-identity|owner_id|title|body|access_token|alertId/);
});
test('no action, query or alternative route is accepted',async()=>{
  const handler=createOperationsHandler({verify:()=>{throw Error('must not authenticate');}});
  for(const [method,url,code]of [['POST','/api/operations',405],['GET','/api/operations?action=restore',400],['GET','/api/operations/export',400]]){
    const res=response();await handler({method,url},res);assert.equal(res.code,code);
  }
});


test('redacted server record equals the response, shares ID, and excludes private inputs', async()=>{
  const records=[];
  const handler=createOperationsHandler({verify:async()=>({kind:'student',userId:'private-user',token:'private-token'}),
    approve:async()=>true,writeRecord:record=>records.push(JSON.parse(JSON.stringify(record)))});
  const req={url:'/api/operations',method:'GET',headers:{authorization:'private-bearer',cookie:'private-cookie',
    'x-request-id':'untrusted-id'},body:{title:'private-title',body:'private-note'}};
  const first=response();await handler(req,first);
  assert.equal(first.code,200);assert.equal(records.length,1);
  const record=records[0];
  assert.deepEqual(record.summary,first.data);
  assert.equal(record.requestId,first.headers['X-Request-ID']);
  assert.equal(record.checkedAt,first.data.checkedAt);
  assert.equal(record.httpStatus,first.code);
  assert.deepEqual(record.summary.detection.savedFixtureResults,first.data.detection.savedFixtureResults);
  assert.doesNotMatch(JSON.stringify(record),/private-|untrusted-id|authorization|cookie|userId/);
  const second=response();await handler(req,second);
  assert.notEqual(first.data.requestId,second.data.requestId);
});

test('refusals do not emit success records; logging failure never claims success',async()=>{
  const records=[];
  const denied=createOperationsHandler({verify:async()=>null,writeRecord:r=>records.push(r)});
  const res=response();await denied({url:'/api/operations',method:'GET'},res);
  assert.equal(res.code,401);assert.equal(records.length,0);
  const failed=createOperationsHandler({verify:async()=>({kind:'student'}),approve:async()=>true,
    writeRecord:()=>{throw Error('private-error');}});
  const failure=response();await failed({url:'/api/operations',method:'GET'},failure);
  assert.equal(failure.code,503);assert.deepEqual(failure.data,{error:'OPERATIONS_UNAVAILABLE'});
});
