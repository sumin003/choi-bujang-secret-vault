import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {requestSource,checkXdr,enforceXdr} from '../src/xdr-gate.mjs';
const now=Date.now(),blocked='192.0.2.10',normal='192.0.2.20';
const rule={mode:'live',action:'deny',ip:blocked,ruleId:'xdr.brute-force.fixture',confidence:.95,
  alertIds:['bf-01'],createdAt:new Date(now-1000).toISOString(),expiresAt:new Date(now+60000).toISOString()};
const req=ip=>({headers:{'x-vercel-forwarded-for':ip},socket:{remoteAddress:normal}});
function res(){return {statusCode:200,headers:{},setHeader(k,v){this.headers[k]=v},status(s){this.statusCode=s;return this},json(b){this.body=b},end(){}};}

test('trusted source ignores browser body and generic forwarding headers',()=>{
  const r=req(normal);r.headers['x-forwarded-for']=blocked;r.body={ip:blocked};
  assert.equal(requestSource(r,{vercel:true}),normal);
  assert.equal(requestSource(r,{vercel:false}),normal);
  assert.equal(requestSource(req(blocked+','+normal),{vercel:true}),null);
});
test('only live, strong, unexpired rules block; local replay and normal requests pass',()=>{
  assert.equal(checkXdr(req(blocked),{rules:[rule],now,vercel:true}),'blocked');
  assert.equal(checkXdr(req(normal),{rules:[rule],now,vercel:true}),'allowed');
  for(const changed of [{expiresAt:new Date(now-1).toISOString()},{mode:'isolated_learning_replay'},{confidence:.6}])
    assert.equal(checkXdr(req(blocked),{rules:[{...rule,...changed}],now,vercel:true}),'no-active-rules');
  const out=res();assert.equal(enforceXdr(req(blocked),out,{rules:[rule],now,vercel:true}),false);
  assert.equal(out.statusCode,403);assert.equal(out.body.error,'XDR_BLOCKED');
});
test('actual notes server keeps normal CRUD; denied source never reaches DB',async()=>{
  const oldFetch=globalThis.fetch;
  const oldUrl=process.env.SUPABASE_URL,oldKey=process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_URL='https://fixture.supabase.co';process.env.SUPABASE_SECRET_KEY='server-test-placeholder';
  globalThis.__gate=(r,s)=>enforceXdr(r,s,{rules:[rule],now,vercel:true});
  const owner='11111111-1111-4111-8111-111111111111';
  globalThis.__verify=()=>async()=>({userId:owner});
  const text=(await readFile(new URL('../api/notes.js',import.meta.url),'utf8'))
    .replace("import { enforceXdr } from '../src/xdr-gate.mjs';",'const enforceXdr=globalThis.__gate;')
    .replace("import { createLoginVerifier } from '../src/verify-login.mjs';",'const createLoginVerifier=globalThis.__verify;')
    .replace("import config from '../aleph.config.json' with { type: 'json' };",'const config={};');
  const {handleNotes}=await import('data:text/javascript;base64,'+Buffer.from(text).toString('base64'));
  let dbCalls=0;const rows=new Map();
  globalThis.fetch=async(url,init)=>{dbCalls++;let selected=[];
    const id=url.searchParams.get('note_id')?.slice(3),filter=url.searchParams.get('owner_id')?.slice(3);
    if(init.method==='POST'){const r=JSON.parse(init.body);rows.set(r.note_id,r);selected=[r];}
    else{selected=[...rows.values()].filter(r=>(!id||r.note_id===id)&&r.owner_id===filter);
      if(init.method==='PATCH')selected.forEach(r=>Object.assign(r,JSON.parse(init.body)));
      if(init.method==='DELETE')selected.forEach(r=>rows.delete(r.note_id));}
    return Response.json(selected.map(r=>({id:r.note_id,title:r.title,body:r.content,owner_id:r.owner_id})));
  };
  const call=async(method,id=null,ip=normal,body={title:'fixture',body:'fixture'})=>{const r=req(ip);r.method=method;r.headers.authorization='fixture';r.headers['content-type']='application/json';r.body=body;const s=res();await handleNotes(r,s,id);return s;};
  try{
    const before=dbCalls;assert.equal((await call('GET',null,blocked)).statusCode,403);assert.equal(dbCalls,before);
    const created=await call('POST');assert.equal(created.statusCode,201);const id=created.body.id;
    assert.equal((await call('GET',id)).statusCode,200);assert.equal((await call('PUT',id)).statusCode,200);
    assert.equal((await call('DELETE',id)).statusCode,204);assert.equal((await call('GET',id)).statusCode,404);
    const r=req(normal);r.method='GET';const s=res();await handleNotes(r,s,null);assert.equal(s.statusCode,401);
  }finally{globalThis.fetch=oldFetch;delete globalThis.__gate;delete globalThis.__verify;
    if(oldUrl===undefined)delete process.env.SUPABASE_URL;else process.env.SUPABASE_URL=oldUrl;
    if(oldKey===undefined)delete process.env.SUPABASE_SECRET_KEY;else process.env.SUPABASE_SECRET_KEY=oldKey;}
});
test('actual login handler blocks before Auth; normal credentials still reach official Auth',async()=>{
  const oldFetch=globalThis.fetch,oldUrl=process.env.SUPABASE_URL,oldKey=process.env.SUPABASE_SECRET_KEY;
  process.env.SUPABASE_URL='https://fixture.supabase.co';process.env.SUPABASE_SECRET_KEY='server-test-placeholder';
  globalThis.__gate=(r,s)=>enforceXdr(r,s,{rules:[rule],now,vercel:true});
  const text=(await readFile(new URL('../api/auth.js',import.meta.url),'utf8')).replace("import { enforceXdr } from '../src/xdr-gate.mjs';",'const enforceXdr=globalThis.__gate;');
  const {default:handler}=await import('data:text/javascript;base64,'+Buffer.from(text).toString('base64'));
  let calls=0;globalThis.fetch=async()=>{calls++;return Response.json({code:'invalid_credentials'},{status:400});};
  const call=async ip=>{const r=req(ip);r.method='POST';r.query={action:'token',grant_type:'password'};r.headers['content-type']='application/json';r.body={email:'fixture@example.invalid',password:'fixture'};const s=res();await handler(r,s);return s;};
  try{assert.equal((await call(blocked)).statusCode,403);assert.equal(calls,0);
    const s=await call(normal);assert.equal(s.statusCode,400);assert.equal(s.body.code,'invalid_credentials');assert.equal(calls,1);
  }finally{globalThis.fetch=oldFetch;delete globalThis.__gate;
    if(oldUrl===undefined)delete process.env.SUPABASE_URL;else process.env.SUPABASE_URL=oldUrl;
    if(oldKey===undefined)delete process.env.SUPABASE_SECRET_KEY;else process.env.SUPABASE_SECRET_KEY=oldKey;}
});
