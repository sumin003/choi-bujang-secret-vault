import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createBrowserRegistration} from '../src/browser-registration.mjs';
import {checkApprovedDevice,enforceApprovedDevice} from '../src/device-approval.mjs';
const USER='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', OTHER='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const identity={kind:'student',userId:USER}, time=Date.parse('2026-10-15T13:00:00Z');
const response=()=>({code:200,headers:{},setHeader(k,v){this.headers[k]=v},status(c){this.code=c;return this},json(b){this.body=b;return this}});
const req=cookie=>({headers:{cookie:cookie?.split(';')[0]}});
function fixture(){
 const rows=new Map();let clock=time, evidence=null, reviews=0;
 const options={env:{SUPABASE_URL:'https://fixture.example.invalid',SUPABASE_SECRET_KEY:'fixture-only'},
 now:()=>clock,readEvidence:async()=>{reviews++;return evidence},fetchImpl:async(url,init)=>{
  assert.equal(url.pathname,'/rest/v1/learning_browser_registrations');
  const hash=url.searchParams.get('browser_hash')?.slice(3),user=url.searchParams.get('user_id')?.slice(3);let result=[];
  if(init.method==='POST'){const row=JSON.parse(init.body);assert.equal(row.status,'pending');rows.set(row.browser_hash,row);result=[row]}
  else {const row=rows.get(hash);if(row?.user_id===user){
   if(init.method==='PATCH'&&row.status==='pending')Object.assign(row,JSON.parse(init.body));
   result=init.method==='PATCH'&&row.status!=='approved'?[]:[structuredClone(row)];
  }}
  return {ok:true,status:200,json:async()=>result};}};
 return {rows,options,service:createBrowserRegistration(options),setProof(v){evidence=v},get reviews(){return reviews},advance(ms){clock+=ms}};
}

test('request creates pending only; cookie roundtrip plus independent server evidence is required',async()=>{
 const f=fixture(),res=response();assert.deepEqual(await f.service.status(req(),identity,{review:true}),{status:'unverified'});
 assert.deepEqual(await f.service.request(req(),identity,res),{status:'pending'});assert.equal(f.reviews,0);
 const cookie=res.headers['Set-Cookie'];assert.match(cookie,/^__Host-vault_browser=/);assert.match(cookie,/HttpOnly; Secure; SameSite=Strict/);
 const stored=JSON.stringify([...f.rows.values()]);assert.equal(stored.includes(cookie.split('=')[1].split(';')[0]),false);
 assert.equal(await checkApprovedDevice(req(cookie),identity,{approvalService:f.service}),'required');assert.equal(f.reviews,0);
 assert.deepEqual(await f.service.status(req(cookie),identity,{review:true}),{status:'pending',reason:'recent_login_required'});
 for(const proof of [{confirmed:false,passwordAt:time/1000},{confirmed:true,passwordAt:null},{confirmed:true,passwordAt:time/1000-601},{confirmed:true,passwordAt:time/1000+1}]){
  f.setProof(proof);assert.equal((await f.service.status(req(cookie),identity,{review:true})).status,'pending');
 }
 f.setProof({confirmed:true,passwordAt:time/1000});
 // Even with valid evidence, repeating the request cannot approve.
 assert.equal((await f.service.request(req(cookie),identity,response())).status,'pending');
 assert.equal([...f.rows.values()][0].status,'pending');
 assert.deepEqual(await f.service.status(req(),identity,{review:true}),{status:'unverified'});
 assert.deepEqual(await f.service.status(req(cookie),identity,{review:true}),{status:'approved'});
 assert.equal(await checkApprovedDevice(req(cookie),identity,{approvalService:f.service}),'approved');
 assert.equal((await createBrowserRegistration(f.options).status(req(cookie),identity)).status,'approved');
});

test('other browser/user, forged body/header, revoked and expired registrations stay denied',async()=>{
 const f=fixture(),res=response();await f.service.request(req(),identity,res);const cookie=res.headers['Set-Cookie'];
 f.setProof({confirmed:true,passwordAt:time/1000});await f.service.status(req(cookie),identity,{review:true});
 const registered=response();assert.equal(await enforceApprovedDevice(req(cookie),registered,identity,{approvalService:f.service}),true);
 for(const r of [req(),req('__Host-vault_browser=forged'),{headers:{'x-device-registered':'true'},deviceRegistered:true},
  {headers:{cookie:req(cookie).headers.cookie+'; '+req(cookie).headers.cookie}}]){
  const denied=response();assert.equal(await enforceApprovedDevice(r,denied,identity,{approvalService:f.service}),false);assert.equal(denied.code,403);
 }
 assert.equal((await f.service.status(req(cookie),{kind:'student',userId:OTHER},{review:true})).status,'unverified');
 const row=[...f.rows.values()][0];row.status='rejected';row.reason='revoked';
 assert.equal((await f.service.request(req(cookie),identity,response())).status,'rejected');
 assert.equal((await f.service.status(req(cookie),identity,{review:true})).status,'rejected');
 row.status='approved';f.advance(31*86400000);assert.equal((await f.service.status(req(cookie),identity)).status,'unverified');
});

test('database failure cannot grant access; only official verified user/claims supply proof',async()=>{
 const f=fixture(),res=response();await f.service.request(req(),identity,res);const cookie=res.headers['Set-Cookie'];
 const broken=createBrowserRegistration({...f.options,fetchImpl:async()=>({ok:false})});
 const denied=response();assert.equal(await enforceApprovedDevice(req(cookie),denied,identity,{approvalService:broken}),false);assert.equal(denied.code,503);
 let user={id:USER,email_confirmed_at:'2026-01-01T00:00:00Z'},claims={sub:USER,amr:[{method:'password',timestamp:time/1000}]};
 const sdk={auth:{getUser:async token=>{assert.equal(token,'server-fixture');return {data:{user}}},getClaims:async()=>({data:{claims}})}};
 const sessions={authorization:async()=> 'Bearer server-fixture',client:async()=>sdk};
 const service=createBrowserRegistration({...f.options,readEvidence:undefined,sessions});
 for(const bad of [{...user,email_confirmed_at:null},{...user,is_anonymous:true},{...user,id:OTHER}]){
  const previous=user;user=bad;assert.equal((await service.status(req(cookie),identity,{review:true})).status,'pending');user=previous;
 }
 claims={sub:OTHER,amr:[{method:'password',timestamp:time/1000}]};assert.equal((await service.status(req(cookie),identity,{review:true})).status,'pending');
 claims={sub:USER,amr:[{method:'password',timestamp:time/1000}]};assert.equal((await service.status(req(cookie),identity,{review:true})).status,'approved');
});

test('manifest exists with app identity and standalone settings; browser code stores no credentials',()=>{
 const manifest=JSON.parse(readFileSync(new URL('../public/app.webmanifest',import.meta.url),'utf8'));
 assert.ok(manifest.name);assert.equal(manifest.display,'standalone');assert.equal(manifest.start_url,'/');
 const html=readFileSync(new URL('../public/index.html',import.meta.url),'utf8');assert.match(html,/app.webmanifest/);assert.match(html,/オンライン|온라인/);
 const source=readFileSync(new URL('../public/auth.js',import.meta.url),'utf8');
 assert.doesNotMatch(source,/localStorage\.setItem|sessionStorage\.setItem|indexedDB|document\.cookie|access_token|refresh_token|navigator\.credentials/);
});

test('actual device API and note API: pending denies data; verified registration opens own notes; revocation closes them',async()=>{
 const f=fixture();globalThis.__browserFixture={service:f.service};
 const deviceSource=readFileSync(new URL('../api/device.js',import.meta.url),'utf8').replace(/^import [\s\S]*?;\n/gm,'');
 const devicePrelude=`const resolveSessionAuthorization=async()=>'',createLoginVerifier=()=>()=>null,config={},readDeviceApproval=()=>{},requestDeviceApproval=()=>{};\n`;
 const {createDeviceHandler}=await import('data:text/javascript;base64,'+Buffer.from(devicePrelude+deviceSource).toString('base64'));
 const api=createDeviceHandler({verify:async()=>identity,approvalService:f.service});
 const device=async(method,cookie,body)=>{const r=req(cookie);r.method=method;r.url='/api/device';r.headers.host='vault.example.com';r.headers.origin='https://vault.example.com';r.headers['content-type']='application/json';r.body=body;const res=response();await api(r,res);return res;};
 const noteSource=readFileSync(new URL('../api/notes.js',import.meta.url),'utf8').replace(/^import [\s\S]*?;\n/gm,'');
 const gateUrl=new URL('../src/device-approval.mjs',import.meta.url).href;
 const prelude=`import {enforceApprovedDevice as enforce} from ${JSON.stringify(gateUrl)};
 const config={},enforceXdr=()=>true,randomUUID=()=>'',createLoginVerifier=()=>async()=>({kind:'student',userId:'${USER}'});
 const enforceApprovedDevice=(r,s,i)=>enforce(r,s,i,{approvalService:globalThis.__browserFixture.service});
 const decideAuthenticatedResource=async()=>({decision:'allow'}),exposeResourceDecision=()=>{};\n`;
 const original={fetch:globalThis.fetch,url:process.env.SUPABASE_URL,key:process.env.SUPABASE_SECRET_KEY};let reads=0;
 process.env.SUPABASE_URL='https://fixture.example.invalid';process.env.SUPABASE_SECRET_KEY='fixture-only';
 globalThis.fetch=async url=>{assert.equal(url.searchParams.get('owner_id'),'eq.'+USER);reads++;return {ok:true,json:async()=>[]}};
 try{
  const {handleNotes}=await import('data:text/javascript;base64,'+Buffer.from(prelude+noteSource).toString('base64'));
  const note=async(cookie)=>{const r=req(cookie);r.headers.authorization='Bearer fixture';r.method='GET';r.url='/api/notes';const res=response();await handleNotes(r,res,null);return res;};
  assert.equal((await note()).code,403);assert.equal(reads,0);
  const posted=await device('POST',undefined,{action:'request'});assert.equal(posted.code,200);assert.deepEqual(posted.body,{status:'pending'});
  const cookie=posted.headers['Set-Cookie'];f.setProof({confirmed:true,passwordAt:time/1000});
  assert.equal((await note(cookie)).code,403);assert.equal(reads,0);
  const checked=await device('GET',cookie);assert.equal(checked.body.status,'approved');
  assert.equal((await note(cookie)).code,200);assert.equal(reads,1);
  const forged=await device('POST',cookie,{action:'request',deviceRegistered:true});assert.equal(forged.code,400);
  const row=[...f.rows.values()][0];row.status='rejected';row.reason='revoked';
  assert.equal((await note(cookie)).code,403);assert.equal(reads,1);
 }finally{
  globalThis.fetch=original.fetch;delete globalThis.__browserFixture;
  for(const[name,value]of[['SUPABASE_URL',original.url],['SUPABASE_SECRET_KEY',original.key]]){if(value===undefined)delete process.env[name];else process.env[name]=value}
 }
});
