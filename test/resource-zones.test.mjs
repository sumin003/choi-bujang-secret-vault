import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createBaseDecider} from '../src/decider.mjs';
import {createResourceAuthorizer} from '../src/resource-access.mjs';
const A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',I='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const N='11111111-1111-4111-8111-111111111111',C='22222222-2222-4222-8222-222222222222';
let writes=0;
const store=async(t,p,o={})=>{
 if(t==='learning_resource_subjects'){const id={A,B,I}[p.subject_id.slice(3)];return id&&p.class_id==='eq.fixture'&&p.project_id==='eq.fixture'?[{user_id:id,identity_kind:'student'}]:[];}
 if(t==='learning_instructors')return p.user_id==='eq.'+I&&p.identity_kind==='eq.student'?[{user_id:I,identity_kind:'student',enabled:true}]:[];
 if(t==='learning_notes')return p.owner_id==='eq.'+A&&p.note_id==='eq.'+N?[{owner_id:A}]:[];
 if(t==='learning_announcements'){if(p.owner_id!=='eq.'+I||p.owner_kind!=='eq.student'||p.id!=='eq.'+C)return [];if(o.method==='PATCH'){assert.equal(o.body.owner_id,I);assert.equal(o.body.owner_kind,'student');writes++;}return [{id:C,title:'fixture',body:'fixture',owner_id:I,owner_kind:'student'}];}
 throw Error('unexpected_table');
};
function request(subject='A',notice=false,method='GET'){
const p=notice?'/api/announcements':'/api/notes';return {schema:'aleph.decision.v1',requestId:A,classId:'fixture',projectId:'fixture',subjectId:subject,deviceId:'a'.repeat(16),service:notice?'instructor_announcements':'notes',method,path:p+'/'+(notice?C:N),route:method+' '+p+'/:id',queryLength:0,querySha256:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',at:new Date().toISOString(),policyRevision:1,deviceRegistered:true,stepUp:{verified:false,authAgeSeconds:null},recentEvents:[],signals:{source:'judge_fixture',region:'local',network:'usual',hour:14}};}
test('trusted bindings enforce owner/instructor zones and preserve device/step-up rules',async()=>{
 const decide=createBaseDecider({authorizeResource:createResourceAuthorizer({store})});
 for(const method of ['GET','PUT','DELETE']){assert.equal((await decide(request('A',false,method))).decision,'allow');assert.equal((await decide(request('B',false,method))).decision,'deny');}
 assert.equal((await decide(request('A',true,'PUT'))).decision,'deny');assert.equal((await decide(request('I',true,'PUT'))).decision,'allow');
 assert.equal((await decide({...request(),deviceRegistered:false})).reasonCode,'device_not_registered');
 const risk={...request(),signals:{source:'judge_fixture',region:'foreign',network:'unusual',hour:3},recentEvents:[{kind:'risk_signal',ageSeconds:60,count:20}]};assert.equal((await decide(risk)).decision,'step_up');assert.equal((await decide({...risk,stepUp:{verified:true,authAgeSeconds:60}})).decision,'allow');
 for(const bad of [{...request(),path:'/api/notes/export'},{...request(),queryLength:1},{...request(),subjectId:'unknown'},{...request(),role:'instructor'}])assert.equal((await decide(bad)).decision,'deny');
});
test('direct announcement handler rejects students, forged roles and query actions; permits stored instructor',async()=>{
 const source=readFileSync(new URL('../api/announcements.js',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 const resource=new URL('../src/resource-access.mjs',import.meta.url).href;
 const prelude=`import {createResourceStore,isStoredInstructor} from ${JSON.stringify(resource)};\nconst enforceXdr=()=>true,createLoginVerifier=()=>()=>null,config={},randomUUID=()=>${JSON.stringify(C)};\n`;
 const {createAnnouncementHandler}=await import('data:text/javascript;base64,'+Buffer.from(prelude+source).toString('base64'));
 const handler=createAnnouncementHandler({store,verifyLogin:async user=>user?{userId:user,kind:'student'}:null});
 const call=async(user,url='/api/announcements/'+C)=>{const r={statusCode:200,setHeader(){},status(n){this.statusCode=n;return this},json(b){this.body=b;return this},end(){return this}};await handler({method:'PUT',url,headers:{authorization:user,'content-type':'application/json'},body:{title:'fixture',body:'fixture',role:'instructor',owner_id:B,owner_kind:'judge'}},r,C);return r;};
 for(const id of [A,B]){const r=await call(id);assert.equal(r.statusCode,403);assert.equal(r.body.reason,'instructor_required');assert.equal(r.body.id,undefined);}assert.equal(writes,0);
 assert.equal((await call(null)).statusCode,401);assert.equal((await call(I,'/api/announcements/'+C+'?action=export')).statusCode,400);
 const r=await call(I);assert.equal(r.statusCode,200);assert.deepEqual(r.body,{id:C,title:'fixture',body:'fixture'});assert.equal(writes,1);
});
test('direct note API preserves own reads/updates/deletes and rejects another owner and function queries',async()=>{
 const source=readFileSync(new URL('../api/notes.js',import.meta.url),'utf8').replace(/^import .*;\n/gm,'');
 const prelude='const enforceXdr=()=>true,config={},randomUUID=()=>"'+N+'",createLoginVerifier=()=>async user=>({userId:user,kind:"student"});\n';
 const {handleNotes}=await import('data:text/javascript;base64,'+Buffer.from(prelude+source).toString('base64'));
 const previousFetch=globalThis.fetch,previousUrl=process.env.SUPABASE_URL,previousKey=process.env.SUPABASE_SECRET_KEY;
 let row={id:N,title:'fixture',body:'fixture',owner_id:A};
 try {
 process.env.SUPABASE_URL='https://fixture.example.invalid';process.env.SUPABASE_SECRET_KEY='fixture-only';
 globalThis.fetch=async(url,o)=>{assert.equal(url.searchParams.get('note_id'),'eq.'+N);const own=url.searchParams.get('owner_id')==='eq.'+A;if(own&&o.method==='PATCH'){const p=JSON.parse(o.body);assert.equal(p.owner_id,A);row={...row,...p};}const rows=own?[{...row}]:[];if(own&&o.method==='DELETE')row=null;return {ok:true,status:200,json:async()=>rows};};
 const call=async(user,method,url='/api/notes/'+N)=>{const r={statusCode:200,setHeader(){},status(n){this.statusCode=n;return this},json(b){this.body=b;return this},end(){return this}};await handleNotes({method,url,headers:{authorization:user,'content-type':'application/json'},body:{title:'own',body:'own',owner_id:B,role:'instructor'}},r,N);return r;};
 for(const method of ['GET','PUT','DELETE']){const r=await call(B,method);assert.equal(r.statusCode,404);assert.equal(r.body.id,undefined);assert.equal(row.title,'fixture');}
 assert.equal((await call(A,'GET','/api/notes/'+N+'?action=export')).statusCode,400);
 assert.equal((await call(A,'GET')).statusCode,200);assert.equal((await call(A,'PUT')).statusCode,200);assert.equal(row.owner_id,A);assert.equal((await call(A,'DELETE')).statusCode,204);assert.equal(row,null);
 } finally {globalThis.fetch=previousFetch;if(previousUrl===undefined)delete process.env.SUPABASE_URL;else process.env.SUPABASE_URL=previousUrl;if(previousKey===undefined)delete process.env.SUPABASE_SECRET_KEY;else process.env.SUPABASE_SECRET_KEY=previousKey;}
});
