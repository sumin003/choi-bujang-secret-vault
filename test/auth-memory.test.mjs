import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const response=()=>({code:200,headers:{},setHeader(k,v){this.headers[k]=v},status(c){this.code=c;return this},json(body){this.body=body;return this},end(){return this}});
async function load(){const source=readFileSync(new URL('../api/auth.js',import.meta.url),'utf8').replace(/^import [\s\S]*?;\n/gm,'');return (await import('data:text/javascript;base64,'+Buffer.from('const enforceXdr=()=>true;\n'+source).toString('base64'))).default;}

test('official SDK auth relay never exposes the server key or sets a persistent login cookie',async()=>{
 const handler=await load(),original={fetch:globalThis.fetch,url:process.env.SUPABASE_URL,key:process.env.SUPABASE_SECRET_KEY};
 process.env.SUPABASE_URL='https://fixture.example.invalid';process.env.SUPABASE_SECRET_KEY='fixture-server-secret';let calls=0;
 globalThis.fetch=async(url,init)=>{calls++;assert.equal(url.pathname,'/auth/v1/token');assert.equal(init.headers.apikey,'fixture-server-secret');assert.deepEqual(JSON.parse(init.body),{email:'fixture@example.invalid',password:'fixture-only'});
  return {ok:true,status:200,json:async()=>({access_token:'fixture-access',refresh_token:'fixture-refresh',user:{id:'fixture-user'},expires_in:3600})};};
 try{
  const req={method:'POST',query:{action:'token',grant_type:'password'},headers:{host:'vault.example.com',origin:'https://vault.example.com','content-type':'application/json'},body:{email:'fixture@example.invalid',password:'fixture-only'}};
  const res=response();await handler(req,res);assert.equal(res.code,200);assert.equal(calls,1);assert.equal(res.body.access_token,'fixture-access');
  assert.match(res.headers['Set-Cookie'],/Max-Age=0/);assert.equal(JSON.stringify(res.body).includes('fixture-server-secret'),false);
  assert.equal(res.headers['Cache-Control'],'no-store');
  const denied=response();await handler({...req,headers:{...req.headers,origin:'https://other.example.com'}},denied);assert.equal(denied.code,403);assert.equal(calls,1);
  const invalid=response();await handler({...req,query:{action:'approve'}},invalid);assert.equal(invalid.code,400);assert.equal(calls,1);
 }finally{globalThis.fetch=original.fetch;for(const[n,v]of[['SUPABASE_URL',original.url],['SUPABASE_SECRET_KEY',original.key]]){if(v===undefined)delete process.env[n];else process.env[n]=v}}
});

test('browser SDK uses memory only; protected APIs require bearer and never restore login from cookies',()=>{
 const source=readFileSync(new URL('../public/auth.js',import.meta.url),'utf8');
 assert.match(source,/persistSession: false/);assert.match(source,/detectSessionInUrl: false/);
 assert.doesNotMatch(source,/localStorage\.setItem|sessionStorage\.setItem|indexedDB|document\.cookie|authFetch\('session'\)/);
 for(const name of ['api/notes.js','api/announcements.js','api/device.js','src/note-restore.mjs']){
  const api=readFileSync(new URL('../'+name,import.meta.url),'utf8');assert.doesNotMatch(api,/resolveSessionAuthorization|web-session/);
 }
 for(const name of ['src/device-approval.mjs','src/browser-registration.mjs']){
  assert.doesNotMatch(readFileSync(new URL('../'+name,import.meta.url),'utf8'),/from ['"].*decider\.mjs/);
 }
});
