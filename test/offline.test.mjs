import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
const source=readFileSync(new URL('../public/sw.js',import.meta.url),'utf8');
function fixture(){const events=new Map(),cached=[],deleted=[];let network=true;
 const offline={kind:'offline'},online={kind:'online'};
 const context={URL,Promise,self:{location:{origin:'https://vault.example.com'},addEventListener(k,v){events.set(k,v)},skipWaiting:async()=>{},clients:{claim:async()=>{}}},
  caches:{open:async()=>({addAll:async files=>cached.push(...files)}),keys:async()=>['vault-offline-old','other-app-cache','vault-offline-v1'],delete:async k=>deleted.push(k),match:async()=>offline},
  fetch:async()=>{if(!network)throw Error('offline');return online}};
 vm.runInNewContext(source,context);return {events,cached,deleted,offline,online,disconnect(){network=false}};
}
test('only offline guidance and icons are cached; other applications caches are preserved',async()=>{
 const f=fixture();let work;f.events.get('install')({waitUntil(p){work=p}});await work;
 assert.deepEqual(f.cached,['/offline.html','/icons/vault-192.png','/icons/vault-512.png']);
 f.events.get('activate')({waitUntil(p){work=p}});await work;assert.deepEqual(f.deleted,['vault-offline-old']);
});
test('API, notes, auth responses, cross-origin requests and POST are never intercepted',()=>{
 const f=fixture();for(const [path,method,mode]of [['/api/notes','GET','navigate'],['/api/auth?action=token','POST','cors'],['/api/device','GET','cors'],['/data.json','GET','cors'],['/offline.html','POST','cors']]){
  let intercepted=false;f.events.get('fetch')({request:{url:'https://vault.example.com'+path,method,mode},respondWith(){intercepted=true}});assert.equal(intercepted,false);
 }
 let intercepted=false;f.events.get('fetch')({request:{url:'https://other.example.com/offline.html',method:'GET',mode:'navigate'},respondWith(){intercepted=true}});assert.equal(intercepted,false);
});
test('navigation failure opens guidance and successful responses are not cached',async()=>{
 const f=fixture();const request={url:'https://vault.example.com/',method:'GET',mode:'navigate'};let result;
 f.events.get('fetch')({request,respondWith(p){result=p}});assert.equal(await result,f.online);
 f.disconnect();f.events.get('fetch')({request,respondWith(p){result=p}});assert.equal(await result,f.offline);
});
