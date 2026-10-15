import test from 'node:test';
import assert from 'node:assert/strict';
import { createNoteRestoreHandler, createRestoreRpc } from '../src/note-restore.mjs';

const B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ID='11111111-1111-4111-8111-111111111111';
const BACKUP='22222222-2222-4222-8222-222222222222';
const HASH='a'.repeat(64), CURRENT='b'.repeat(64);
const body={id:ID,backupId:BACKUP,contentSha256:HASH,currentSha256:CURRENT};
const response=()=>({statusCode:200,headers:{},setHeader(k,v){this.headers[k]=v;},
  status(code){this.statusCode=code;return this;},json(value){this.body=value;return this;}});
const request=(input=body,url='/api/restore-notes')=>({method:'POST',url,
  headers:{authorization:'fixture-login','content-type':'application/json'},body:input});
const create=options=>createNoteRestoreHandler({verifyLogin:async()=>({kind:'student',userId:B}),
  enforceRequest:()=>true,approveDevice:async()=>true,...options});

test('B의 사전 확인은 한 건의 ID와 해시만 표시하고 사본 내용은 응답하지 않는다',async()=>{
  const handler=create({preview:true,callRpc:async(name,payload)=>{
    assert.equal(name,'learning_preview_note_restore');
    assert.deepEqual(payload,{p_actor:B,p_note_id:ID});
    return {...body,operation:'update',title:'synthetic-private-marker',content:'never return'};
  }});
  const res=response();await handler(request({id:ID},'/api/restore-notes/preview'),res);
  assert.equal(res.statusCode,200);
  assert.deepEqual(res.body,{...body,operation:'update'});
  assert.equal(JSON.stringify(res.body).includes('private-marker'),false);
});

test('B의 지정한 한 건 복원은 서버가 검증한 소유자만 RPC에 넘긴다',async()=>{
  let calls=0;
  const handler=create({callRpc:async(name,payload)=>{
    calls++;assert.equal(name,'learning_restore_note');
    assert.deepEqual(payload,{p_actor:B,p_note_id:ID,p_backup_id:BACKUP,p_content_hash:HASH,p_expected_current:CURRENT});
    return {id:ID,restored:true,contentSha256:HASH,title:'never return',content:'never return'};
  }});
  const res=response();await handler(request(),res);
  assert.equal(calls,1);assert.equal(res.statusCode,200);
  assert.deepEqual(res.body,{id:ID,restored:true,contentSha256:HASH});
  assert.equal(res.headers['Cache-Control'],'no-store');
});

test('로그인 없음·실패는 JSON 401이며 복원 RPC를 실행하지 않는다',async()=>{
  let calls=0;
  for(const verifier of [async()=>null,async()=>{throw Error('synthetic-private-marker');}]) {
    const handler=create({verifyLogin:verifier,callRpc:async()=>{calls++;}});
    const res=response();await handler(request(),res);
    assert.equal(res.statusCode,401);assert.deepEqual(res.body,{error:'LOGIN_REQUIRED'});
  }
  const res=response();const req=request();delete req.headers.authorization;
  await create({callRpc:async()=>{calls++;}})(req,res);
  assert.equal(res.statusCode,401);assert.equal(calls,0);
});

test('본문 소유자·역할·내용·여러 ID·기능 쿼리와 다른 메서드는 거부한다',async()=>{
  let calls=0;
  const handler=create({callRpc:async()=>{calls++;}});
  for(const input of [{...body,owner_id:B},{...body,userId:B},{...body,role:'instructor'},
    {...body,title:'forged'},{...body,content:'forged'},{...body,id:[ID]},
    {...body,backupId:[BACKUP]},{...body,contentSha256:[HASH]},{...body,currentSha256:[CURRENT]}]) {
    const res=response();await handler(request(input),res);assert.equal(res.statusCode,400);
  }
  const query=response();await handler(request(body,'/api/restore-notes?action=all'),query);
  assert.equal(query.statusCode,400);
  const method=response();await handler({...request(),method:'GET'},method);
  assert.equal(method.statusCode,405);assert.equal(calls,0);
});

test('사본 누락·소유자 거부·해시 불일치·확인 뒤 변경은 자료 없이 JSON 오류를 반환한다',async()=>{
  for(const [code,status] of [['RESTORE_SOURCE_NOT_FOUND',404],['RESTORE_SOURCE_UNVERIFIED',409],
    ['RESTORE_HASH_MISMATCH',409],['RESTORE_STATE_CHANGED',409],['RESTORE_CONFLICT',409],
    ['untrusted synthetic-private-marker',503]]) {
    const handler=create({callRpc:async()=>{throw Error(code);}});
    const res=response();await handler(request(),res);
    assert.equal(res.statusCode,status);
    assert.deepEqual(res.body,{error:status===503?'RESTORE_UNAVAILABLE':code});
    assert.equal(res.headers['X-Resource-Decision'],'deny');
  }
});

test('서버 RPC는 서버 키만 사용하고 오류 상세·사본 원문을 화면에 전달하지 않는다',async()=>{
  const rpc=createRestoreRpc({env:{SUPABASE_URL:'https://fixture.example.invalid',SUPABASE_SECRET_KEY:'fixture-only-key'},
    fetchImpl:async(url,options)=>{
      assert.equal(url.pathname,'/rest/v1/rpc/learning_restore_note');
      assert.equal(options.headers.apikey,'fixture-only-key');
      assert.equal(options.cache,'no-store');
      return {ok:false,json:async()=>({code:'23514',message:'synthetic-private-marker',details:'do not echo'})};
    }});
  await assert.rejects(rpc('learning_restore_note',{}),/^Error: RESTORE_UNAVAILABLE$/);
});

test('복원 라우트는 설정된 POST 경로 문자열과 일치한다',async()=>{
  const {default:config}=await import('../aleph.config.json',{with:{type:'json'}});
  assert.equal(config.restoreRoute,'/api/restore/notes/:id');
  assert.ok(config.allowedRoutes.includes('POST /api/restore/notes/:id'));
  assert.ok(config.allowedRoutes.includes('POST /api/restore-notes'));
  assert.ok(config.allowedRoutes.includes('POST /api/restore-notes/preview'));
  assert.ok(config.step>=10);
});

test('설정된 경로의 ID로 B 본인 메모 한 건만 복원한다',async()=>{
  const handler=create({pathParam:true,callRpc:async(name,payload)=>{
    assert.equal(name,'learning_restore_note');
    assert.deepEqual(payload,{p_actor:B,p_note_id:ID,p_backup_id:BACKUP,p_content_hash:HASH,p_expected_current:CURRENT});
    return {id:ID,restored:true,contentSha256:HASH};
  }});
  const res=response();
  await handler(request({backupId:BACKUP,contentSha256:HASH,currentSha256:CURRENT},`/api/restore/notes/${ID}`),res);
  assert.equal(res.statusCode,200);
  assert.deepEqual(res.body,{id:ID,restored:true,contentSha256:HASH});
  const extra=response();
  await handler(request({...body,id:ID},`/api/restore/notes/${ID}`),extra);
  assert.equal(extra.statusCode,400);
});
