import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createNoteRestoreHandler } from '../src/note-restore.mjs';
import { runRestorePreview, applyTrialRestore } from '../src/restore-workflow.mjs';
import { fixtureRequests } from './fixture-7.mjs';

const A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const A_NOTE='11111111-1111-4111-8111-111111111111';
const B_NOTE='22222222-2222-4222-8222-222222222222';
const BACKUP='33333333-3333-4333-8333-333333333333';
const HASH='a'.repeat(64), CURRENT='b'.repeat(64);
const response=()=>({statusCode:200,headers:{},setHeader(k,v){this.headers[k]=v;},
  status(n){this.statusCode=n;return this;},json(v){this.body=v;return this;},end(){return this;}});
const requireCheck=(ok,code)=>{if(!ok)throw new Error(code);};

async function checkNoteRestoreThenAccess(){
  const originalFetch=globalThis.fetch;
  const originalUrl=process.env.SUPABASE_URL, originalKey=process.env.SUPABASE_SECRET_KEY;
  const rows=new Map([
    [A_NOTE,{note_id:A_NOTE,owner_id:A,title:'A note',content:'A body'}],
    [B_NOTE,{note_id:B_NOTE,owner_id:B,title:'damaged',content:'damaged'}],
  ]);
  const backup={note_id:B_NOTE,owner_id:B,title:'restored B note',content:'restored B body'};
  try {
    process.env.SUPABASE_URL='https://fixture.example.invalid';
    process.env.SUPABASE_SECRET_KEY='fixture-only';
    const preview=createNoteRestoreHandler({preview:true,verifyLogin:async()=>({kind:'student',userId:B}),
      enforceRequest:()=>true,callRpc:async(name,payload)=>{
        requireCheck(name==='learning_preview_note_restore' && payload.p_actor===B && payload.p_note_id===B_NOTE,'preview_check_failed');
        return {id:B_NOTE,backupId:BACKUP,contentSha256:HASH,currentSha256:CURRENT,operation:'update'};
      }});
    const restore=createNoteRestoreHandler({verifyLogin:async()=>({kind:'student',userId:B}),
      enforceRequest:()=>true,callRpc:async(name,payload)=>{
        requireCheck(name==='learning_restore_note' && payload.p_actor===B && payload.p_note_id===B_NOTE
          && payload.p_backup_id===BACKUP && payload.p_content_hash===HASH && payload.p_expected_current===CURRENT,
          'restore_check_failed');
        rows.set(B_NOTE,{...backup});
        return {id:B_NOTE,restored:true,contentSha256:HASH};
      }});
    const prepared=response();
    await preview({method:'POST',url:'/api/restore-notes/preview',headers:{authorization:'B','content-type':'application/json'},
      body:{id:B_NOTE}},prepared);
    requireCheck(prepared.statusCode===200,'preview_http_failed');
    const restored=response();
    await restore({method:'POST',url:'/api/restore-notes',headers:{authorization:'B','content-type':'application/json'},
      body:{id:B_NOTE,backupId:BACKUP,contentSha256:HASH,currentSha256:CURRENT}},restored);
    requireCheck(restored.statusCode===200 && rows.get(B_NOTE).content===backup.content,'note_restore_failed');

    const source=await readFile(new URL('../api/notes.js',import.meta.url),'utf8');
    const stripped=source.replace(/^import .*;\n/gm,'');
    const deciderUrl=new URL('../src/decider.mjs',import.meta.url).href;
    const prelude=`import {decideAuthenticatedResource,exposeResourceDecision} from ${JSON.stringify(deciderUrl)};\n`
      +`const enforceXdr=()=>true,config={},randomUUID=()=>${JSON.stringify(B_NOTE)};\n`
      +`const createLoginVerifier=()=>async token=>({userId:token==='Bearer A'?${JSON.stringify(A)}:${JSON.stringify(B)},kind:'student'});\n`;
    const module=await import('data:text/javascript;base64,'+Buffer.from(prelude+stripped).toString('base64'));
    globalThis.fetch=async url=>{
      const id=url.searchParams.get('note_id')?.slice(3), owner=url.searchParams.get('owner_id')?.slice(3);
      const row=rows.get(id);
      return {ok:true,status:200,json:async()=>row&&row.owner_id===owner
        ?[{id:row.note_id,title:row.title,body:row.content,owner_id:row.owner_id}]:[]};
    };
    const call=async(user,noteId)=>{
      const res=response();
      await module.handleNotes({method:'GET',url:'/api/notes/'+noteId,query:{id:noteId},headers:{authorization:user}},res,noteId);
      return res;
    };
    const aOwn=await call('Bearer A',A_NOTE);
    const bToA=await call('Bearer B',A_NOTE);
    const bOwnRestored=await call('Bearer B',B_NOTE);
    return { aOwnAllowed:aOwn.statusCode===200, bToADenied:bToA.statusCode===404
      && bToA.headers['X-Resource-Decision']==='deny', bOwnRestoredReadable:bOwnRestored.statusCode===200 };
  } finally {
    globalThis.fetch=originalFetch;
    if(originalUrl===undefined)delete process.env.SUPABASE_URL;else process.env.SUPABASE_URL=originalUrl;
    if(originalKey===undefined)delete process.env.SUPABASE_SECRET_KEY;else process.env.SUPABASE_SECRET_KEY=originalKey;
  }
}

async function checkPolicyRestoreThenAccess(){
  const folder=await mkdtemp(join(tmpdir(),'stage10-policy-check-'));
  try {
    const trialDir=join(folder,'trial');
    await mkdir(join(trialDir,'src'),{recursive:true});
    await writeFile(join(trialDir,'trial-policy.json'),JSON.stringify({schema:'aleph.trial.policy.v1',purpose:'isolated_test'}));
    const sourceUrl=new URL('../src/decider.mjs',import.meta.url);
    const safeSource=await readFile(sourceUrl,'utf8');
    const corrupted=safeSource.replace('NOTE_OWNERS[id]===request.subjectId','true');
    requireCheck(corrupted!==safeSource,'policy_fixture_failed');
    const version='1234567890abcdef1234567890abcdef12345678';
    const bytes=Buffer.from(JSON.stringify({schema:'aleph.policy.backup.v1',version,
      verifiedAt:'2026-10-01T00:00:00.000Z',incidentAt:'2026-10-13T00:00:00.000Z',
      files:[{path:'src/decider.mjs',content:safeSource}]}));
    const backupPath=join(folder,'safe-policy.json'), policyPath=join(trialDir,'src/decider.mjs');
    await writeFile(backupPath,bytes);await writeFile(policyPath,corrupted);
    const options={backupPath,trialDir,verifiedSha256:createHash('sha256').update(bytes).digest('hex')};
    const plan=await runRestorePreview(options);
    const applied=await applyTrialRestore({...options,approvalToken:plan.approvalToken,itemIds:plan.items.map(item=>item.id)});
    requireCheck(applied.status==='restored_selected_items','policy_restore_failed');
    const restoredSource=await readFile(policyPath,'utf8');
    const module=await import('data:text/javascript;base64,'+Buffer.from(restoredSource).toString('base64'));
    const {normal}=fixtureRequests();
    const results=[];
    for(const method of ['GET','PUT','DELETE']){
      const request={...normal,method,route:method+' /notes/:id'};
      const own=await module.decide(request);
      const other=await module.decide({...request,subjectId:'other_learner_fixture'});
      results.push(own.decision==='allow' && other.decision==='deny'
        && other.ruleIds.includes('resource_zone'));
    }
    return {aOwnAllowed:results.every(Boolean),bToADenied:results.every(Boolean),itemsRestored:plan.items.length>0};
  } finally { await rm(folder,{recursive:true,force:true}); }
}

export async function runRestoreAccessChecks(){
  const data=await checkNoteRestoreThenAccess();
  const policy=await checkPolicyRestoreThenAccess();
  return {data,policy};
}
