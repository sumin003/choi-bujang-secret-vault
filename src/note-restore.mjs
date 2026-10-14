import { enforceXdr } from './xdr-gate.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HASH = /^[0-9a-f]{64}$/;
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => plain(value) && Object.keys(value).length===keys.length
  && keys.every(key => Object.hasOwn(value,key));
const ERROR_STATUS = Object.freeze({ RESTORE_SOURCE_NOT_FOUND:404, RESTORE_SOURCE_UNVERIFIED:409,
  RESTORE_HASH_MISMATCH:409, RESTORE_STATE_CHANGED:409, RESTORE_CONFLICT:409 });

export function createRestoreRpc({ env=process.env, fetchImpl=globalThis.fetch }={}) {
  return async (name, payload) => {
    const code = () => { throw new Error('RESTORE_UNAVAILABLE'); };
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY || typeof fetchImpl!=='function'
      || !['learning_preview_note_restore','learning_restore_note'].includes(name)) return code();
    const base = new URL(env.SUPABASE_URL);
    if (base.protocol!=='https:' || base.username || base.password || base.search || base.hash || base.pathname!=='/') return code();
    const response=await fetchImpl(new URL('/rest/v1/rpc/'+name,base),{method:'POST',redirect:'error',cache:'no-store',
      signal:AbortSignal.timeout(10000),headers:{apikey:env.SUPABASE_SECRET_KEY,'Content-Type':'application/json'},
      body:JSON.stringify(payload)});
    const data=await response.json();
    if (!response.ok) {
      if (data?.code==='P0001' && Object.hasOwn(ERROR_STATUS,data.message)) throw new Error(data.message);
      return code();
    }
    return data;
  };
}

export function createNoteRestoreHandler({ preview=false, pathParam=false, verifyLogin, callRpc,
  enforceRequest=enforceXdr, env=process.env }={}) {
  let verifier=verifyLogin;
  const rpc=callRpc ?? createRestoreRpc({env});
  const path=pathParam?'/api/restore/notes/:id':preview?'/api/restore-notes/preview':'/api/restore-notes';
  return async (req,res) => {
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Resource-Id','notes');
    if (!enforceRequest(req,res)) return;
    let target;
    try { if (typeof req.url==='string') target=new URL(req.url,'https://request.invalid'); } catch {}
    const routeMatch=pathParam && target
      ? /^\/api\/restore\/notes\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(target.pathname)
      : null;
    if (!target || (pathParam?!routeMatch:target.pathname!==path) || target.search || target.hash)
      return res.status(400).json({error:'INVALID_ROUTE'});
    if (req.method!=='POST') {
      res.setHeader('Allow','POST');
      return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
    }
    if (typeof req.headers?.authorization!=='string') return res.status(401).json({error:'LOGIN_REQUIRED'});
    let identity;
    try {
      if (!verifier) {
        if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) return res.status(503).json({error:'RESTORE_UNAVAILABLE'});
        const { createLoginVerifier }=await import('./verify-login.mjs');
        verifier=createLoginVerifier({config,supabaseSecretKey:env.SUPABASE_SECRET_KEY});
      }
      identity=await verifier(req.headers.authorization);
    } catch { return res.status(401).json({error:'LOGIN_REQUIRED'}); }
    if (!identity || !['student','judge'].includes(identity.kind)
      || typeof identity.userId!=='string' || !UUID.test(identity.userId))
      return res.status(401).json({error:'LOGIN_REQUIRED'});
    if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? ''))
      return res.status(415).json({error:'JSON_REQUIRED'});
    let input;
    try { input=typeof req.body==='string' && req.body.length<=2048 ? JSON.parse(req.body) : req.body; } catch {}
    const keys=pathParam?['backupId','contentSha256','currentSha256']
      :preview?['id']:['id','backupId','contentSha256','currentSha256'];
    const noteId=pathParam?routeMatch?.[1]:input?.id;
    if (!exact(input,keys) || typeof noteId!=='string' || !UUID.test(noteId)
      || (!preview && (typeof input.backupId!=='string' || !UUID.test(input.backupId)
        || typeof input.contentSha256!=='string' || !HASH.test(input.contentSha256)
        || typeof input.currentSha256!=='string'
        || (input.currentSha256!=='missing' && !HASH.test(input.currentSha256)))))
      return res.status(400).json({error:'INVALID_RESTORE_REQUEST'});
    const payload={p_actor:identity.userId,p_note_id:noteId};
    if (!preview) Object.assign(payload,{p_backup_id:input.backupId,p_content_hash:input.contentSha256,
      p_expected_current:input.currentSha256});
    try {
      const data=await rpc(preview?'learning_preview_note_restore':'learning_restore_note',payload);
      if (!plain(data) || data.id!==noteId || !HASH.test(data.contentSha256 ?? '')) throw new Error('RESTORE_UNAVAILABLE');
      res.setHeader('X-Resource-Decision','allow');
      res.setHeader('X-Resource-Reason',preview?'restore_preview_verified':'restore_verified');
      if (preview) {
        if (!UUID.test(data.backupId ?? '') || !['update','recreate'].includes(data.operation)
          || (data.currentSha256!=='missing' && !HASH.test(data.currentSha256 ?? ''))) throw new Error('RESTORE_UNAVAILABLE');
        return res.status(200).json({id:data.id,backupId:data.backupId,contentSha256:data.contentSha256,
          currentSha256:data.currentSha256,operation:data.operation});
      }
      if (data.restored!==true || data.contentSha256!==input.contentSha256) throw new Error('RESTORE_UNAVAILABLE');
      return res.status(200).json({id:data.id,restored:true,contentSha256:data.contentSha256});
    } catch (error) {
      const known=Object.hasOwn(ERROR_STATUS,error?.message ?? '');
      res.setHeader('X-Resource-Decision','deny');
      res.setHeader('X-Resource-Reason',known?'restore_rejected':'restore_unavailable');
      return res.status(known?ERROR_STATUS[error.message]:503).json({error:known?error.message:'RESTORE_UNAVAILABLE'});
    }
  };
}
