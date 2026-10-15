import { enforceXdr } from '../src/xdr-gate.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { enforceApprovedDevice } from '../src/device-approval.mjs';
import { decideAuthenticatedResource, exposeResourceDecision } from '../src/decider.mjs';
import { createResourceStore, isStoredInstructor } from '../src/resource-access.mjs';
import config from '../aleph.config.json' with {type:'json'};
import { randomUUID } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function createAnnouncementHandler({store=createResourceStore(), verifyLogin,
  approveDevice=enforceApprovedDevice,
  xdr=enforceXdr, makeId=randomUUID}={}) {
  let verifier=verifyLogin;
  return async (req,res,id=null) => {
    res.setHeader('Cache-Control','no-store');
    res.setHeader('X-Resource-Id','instructor_announcements');
    if (!xdr(req,res)) return;
    const methods=id===null ? ['GET','POST'] : ['GET','PUT','DELETE'];
    if (!methods.includes(req.method)) {res.setHeader('Allow',methods.join(', '));return res.status(405).json({error:'METHOD_NOT_ALLOWED'});}
    if (id!==null && !UUID.test(id)) return res.status(400).json({error:'INVALID_ID'});
    // The actual URL must match the fixed handler, never query-selected actions.
    if (typeof req.url !== 'string') return res.status(400).json({error:'INVALID_ROUTE'});
    const target=new URL(req.url,'https://request.invalid');
    if (target.search || target.pathname !== '/api/announcements'+(id===null ? '' : '/'+id))
      return res.status(400).json({error:'INVALID_ROUTE'});
    let identity;
    try {
      verifier ??= createLoginVerifier({config,supabaseSecretKey:process.env.SUPABASE_SECRET_KEY});
      const authorization=req.headers?.authorization;
      identity=await verifier(authorization);
    } catch { /* No token or upstream details in responses/logs. */ }
    if (!identity) return res.status(401).json({error:'LOGIN_REQUIRED'});
    if (!await approveDevice(req,res,identity)) return;
    try {
      const path='/api/announcements'+(id===null?'':'/'+id);
      const zone=await decideAuthenticatedResource({identity,service:'instructor_announcements',method:req.method,
        path,route:req.method+' /api/announcements'+(id===null?'':'/:id')},{store});
      exposeResourceDecision(res,zone);
      if (zone.decision!=='allow') {
        if (zone.reasonCode==='resource_lookup_unavailable') return res.status(503).json({error:'ANNOUNCEMENTS_UNAVAILABLE'});
        if (zone.reasonCode==='instructor_required') return res.status(403).json({error:'ACCESS_DENIED',reason:'instructor_required'});
        return res.status(404).json({error:'ANNOUNCEMENT_NOT_FOUND',reason:'not_found_or_not_owned'});
      }
      if (!await isStoredInstructor(identity,store)) {
        exposeResourceDecision(res,{...zone,decision:'deny',reasonCode:'instructor_required'});
        return res.status(403).json({error:'ACCESS_DENIED',reason:'instructor_required'});
      }
      let payload;
      if (['POST','PUT'].includes(req.method)) {
        if (!/^application\/json(?:;|$)/i.test(req.headers?.['content-type'] ?? ''))
          return res.status(415).json({error:'JSON_REQUIRED'});
        let input;try {input=typeof req.body==='string'?JSON.parse(req.body):req.body;}catch{}
        if (!input || Array.isArray(input) || typeof input.title!=='string' || !input.title.trim()
          || input.title.length>200 || typeof input.body!=='string' || !input.body.trim() || input.body.length>10000)
          return res.status(400).json({error:'INVALID_ANNOUNCEMENT'});
        payload={title:input.title,body:input.body,owner_id:identity.userId,owner_kind:identity.kind};
        if (req.method==='POST') {
          if (input.id!==undefined && !UUID.test(input.id)) return res.status(400).json({error:'INVALID_ID'});
          payload.id=input.id ?? makeId();
        }
      }
      const params={select:'id,title,body,owner_id,owner_kind'};
      if (req.method!=='POST') {
        params.owner_id='eq.'+identity.userId;params.owner_kind='eq.'+identity.kind;
        if (id!==null) params.id='eq.'+id;
      }
      const rows=await store('learning_announcements',params,
        {method:req.method==='PUT'?'PATCH':req.method,body:payload});
      if (rows.some(row=>row.owner_id!==identity.userId || row.owner_kind!==identity.kind)) {
        exposeResourceDecision(res,{...zone,decision:'deny',reasonCode:'owner_mismatch'});
        return res.status(403).json({error:'ACCESS_DENIED',reason:'owner_mismatch'});
      }
      if (id!==null && rows.length===0) {
        exposeResourceDecision(res,{...zone,decision:'deny',reasonCode:'not_found_or_not_owned'});
        return res.status(404).json({error:'ANNOUNCEMENT_NOT_FOUND',reason:'not_found_or_not_owned'});
      }
      if (req.method==='DELETE') return res.status(204).end();
      if (rows.some(row=>!UUID.test(row.id) || typeof row.title!=='string' || typeof row.body!=='string')) throw new Error();
      const output=rows.map(({id,title,body})=>({id,title,body}));
      if (req.method==='POST') {
        if (output.length!==1) throw new Error();
        return res.status(201).json({id:output[0].id});
      }
      return res.status(200).json(id===null ? output : output[0]);
    } catch {return res.status(503).json({error:'ANNOUNCEMENTS_UNAVAILABLE'});}
  };
}
export const handleAnnouncements=createAnnouncementHandler();
export default async function handler(req,res) {return handleAnnouncements(req,res,null);}
