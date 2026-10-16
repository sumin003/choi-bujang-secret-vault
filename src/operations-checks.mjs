import {randomUUID} from 'node:crypto';
import cases from './verification-cases.json' with {type:'json'};

async function smallJson(response) {
  if (!(response.headers.get('content-type') ?? '').includes('application/json')) return null;
  const reader=response.body?.getReader();
  if (!reader) return null;
  const chunks=[];let size=0;
  try {
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;
      if(size>32768) return null;chunks.push(value);}
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {return null;} finally {await reader.cancel().catch(()=>{});}
}
const safeId=value=>typeof value==='string'&&/^[A-Za-z0-9_:;.= -]{1,200}$/.test(value)?value:null;

export async function runOperationsChecks({publicAppUrl,fetchImpl=globalThis.fetch}={}) {
  const base=new URL(publicAppUrl);
  // Only the configured public Vercel origin; no client-controlled target, cookies or redirects.
  if(base.protocol!=='https:'||base.username||base.password||base.port||base.pathname!=='/'
    ||base.search||base.hash||!base.hostname.endsWith('.vercel.app'))throw Error('invalid_probe_origin');
  const plans=[{id:'T03',path:'/aleph.json',kind:'identity'},
    {id:'T07',path:'/api/notes',kind:'anonymous'},
    {id:'anonymous_single',path:'/api/notes/00000000-0000-4000-8000-000000000001',kind:'anonymous'}];
  const probes=await Promise.all(plans.map(async plan=>{
    const out={id:plan.id,method:'GET',path:plan.path,status:'NOT_RUN',httpStatus:null,
      reason:'response_unverified',requestId:randomUUID(),requestIdSource:'operations_correlation',
      targetRequestId:null,targetRequestIdHeader:null,checkedAt:null};
    try {
      const response=await fetchImpl(new URL(plan.path,base),{method:'GET',redirect:'manual',cache:'no-store',
        credentials:'omit',signal:AbortSignal.timeout(4000),
        headers:{Accept:'application/json','X-Request-Id':out.requestId}});
      out.checkedAt=new Date().toISOString();out.httpStatus=response.status;
      for(const key of ['x-request-id','x-vercel-id']){
        const id=safeId(response.headers.get(key));
        if(id){out.targetRequestId=id;out.targetRequestIdHeader=key;break;}
      }
      const data=await smallJson(response);
      if(data===null)return out; // HTML, protection pages, oversized responses are not app evidence.
      if(plan.kind==='identity'){
        if(response.status!==200)return out;
        out.status=data.schema==='aleph.defense.deployment.v1'&&Number.isInteger(data.step)&&data.step>=12
          &&/^[a-f0-9]{40}$/.test(data.commit??'')?'PASS':'FAIL';
        out.reason=out.status==='PASS'?'deployment_identity_confirmed':'deployment_identity_mismatch';
      }else{
        const denied=[401,403].includes(response.status)
          &&['LOGIN_REQUIRED','UNAUTHORIZED','AUTH_REQUIRED'].includes(data?.error)
          &&Object.keys(data).every(key=>['error','reason'].includes(key));
        if(denied){out.status='PASS';out.reason='anonymous_denied_without_data';}
        else if(response.status===200){out.status='FAIL';out.reason='anonymous_read_not_denied';}
      }
    } catch {out.reason='request_failed';}
    return out;
  }));
  const rows=cases.map(item=>({...item,...(probes.find(p=>p.id===item.id)
    ??{status:'NOT_RUN',httpStatus:null,reason:'not_executed',requestId:null,
      requestIdSource:null,targetRequestId:null,targetRequestIdHeader:null,checkedAt:null})}));
  const counts={PASS:0,FAIL:0,NOT_RUN:0};for(const row of rows)counts[row.status]++;
  // Supplementary anonymous single-read probe is not a B→A ownership test and not counted as one.
  return {source:'live_anonymous_http',rows,counts,supplementary:probes.filter(p=>!cases.some(c=>c.id===p.id))};
}
