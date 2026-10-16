// Read-only probes against the existing deployment. No credentials or note bodies are recorded.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
const base='https://choi-bujang-secret-vault-mocha.vercel.app';
const cases=[['T01','/','home'],['T02','/data.json','removed'],['T03','/aleph.json','identity'],['T04','/','header'],['T07','/api/notes','anonymous']];
const results=await Promise.all(cases.map(async([id,path,kind])=>{
  const row={id,checkedAt:new Date().toISOString(),result:'미확인',requestId:'미제공',actual:'앱 응답 미확인'};
  try{
    const response=await fetch(base+path,{redirect:'manual',cache:'no-store',signal:AbortSignal.timeout(8000)});
    row.httpStatus=response.status;
    for(const key of ['x-request-id','x-vercel-id']){
      const value=response.headers.get(key);
      if(value&&/^[A-Za-z0-9_:;.= -]{1,200}$/.test(value)){row.requestId=key+': '+value;break;}
    }
    const type=response.headers.get('content-type')??'';
    // Reading occurs only for validation. Never persist raw responses or notes.
    let data=null,text='';
    if(type.includes('application/json'))data=await response.json().catch(()=>null);
    else if(kind==='home')text=await response.text();
    let matched=false;
    if(kind==='home')matched=response.status===200&&/BYTE BACK/.test(text)&&/login-form/.test(text);
    if(kind==='removed')matched=response.status===404&&response.headers.has('x-vercel-id');
    if(kind==='identity')matched=response.status===200&&data?.schema==='aleph.defense.deployment.v1'
      &&data.repoUrl==='https://github.com/sumin003/choi-bujang-secret-vault'&&/^[a-f0-9]{40}$/.test(data.commit??'');
    if(kind==='header')matched=response.status===200&&response.headers.get('x-content-type-options')==='nosniff';
    if(kind==='anonymous')matched=[401,403].includes(response.status)&&data&&Object.keys(data).every(k=>['error','reason'].includes(k))
      &&['LOGIN_REQUIRED','UNAUTHORIZED','AUTH_REQUIRED'].includes(data.error);
    row.result=matched?'통과':'미확인';
    row.actual='HTTP '+response.status+(matched?' · 기대 응답 확인':' · 기대한 앱 응답을 검증하지 못함');
    if(kind==='anonymous'&&matched)row.actual+=' · '+data.error+' · 자료 없음';
    if(kind==='identity'&&matched)row.deployedCommit=data.commit;
  }catch{row.actual='통신 실패 · 앱 응답 미확인';}
  return row;
}));
await mkdir(new URL('../artifacts/',import.meta.url),{recursive:true});
await writeFile(new URL('../artifacts/stage12-http.json',import.meta.url),JSON.stringify({base,source:'direct_http',results},null,2)+'\n');
const doc=new URL('../docs/STAGE12_VERIFICATION.md',import.meta.url);
let text=await readFile(doc,'utf8');
for(const row of results){
  text=text.split('\n').map(line=>{
    if(!line.startsWith('| '+row.id+' |'))return line;
    const fields=line.split('|').slice(1,-1).map(v=>v.trim());
    fields[5]=row.actual;fields[6]=row.requestId;fields[7]=row.checkedAt;fields[8]='미대조';fields[9]=row.result;
    return '| '+fields.join(' | ')+' |';
  }).join('\n');
}
const rows=text.split('\n').filter(l=>/^\| T\d{2} \|/.test(l));
const count=status=>rows.filter(l=>l.endsWith('| '+status+' |')).length;
text=text.replace(/집계: 통과 \d+ · 실패 \d+ · 미확인 \d+ · 미실행 \d+[^\n]*/,
  `집계: 통과 ${count('통과')} · 실패 ${count('실패')} · 미확인 ${count('미확인')} · 미실행 ${count('미실행')}. 직접 응답을 검증한 행만 통과이며, 미확인은 앱 허용/거부 증거가 아닙니다.`);
await writeFile(doc,text);
console.log(JSON.stringify({results,passed:count('통과'),unconfirmed:count('미확인'),notRun:count('미실행')}));
