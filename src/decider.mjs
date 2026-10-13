// Self-contained decision module: importing it requires no sibling files,
// packages, environment variables or server network capabilities.
// Resource-kind identifiers, distinct from individual note UUIDs.
// These definitions grant no access and do not change existing routes.
export const RESOURCE_IDS = Object.freeze({
  notes: 'notes',
  instructorAnnouncements: 'instructor_announcements',
});

// Only call with the engine-validated request; never trust a client resourceId.
export function resourceIdForRequest(request) {
  if (!request || typeof request.path !== 'string') return null;
  const resources = [
    { service: 'notes', id: RESOURCE_IDS.notes, prefixes: ['/notes', '/api/notes'] },
    { service: 'instructor_announcements', id: RESOURCE_IDS.instructorAnnouncements,
      prefixes: ['/announcements', '/api/announcements'] },
  ];
  const reserved = new Set(['export', 'import', 'search', 'bulk', 'download', 'upload', 'action', 'admin']);
  for (const resource of resources) {
    if (request.service !== resource.service) continue;
    for (const prefix of resource.prefixes) {
      if (request.path === prefix && ['GET', 'POST'].includes(request.method)
        && request.route === request.method + ' ' + prefix) return resource.id;
      const id = request.path.startsWith(prefix + '/') ? request.path.slice(prefix.length + 1) : '';
      if (/^[A-Za-z0-9._~-]{1,128}$/.test(id) && !['.','..'].includes(id) && !reserved.has(id.toLowerCase())
        && ['GET', 'PUT', 'DELETE'].includes(request.method)
        && request.route === request.method + ' ' + prefix + '/:id') return resource.id;
    }
  }
  return null;
}



// Explicit synthetic policy, scoped to the supplied local engine fixture.
// This is not a Supabase account map and grants no production DB permissions.
const SCOPE = Object.freeze({classId:'class_fixture',projectId:'project_fixture',source:'judge_fixture'});
const SUBJECTS = Object.freeze({
  learner_fixture:'student',
  other_learner_fixture:'student',
  teacher_fixture:'instructor',
});
const NOTE_OWNERS = Object.freeze({
  demo:'learner_fixture', // Original stage 6/7 fixture resource.
  '11111111-1111-4111-8111-111111111111':'learner_fixture', // Existing local UUID fixture alias.
  'other-demo':'other_learner_fixture',
});
const NOTICE_OWNERS = Object.freeze({'notice-demo':'teacher_fixture'});

// null means this policy does not apply; false is a definitive refusal.
export function fixtureZoneAccess(request) {
  if (request.classId!==SCOPE.classId || request.projectId!==SCOPE.projectId
    || request.signals?.source!==SCOPE.source) return null;
  const role=Object.hasOwn(SUBJECTS,request.subjectId) ? SUBJECTS[request.subjectId] : null;
  if (!role) return false;
  const resource=resourceIdForRequest(request);
  if (!resource) return false;
  const id=request.path.split('/').at(-1);
  const collection=['/notes','/api/notes','/announcements','/api/announcements'].includes(request.path);
  if (resource===RESOURCE_IDS.notes) {
    if (collection) return request.method==='POST';
    return Object.hasOwn(NOTE_OWNERS,id) && NOTE_OWNERS[id]===request.subjectId
      && ['GET','PUT','DELETE'].includes(request.method);
  }
  if (resource===RESOURCE_IDS.instructorAnnouncements) {
    // The eighteen-field engine contract cannot establish an instructor role.
    if (request.method!=='GET') return false;
    if (role!=='instructor') return false;
    if (collection) return true;
    return Object.hasOwn(NOTICE_OWNERS,id) && NOTICE_OWNERS[id]===request.subjectId
      && request.method==='GET';
  }
  return false;
}


export function createResourceStore({fetchImpl, env} = {}) {
  return async (table, params, {method = 'GET', body} = {}) => {
    // Resolve server capabilities at request time; isolated imports need none.
    const settings=env ?? globalThis.process?.env ?? {};
    const send=fetchImpl ?? globalThis.fetch;
    if (!settings.SUPABASE_URL || !settings.SUPABASE_SECRET_KEY || typeof send!=='function')
      throw new Error('resource_store_unavailable');
    const base = new URL(settings.SUPABASE_URL);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash
      || base.pathname !== '/') throw new Error('resource_store_unavailable');
    if (!['learning_resource_subjects','learning_instructors','learning_announcements','learning_notes'].includes(table))
      throw new Error('unknown_resource');
    const url = new URL('/rest/v1/' + table, base);
    url.search = new URLSearchParams(params);
    const response = await send(url, {method, redirect:'error', cache:'no-store',
      signal:AbortSignal.timeout(5000), headers:{apikey:settings.SUPABASE_SECRET_KEY,
        Accept:'application/json', 'Content-Type':'application/json', Prefer:'return=representation'},
      body:body ? JSON.stringify(body) : undefined});
    if (!response.ok) throw new Error('resource_store_unavailable');
    const rows = await response.json();
    if (!Array.isArray(rows)) throw new Error('resource_store_unavailable');
    return rows;
  };
}

export async function isStoredInstructor(identity, store) {
  if (!identity || !['student','judge'].includes(identity.kind)) return false;
  const rows = await store('learning_instructors', {select:'user_id,identity_kind,enabled',
    user_id:'eq.' + identity.userId, identity_kind:'eq.' + identity.kind, enabled:'eq.true'});
  return rows.length === 1 && rows[0].user_id === identity.userId
    && rows[0].identity_kind === identity.kind && rows[0].enabled === true;
}

// Called only with identity returned by the server's login verifier.
// Engine and HTTP entry points share this ownership/permission policy.
export async function checkVerifiedResource(identity, request, store) {
  const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!identity || !uuid.test(identity.userId ?? '') || !['student','judge'].includes(identity.kind))
    return {allowed:false,reason:'login_required'};
  const resource=resourceIdForRequest(request);
  if (!resource) return {allowed:false,reason:'invalid_resource_route'};
  const collection=['/notes','/api/notes','/announcements','/api/announcements'].includes(request.path);
  if (resource===RESOURCE_IDS.instructorAnnouncements && !await isStoredInstructor(identity,store))
    return {allowed:false,reason:'instructor_required'};
  if (collection) return {allowed:true,reason:'verified_collection'};
  const id=request.path.split('/').at(-1);
  if (!uuid.test(id)) return {allowed:false,reason:'invalid_resource_id'};
  const notes=resource===RESOURCE_IDS.notes;
  const rows=await store(notes?'learning_notes':'learning_announcements',{
    select:notes?'owner_id':'owner_id,owner_kind',
    [notes?'note_id':'id']:'eq.'+id,owner_id:'eq.'+identity.userId,
    ...(!notes?{owner_kind:'eq.'+identity.kind}:{})});
  const allowed=rows.length===1 && rows[0].owner_id===identity.userId
    && (notes || rows[0].owner_kind===identity.kind);
  return {allowed,reason:allowed?'owner_verified':'not_found_or_not_owned'};
}

export function createResourceAuthorizer({store = createResourceStore()} = {}) {
  return async request => {
    const resource = resourceIdForRequest(request);
    if (!resource) return false;
    const bindings = await store('learning_resource_subjects', {select:'user_id,identity_kind',
      class_id:'eq.' + request.classId, project_id:'eq.' + request.projectId,
      subject_id:'eq.' + request.subjectId});
    if (bindings.length !== 1 || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(bindings[0].user_id)
      || !['student','judge'].includes(bindings[0].identity_kind)) return false;
    const identity = {userId:bindings[0].user_id, kind:bindings[0].identity_kind};
    return (await checkVerifiedResource(identity,request,store)).allowed;
  };
}

// The engine subject is resolved through trusted storage before either zone is
// allowed. The final API independently repeats its own login/ownership checks.
export function createZoneAuthorizer({store = createResourceStore()} = {}) {
  const authorizeStoredResource=createResourceAuthorizer({store});
  return async request => {
    const synthetic=fixtureZoneAccess(request);
    if (synthetic!==null) return synthetic;
    return authorizeStoredResource(request);
  };
}

// Only the engine-validated request contract is accepted here.
// XDR is a separate, deny-only layer and never supplies an allow decision.
export const RULE_IDS = Object.freeze(['starter.deny', 'verified_request.allow', 'xdr.brute_force.deny', 'device_registered', 'step_up_required', 'resource_zone']);
const FIELDS = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId',
  'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
  'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const plainObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => plainObject(value) && Object.keys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value,key));
const shortText = value => typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);

function validSignals(signals) {
  if (!exactKeys(signals, ['source', 'region', 'network', 'hour'])
    || !Number.isInteger(signals.hour) || signals.hour < 0 || signals.hour > 23) return false;
  // No connection evidence: keep the contract's unknown values, never infer a normal location.
  if (signals.source === 'none') {
    return signals.region === 'unknown' && signals.network === 'unknown';
  }
  // Engine-provided synthetic evidence is for practice, not proof of a real location.
  if (signals.source === 'judge_fixture') {
    return shortText(signals.region) && shortText(signals.network)
      && signals.region !== 'unknown' && signals.network !== 'unknown';
  }
  return false;
}

function allowedRoute(request) {
  // Query contents are unavailable in this contract; no query may select a function.
  if (request.queryLength !== 0
    || request.querySha256 !== 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') return false;
  // Function names are never accepted as a resource ID at the /:id depth.
  const finalSegment = typeof request.path === 'string' ? request.path.split('/').at(-1) : '';
  if (['export', 'import', 'search', 'bulk', 'download', 'upload', 'action', 'admin'].includes(finalSegment.toLowerCase())) return false;
  const resource = resourceIdForRequest(request);
  return resource===RESOURCE_IDS.notes || resource===RESOURCE_IDS.instructorAnnouncements;
}
function normalRequest(request, now) {
  if(!exactKeys(request,FIELDS))return false;
  return request.schema === 'aleph.decision.v1' && typeof request.requestId === 'string' && UUID.test(request.requestId)
    && ['classId','projectId','subjectId'].every(key=>shortText(request[key]))
    && typeof request.deviceId === 'string' && /^[0-9a-f]{16}$/.test(request.deviceId)
    && request.deviceRegistered === true && typeof request.path === 'string' && allowedRoute(request)
    && Number.isInteger(request.queryLength) && request.queryLength>=0
    && typeof request.querySha256 === 'string' && /^[0-9a-f]{64}$/.test(request.querySha256)
    && typeof request.at === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/.test(request.at)
    && Number.isFinite(Date.parse(request.at)) && Math.abs(Date.parse(request.at)-now)<=5000
    && Number.isInteger(request.policyRevision) && request.policyRevision>=1
    && exactKeys(request.stepUp,['verified','authAgeSeconds'])
    && ((request.stepUp.verified === false && request.stepUp.authAgeSeconds === null)
      || (request.stepUp.verified === true && Number.isInteger(request.stepUp.authAgeSeconds)
        && request.stepUp.authAgeSeconds>=0 && request.stepUp.authAgeSeconds<=900))
    && Array.isArray(request.recentEvents) && request.recentEvents.length<=12
    && request.recentEvents.every(e=>exactKeys(e,['kind','ageSeconds','count']) && shortText(e.kind)
      && Number.isFinite(e.ageSeconds) && e.ageSeconds>=0 && Number.isInteger(e.count) && e.count>=0)
    && validSignals(request.signals);
}
// Preserve the existing denial for requests outside the normal allow rule.
function starterDeny(request) {
  return {schema:'aleph.decision.v1',requestId:request?.requestId,decision:'deny',
    reasonCode:'starter_not_ready',ruleIds:['starter.deny']};
}
function requiresStepUp(request) {
  // Synthetic practice signals only; region alone never determines this decision.
  return request.signals.source === 'judge_fixture'
    && request.method === 'GET'
    && (request.signals.hour < 6 || request.signals.hour >= 23)
    && request.signals.network === 'unusual'
    && request.recentEvents.some(event => event.kind === 'risk_signal'
      && event.ageSeconds <= 120 && event.count >= 20);
}
function forbiddenEngineZone(request) {
  const resource=resourceIdForRequest(request);
  // A collection read can expose multiple owners; the HTTP API separately
  // filters its authenticated user's list and is not this engine entry point.
  if (resource===RESOURCE_IDS.notes && request.method==='GET'
    && ['/notes','/api/notes'].includes(request.path)) return true;
  // No instructor role exists in the engine request contract. Stored HTTP API
  // permissions must never promote an engine request into a notice writer.
  return resource===RESOURCE_IDS.instructorAnnouncements && request.method!=='GET';
}
export function createBaseDecider({now=()=>Date.now(), authorizeResource=createZoneAuthorizer()}={}) {
  return async request => {
    if (request?.deviceRegistered !== true) {
      return {schema:'aleph.decision.v1',requestId:request?.requestId,decision:'deny',
        reasonCode:'device_not_registered',ruleIds:['device_registered']};
    }
    if (!normalRequest(request, now())) return starterDeny(request);
    let authorized = false;
    try { authorized = !forbiddenEngineZone(request) && await authorizeResource(request) === true; } catch { /* Fail closed without logging credentials. */ }
    if (!authorized) return {schema:'aleph.decision.v1',requestId:request.requestId,
      decision:'deny',reasonCode:'starter_not_ready',ruleIds:['resource_zone']};
    if (requiresStepUp(request) && request.stepUp.verified !== true) {
      return {schema:'aleph.decision.v1',requestId:request.requestId,decision:'step_up',
        reasonCode:'step_up_required',ruleIds:['device_registered','step_up_required']};
    }
    return {schema:'aleph.decision.v1',requestId:request.requestId,decision:'allow',
      reasonCode:'approved',ruleIds:['verified_request.allow','device_registered','resource_zone']};
  };
}
const baseDecide = createBaseDecider();
export async function decide(request) { return baseDecide(request); }

// Server HTTP bridge: uses the UUID already verified by createLoginVerifier.
// It does not invent any engine identity, registration, device or step-up data.
// This is a separate entry point, not a change to the eighteen-field engine contract.
export async function decideAuthenticatedResource({identity,service,method,path,route},
  {store=createResourceStore()}={}) {
  let result;
  try {result=await checkVerifiedResource(identity,{service,method,path,route},store);}
  catch {result={allowed:false,reason:'resource_lookup_unavailable'};}
  return {schema:'aleph.resource.decision.v1',decision:result.allowed?'allow':'deny',
    reasonCode:result.reason,ruleIds:['resource_zone'],resourceId:resourceIdForRequest({service,method,path,route})};
}

// Safe observation of real server decisions: no tokens, identities or note bodies.
export function exposeResourceDecision(res,result) {
  res.setHeader('X-Resource-Decision',result.decision);
  res.setHeader('X-Resource-Rule','resource_zone');
  res.setHeader('X-Resource-Reason',result.reasonCode);
}
