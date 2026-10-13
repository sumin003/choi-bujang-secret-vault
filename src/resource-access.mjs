import { RESOURCE_IDS, resourceIdForRequest } from './resources.mjs';
import { fixtureZoneAccess } from './resource-zone-policy.mjs';

export function createResourceStore({fetchImpl = fetch, env = process.env} = {}) {
  return async (table, params, {method = 'GET', body} = {}) => {
    if (!env.SUPABASE_URL || !env.SUPABASE_SECRET_KEY) throw new Error('resource_store_unavailable');
    const base = new URL(env.SUPABASE_URL);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash
      || base.pathname !== '/') throw new Error('resource_store_unavailable');
    if (!['learning_resource_subjects','learning_instructors','learning_announcements','learning_notes'].includes(table))
      throw new Error('unknown_resource');
    const url = new URL('/rest/v1/' + table, base);
    url.search = new URLSearchParams(params);
    const response = await fetchImpl(url, {method, redirect:'error', cache:'no-store',
      signal:AbortSignal.timeout(5000), headers:{apikey:env.SUPABASE_SECRET_KEY,
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
