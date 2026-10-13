import { RESOURCE_IDS, resourceIdForRequest } from './resources.mjs';

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
    const parts = request.path.split('/');
    const collection = ['notes','announcements'].includes(parts.at(-1));
    if (resource === RESOURCE_IDS.notes && collection) return ['GET','POST'].includes(request.method);
    if (resource === RESOURCE_IDS.instructorAnnouncements) {
      if (!await isStoredInstructor(identity, store)) return false;
      if (collection) return ['GET','POST'].includes(request.method);
      if (!['GET','PUT','DELETE'].includes(request.method)) return false;
    }
    const id = parts.at(-1);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) return false;
    const notes = resource === RESOURCE_IDS.notes;
    const rows = await store(notes ? 'learning_notes' : 'learning_announcements', {
      select:notes ? 'owner_id' : 'owner_id,owner_kind',
      [notes ? 'note_id' : 'id']:'eq.' + id, owner_id:'eq.' + identity.userId,
      ...(!notes ? {owner_kind:'eq.' + identity.kind} : {}),
    });
    return rows.length === 1 && rows[0].owner_id === identity.userId
      && (notes || rows[0].owner_kind === identity.kind);
  };
}

// The engine contract contains a pseudonymous subject, not a note owner UUID.
// Admit valid notes-zone requests here; the final notes API independently enforces
// the verified login UUID against owner_id in the same database statement.
// Announcement privileges still require an operator-managed binding and role.
export function createZoneAuthorizer({store = createResourceStore()} = {}) {
  const authorizeStoredResource = createResourceAuthorizer({store});
  return async request => {
    const resource = resourceIdForRequest(request);
    if (resource === RESOURCE_IDS.notes) return true;
    if (resource === RESOURCE_IDS.instructorAnnouncements) return authorizeStoredResource(request);
    return false;
  };
}
