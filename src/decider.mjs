import { RESOURCE_IDS, resourceIdForRequest } from './resources.mjs';
import { createResourceAuthorizer } from './resource-access.mjs';
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
  if (resource === RESOURCE_IDS.instructorAnnouncements) return true;
  if (resource !== RESOURCE_IDS.notes) return false;
  if(request.service !== 'notes') return false;
  // The engine uses /notes; the application uses /api/notes. Both describe the same five routes.
  const collection = request.path === '/notes' || request.path === '/api/notes';
  const single = /^\/(?:api\/)?notes\/[A-Za-z0-9-]{1,128}$/.test(request.path);
  const prefix = request.path.startsWith('/api/') ? '/api/notes' : '/notes';
  if(collection) return ['GET','POST'].includes(request.method) && request.route === request.method+' '+prefix;
  return single && ['GET','PUT','DELETE'].includes(request.method)
    && request.route === request.method+' '+prefix+'/:id';
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
export function createBaseDecider({now=()=>Date.now(), authorizeResource=createResourceAuthorizer()}={}) {
  return async request => {
    if (request?.deviceRegistered !== true) {
      return {schema:'aleph.decision.v1',requestId:request?.requestId,decision:'deny',
        reasonCode:'device_not_registered',ruleIds:['device_registered']};
    }
    if (!normalRequest(request, now())) return starterDeny(request);
    let authorized = false;
    try { authorized = await authorizeResource(request) === true; } catch { /* Fail closed without logging credentials. */ }
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
