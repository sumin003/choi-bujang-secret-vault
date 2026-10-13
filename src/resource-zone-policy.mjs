import { RESOURCE_IDS, resourceIdForRequest } from './resources.mjs';

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
    if (collection) return ['GET','POST'].includes(request.method);
    return Object.hasOwn(NOTE_OWNERS,id) && NOTE_OWNERS[id]===request.subjectId
      && ['GET','PUT','DELETE'].includes(request.method);
  }
  if (resource===RESOURCE_IDS.instructorAnnouncements) {
    if (role!=='instructor') return false;
    if (collection) return ['GET','POST'].includes(request.method);
    return Object.hasOwn(NOTICE_OWNERS,id) && NOTICE_OWNERS[id]===request.subjectId
      && ['GET','PUT','DELETE'].includes(request.method);
  }
  return false;
}
