// Isolated local practice only. Never used to authorize production users.
import { createResourceAuthorizer } from '../src/resource-access.mjs';
export const fixtureNoteId = '11111111-1111-4111-8111-111111111111';
const fixtureUserId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const fixtureAuthorize = createResourceAuthorizer({store:async(table,p)=>{
  if (table==='learning_resource_subjects') {
    return p.class_id==='eq.class_fixture' && p.project_id==='eq.project_fixture'
      && p.subject_id==='eq.learner_fixture'
      ? [{user_id:fixtureUserId,identity_kind:'student'}] : [];
  }
  if (table==='learning_notes') return p.note_id==='eq.'+fixtureNoteId
    && p.owner_id==='eq.'+fixtureUserId ? [{owner_id:fixtureUserId}] : [];
  return [];
}});
