import { handleNotes, resolveNoteId } from '../notes.js';
export default async function handler(req,res) {
  const id=resolveNoteId(req);
  if (!id) return res.status(400).json({error:'INVALID_ROUTE'});
  return handleNotes(req,res,id);
}
