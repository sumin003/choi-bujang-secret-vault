import { handleNotes } from '../notes.js';
export default async function handler(req,res) {
  const match=/^\/api\/notes\/([^/?]+)$/.exec(req.url ?? '');
  if (!match) return res.status(400).json({error:'INVALID_ROUTE'});
  return handleNotes(req,res,match[1]);
}
