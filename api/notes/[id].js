import { handleNotes } from '../notes.js';
export default async function handler(req, res) {
  return handleNotes(req, res, req.query?.id);
}
