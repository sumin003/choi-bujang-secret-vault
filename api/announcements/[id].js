import { handleAnnouncements } from '../announcements.js';
export default async function handler(req,res) {
  const match=/^\/api\/announcements\/([^/?]+)$/.exec(req.url ?? '');
  if (!match) return res.status(400).json({error:'INVALID_ROUTE'});
  return handleAnnouncements(req,res,match[1]);
}
