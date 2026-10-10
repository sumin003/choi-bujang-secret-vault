import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };
let verifyLogin;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export default async function handler(req, res) {
  return handleNotes(req, res, null);
}

export async function handleNotes(req, res, id) {
  res.setHeader('Cache-Control', 'no-store');
  const allowed = id === null ? ['GET', 'POST'] : ['GET', 'PUT', 'DELETE'];
  if (!allowed.includes(req.method)) {
    res.setHeader('Allow', allowed.join(', '));
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const authorization = req.headers?.authorization;
  if (typeof authorization !== 'string') return res.status(401).json({ error: 'LOGIN_REQUIRED' });
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  let identity;
  try {
    verifyLogin ??= createLoginVerifier({ config, supabaseSecretKey: key });
    identity = await verifyLogin(authorization);
    if (!identity) return res.status(401).json({ error: 'LOGIN_REQUIRED' });
  } catch {
    return res.status(401).json({ error: 'LOGIN_REQUIRED' });
  }
  if (id !== null && (typeof id !== 'string' || !UUID.test(id))) {
    return res.status(400).json({ error: 'INVALID_ID' });
  }
  let input;
  if (req.method === 'POST' || req.method === 'PUT') {
    if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] ?? '')) {
      return res.status(415).json({ error: 'JSON_REQUIRED' });
    }
    try { input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; } catch {}
    if (!input || typeof input !== 'object' || Array.isArray(input)
        || typeof input.title !== 'string' || !input.title.trim() || input.title.length > 200
        || typeof input.body !== 'string' || !input.body.trim() || input.body.length > 10000
        || (req.method === 'POST' && input.id !== undefined
          && (typeof input.id !== 'string' || !UUID.test(input.id)))) {
      return res.status(400).json({ error: 'INVALID_NOTE' });
    }
  }
  try {
    const base = new URL(url);
    if (base.protocol !== 'https:' || base.username || base.password) throw new Error();
    const endpoint = new URL('/rest/v1/learning_notes', base);
    const params = new URLSearchParams({ select: 'id:note_id,title,body:content,owner_id' });
    if (id !== null) params.set('note_id', 'eq.' + id);
    // Apply ownership in the same database statement as reads, updates and deletes.
    if (req.method !== 'POST') params.set('owner_id', 'eq.' + identity.userId);
    if (req.method === 'GET' && id === null) {
      params.set('order', 'created_at.asc,id.asc');
    }
    endpoint.search = params;
    const headers = { apikey: key, Accept: 'application/json', Prefer: 'return=representation' };
    let payload;
    let method = req.method;
    if (method === 'POST') {
      payload = { note_id: input.id ?? randomUUID(), title: input.title, content: input.body,
        owner_id: identity.userId };
    } else if (method === 'PUT') {
      method = 'PATCH';
      // Ignore browser-supplied owner_id, userId and role.
      payload = { title: input.title, content: input.body, owner_id: identity.userId };
    }
    if (payload) headers['Content-Type'] = 'application/json';
    const response = await fetch(endpoint, {
      method, headers, body: payload ? JSON.stringify(payload) : undefined,
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
    });
    if (response.status === 409) return res.status(409).json({ error: 'ID_CONFLICT' });
    if (!response.ok) throw new Error();
    const rows = await response.json();
    if (!Array.isArray(rows)) throw new Error();
    if (rows.some(row => row.owner_id !== identity.userId)) throw new Error();
    if (id !== null && rows.length === 0) return res.status(404).json({ error: 'NOTE_NOT_FOUND' });
    if (req.method === 'DELETE') return res.status(204).end();
    const notes = rows.map(row => {
      if (!UUID.test(row.id ?? '') || typeof row.title !== 'string' || typeof row.body !== 'string') throw new Error();
      return { id: row.id, title: row.title, body: row.body };
    });
    if (req.method === 'POST') {
      if (notes.length !== 1) throw new Error();
      return res.status(201).json({ id: notes[0].id });
    }
    return res.status(200).json(id === null ? notes : notes[0]);
  } catch {
    return res.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
