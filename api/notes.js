// Stage 2: intentionally public; authentication is added in a later stage.
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) return res.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  try {
    const base = new URL(url);
    if (base.protocol !== 'https:' || base.username || base.password) throw new Error();
    const endpoint = new URL('/rest/v1/learning_notes', base);
    endpoint.search = new URLSearchParams({
      select: 'id,title,content', id: 'in.(1,2,3,4)', order: 'id.asc', limit: '4',
    });
    const response = await fetch(endpoint, {
      headers: { apikey: key, Accept: 'application/json' },
      redirect: 'error', signal: AbortSignal.timeout(10000), cache: 'no-store',
    });
    if (!response.ok) throw new Error();
    const rows = await response.json();
    if (!Array.isArray(rows) || rows.length !== 4
        || rows.some((row, index) => Number(row.id) !== index + 1
          || typeof row.title !== 'string' || typeof row.content !== 'string')) throw new Error();
    return res.status(200).json({ notes: rows.map(({ id, title, content }) => ({ id, title, content })) });
  } catch {
    // Never forward upstream errors, request headers, environment values or logs.
    return res.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }
}
