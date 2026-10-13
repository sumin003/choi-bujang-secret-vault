// Resource-kind identifiers, distinct from individual note UUIDs.
// These definitions grant no access and do not change existing routes.
export const RESOURCE_IDS = Object.freeze({
  notes: 'notes',
  instructorAnnouncements: 'instructor_announcements',
});

// Only call with the engine-validated request; never trust a client resourceId.
export function resourceIdForRequest(request) {
  if (!request || typeof request.path !== 'string') return null;
  const resources = [
    { service: 'notes', id: RESOURCE_IDS.notes, prefixes: ['/notes', '/api/notes'] },
    { service: 'instructor_announcements', id: RESOURCE_IDS.instructorAnnouncements,
      prefixes: ['/announcements', '/api/announcements'] },
  ];
  const reserved = new Set(['export', 'import', 'search', 'bulk', 'download', 'upload', 'action', 'admin']);
  for (const resource of resources) {
    if (request.service !== resource.service) continue;
    for (const prefix of resource.prefixes) {
      if (request.path === prefix && ['GET', 'POST'].includes(request.method)
        && request.route === request.method + ' ' + prefix) return resource.id;
      const id = request.path.startsWith(prefix + '/') ? request.path.slice(prefix.length + 1) : '';
      if (/^[A-Za-z0-9-]{1,128}$/.test(id) && !reserved.has(id.toLowerCase())
        && ['GET', 'PUT', 'DELETE'].includes(request.method)
        && request.route === request.method + ' ' + prefix + '/:id') return resource.id;
    }
  }
  return null;
}

