// Server APIs and the isolated decider use the same ownership policy.
export { createResourceStore, isStoredInstructor, checkVerifiedResource,
  createResourceAuthorizer, createZoneAuthorizer } from './decider.mjs';
