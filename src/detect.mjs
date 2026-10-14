// Only engine-validated practice events described in docs/DETECT_EVENTS.md.
// Parsing is not authentication: the caller must establish the event's origin.
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const DECISIONS = new Set(['allow', 'deny', 'step_up']);
const DEVICE = /^[0-9a-f]{16}$/;
const SIGNAL_SOURCES = new Set(['judge_fixture', 'none']);
const NETWORKS = new Set(['usual', 'unusual', 'unknown']);
const READ_WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;
const SUBJECT = /^[A-Za-z0-9_.:-]{1,128}$/;
const PRIVATE_VALUE = /^(?:sb_secret_|gh[pousr]_|github_pat_)|^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// Copy only the documented scalar metadata, never the entire input or identity.
// Optional device/verdict metadata is accepted only at the documented top-level
// fields. Never infer missing values from headers, tokens, names or note content.
export function readDetectionEvents(events) {
  try {
    if (!Array.isArray(events)) throw new TypeError();
    const safe = [];
    for (const event of events) {
      if (!record(event) || !['at', 'method', 'identity'].every(key => Object.hasOwn(event, key)))
        throw new TypeError();
      const at = event.at, method = event.method, identity = event.identity;
      if (!record(identity) || !Object.hasOwn(identity, 'sub')) throw new TypeError();
      const sub = identity.sub;
      if (typeof sub !== 'string' || !SUBJECT.test(sub) || PRIVATE_VALUE.test(sub)
        || typeof method !== 'string' || !METHODS.has(method)
        || typeof at !== 'string' || !ISO_TIME.test(at)) throw new TypeError();
      const time = Date.parse(at);
      if (!Number.isFinite(time) || new Date(time).toISOString().slice(0, 19) !== at.slice(0, 19))
        throw new TypeError();
      const selected = { at, method, identity: { sub } };
      if (Object.hasOwn(event, 'deviceId')) {
        const deviceId = event.deviceId;
        if (typeof deviceId !== 'string' || !DEVICE.test(deviceId)) throw new TypeError();
        selected.deviceId = deviceId;
      }
      if (Object.hasOwn(event, 'deviceRegistered')) {
        const deviceRegistered = event.deviceRegistered;
        if (typeof deviceRegistered !== 'boolean') throw new TypeError();
        selected.deviceRegistered = deviceRegistered;
      }
      if (Object.hasOwn(event, 'decision')) {
        const decision = event.decision;
        if (typeof decision !== 'string' || !DECISIONS.has(decision)) throw new TypeError();
        selected.decision = decision;
      }
      if (Object.hasOwn(event, 'signals')) {
        const signals = event.signals;
        if (!record(signals)) throw new TypeError();
        const selectedSignals = {};
        if (Object.hasOwn(signals, 'source')) {
          const source = signals.source;
          if (typeof source !== 'string' || !SIGNAL_SOURCES.has(source)) throw new TypeError();
          selectedSignals.source = source;
        }
        if (Object.hasOwn(signals, 'network')) {
          const network = signals.network;
          if (typeof network !== 'string' || !NETWORKS.has(network)) throw new TypeError();
          selectedSignals.network = network;
        }
        // Region is intentionally neither accessed nor copied. Missing signal
        // evidence stays missing; it is never defaulted to a usual network.
        if (Object.keys(selectedSignals).length) selected.signals = selectedSignals;
      }
      safe.push(selected);
    }
    return safe;
  } catch {
    // Fixed error only; an accessor or malformed value may contain a secret.
    throw new TypeError('invalid_detection_events');
  }
}

function exceedsReadLimit(times) {
  times.sort((a, b) => a - b);
  let first = 0;
  for (let last = 0; last < times.length; last++) {
    while (times[last] - times[first] > READ_WINDOW_MS) first++;
    if (last - first + 1 > READ_LIMIT) return true;
  }
  return false;
}

export function detect(events) {
  const selected = readDetectionEvents(events);
  const readsBySubject = new Map();
  const confirmedDevicesBySubject = new Map();
  for (const event of selected) {
    // Both facts must occur on the same user's unusual-network reads. These
    // practice labels are not proof of a real network or event provenance.
    if (event.method !== 'GET' || event.signals?.source !== 'judge_fixture'
      || event.signals.network !== 'unusual') continue;
    const sub = event.identity.sub;
    const time = Date.parse(event.at);
    if (!readsBySubject.has(sub)) readsBySubject.set(sub, []);
    readsBySubject.get(sub).push(time);
    if (event.deviceId !== undefined && event.deviceRegistered === true) {
      if (!confirmedDevicesBySubject.has(sub)) confirmedDevicesBySubject.set(sub, new Map());
      const devices = confirmedDevicesBySubject.get(sub);
      if (!devices.has(event.deviceId)) devices.set(event.deviceId, []);
      devices.get(event.deviceId).push(time);
    }
  }
  // A single device must independently satisfy the rule. Never revoke a whole
  // subject, combine devices, or pick an unrelated normal device for a burst.
  for (const [subject, devices] of confirmedDevicesBySubject) {
    for (const [deviceId, times] of devices) {
      if (exceedsReadLimit(times)) {
        // Separate detection result only; no API calls or permission changes.
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId };
      }
    }
  }
  for (const [subject, times] of readsBySubject) {
    if (exceedsReadLimit(times)) return { action: 'alert', reasonCode: 'burst_read', subject };
  }
  return { action: 'observe' };
}
