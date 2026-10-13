import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from './decider.mjs';

// Record only what was actually requested/returned, never keys, tokens or response bodies.
export async function runAttackChecks(config) {
  if (config.step === 1) return legacyStageOne(config);
  if (config.step !== 6) throw new Error('이 단계의 자기 점검을 구현해 주세요.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash || app.pathname !== '/')
    throw new Error('자료실의 HTTPS 배포 주소를 확인해 주세요.');
  const { normal } = fixtureRequests();
  const result = await decide(normal);
  const attempts = [{ attackId: 'registered_device_local', expected: '등록 기기의 정상 가상 요청은 allow',
    observed: '로컬 가상 판정: ' + result.decision + ' · ' + result.reasonCode + ' (실제 접속·심판 판정 아님)' }];
  try {
    const response = await fetch(new URL('/api/notes', app), { redirect: 'error',
      signal: AbortSignal.timeout(10000), cache: 'no-store', headers: { Accept: 'application/json' } });
    let jsonError = false;
    if ((response.headers.get('content-type') ?? '').includes('application/json')) {
      try { const data = await response.json(); jsonError = typeof data?.error === 'string' && !Array.isArray(data); } catch {}
    }
    const denied = [401,403].includes(response.status) && jsonError;
    attempts.push({ attackId: 'anonymous_note_read', expected: '미로그인 목록 요청은 HTTP 401 또는 403 및 JSON 오류',
      observed: '직접 GET /api/notes: HTTP ' + response.status + (jsonError ? ' · JSON 오류' : ' · JSON 오류 확인 안 됨')
        + (denied ? ' · 요청 거부 확인' : ' · 조건 미확인; 환경 접근 제한이나 응답 오류를 통과로 기록하지 않음') });
  } catch {
    attempts.push({ attackId: 'anonymous_note_read', expected: '미로그인 목록 요청은 HTTP 401 또는 403 및 JSON 오류',
      observed: '직접 GET /api/notes를 시도했으나 연결·응답 오류로 미확인' });
  }
  // Actual unregistered-device attacks are performed by the judge, not fabricated here.
  return attempts;
}

// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
async function legacyStageOne(config) {
  if (config.step !== 1) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}
