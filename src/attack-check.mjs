import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from './decider.mjs';

// Record only what was actually requested/returned, never keys, tokens or response bodies.
export async function runAttackChecks(config) {
  if (config.step === 1) return legacyStageOne(config);
  if (!Number.isInteger(config.step) || config.step < 6 || config.step > 12)
    throw new Error('이 단계의 자기 점검을 구현해 주세요.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash || app.pathname !== '/' || app.port || !app.hostname.endsWith('.vercel.app'))
    throw new Error('자료실의 HTTPS 배포 주소를 확인해 주세요.');
  const { normal, suspicious } = fixtureRequests();
  const evaluate = decide;
  const result = await evaluate(normal);
  const attempts = [{ attackId: 'registered_device_local', expected: '등록 기기의 정상 가상 요청은 allow',
    observed: 'not_run' }];
  if (config.step >= 7) {
    for (const [attackId, input, expected] of [
      ['composite_event_local', suspicious, '복합 이상 가상 사건은 step_up'],
      ['reconfirmed_event_local', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, '가상 추가 확인 후 allow'],
    ]) {
      const output = await evaluate(input);
      attempts.push({ attackId, expected, observed: 'not_run' });
    }
  }
  if (config.step >= 8) {
    for (const [attackId, input, expected] of [
      ['note_collection_local', {...normal,path:'/notes',route:'GET /notes'}, '가상 메모 전체 목록 경로는 deny'],
      ['notice_write_local', {...normal,subjectId:'teacher_fixture',service:'instructor_announcements',method:'PUT',
        path:'/announcements/notice-demo',route:'PUT /announcements/:id'}, '역할 없는 엔진 계약에서 공지 쓰기는 deny'],
      ['foreign_owner_local', {...normal,subjectId:'other_learner_fixture'}, '같은 가상 메모를 다른 사용자가 요청하면 deny'],
      ['foreign_zone_local', {...normal,service:'other_zone',path:'/other-zone/item',route:'GET /other-zone/:id'}, '가상 다른 구역 요청은 deny'],
      ['student_notice_local', {...normal,service:'instructor_announcements',method:'PUT',
        path:'/api/announcements/22222222-2222-4222-8222-222222222222',route:'PUT /api/announcements/:id'}, '가상 학생 공지 수정은 deny'],
    ]) {
      const output = await evaluate(input);
      attempts.push({attackId,expected,observed:'not_run'});
    }
  }
  // Keep server/restore test helpers outside the restricted bundle import graph.
  // They remain available through their existing, separate local test commands.
  if (config.step >= 9) attempts.push({attackId:'detection_proposal_local',
    expected:'별도 탐지 시험에서 정상 유지와 복합 의심 회수 제안 확인', observed:'not_run'});
  if (config.step >= 10) {
    attempts.push({attackId:'restored_note_access_local',
      expected:'복원 뒤 본인 자료 허용과 타인 자료 거부 확인', observed:'not_run'});
    attempts.push({attackId:'restored_policy_access_local',
      expected:'정책 복원 뒤 정상·금지 요청 재시험', observed:'not_run'});
  }
  if (config.step >= 11) attempts.push({attackId:'unregistered_browser_local',
    expected:'별도 서버 시험에서 미등록 브라우저 자료 접근 거부', observed:'not_run'});
  try {
    const requestUrl = new URL('/api/notes', app).href;
    const response = await fetch(requestUrl, { method: 'GET', redirect: 'error',
      signal: AbortSignal.timeout(10000), cache: 'no-store', headers: { Accept: 'application/json' } });
    // Do not report an execution proxy/protection page as the notes API response.
    let apiResponse = false;
    if ((response.headers.get('content-type') ?? '').includes('application/json')) {
      const data = await response.json().catch(() => null);
      apiResponse = data !== null && (response.headers.has('x-vercel-id')
        || ([401, 403].includes(response.status) && data?.error === 'LOGIN_REQUIRED'
          && Object.keys(data).every(key => ['error', 'reason'].includes(key))));
    }
    if (response.url && response.url !== requestUrl) apiResponse = false;
    attempts.push({ attackId: 'anonymous_note_read', expected: '미로그인 목록 요청은 HTTP 401 또는 403 및 JSON 오류',
      observed: apiResponse ? 'HTTP ' + response.status : 'not_run' });
  } catch {
    attempts.push({ attackId: 'anonymous_note_read', expected: '미로그인 목록 요청은 HTTP 401 또는 403 및 JSON 오류',
      observed: 'not_run' });
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
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(10000),
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
