import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { checkDetection } from '../scripts/detect-test.mjs';
import { checkDetection as checkDeviceDetection } from '../scripts/detect-device-test.mjs';
import { runRestoreAccessChecks } from '../scripts/restore-access-check.mjs';
import { enforceApprovedDevice } from './device-approval.mjs';

// Record only what was actually requested/returned, never keys, tokens or response bodies.
export async function runAttackChecks(config) {
  if (config.step === 1) return legacyStageOne(config);
  if (!Number.isInteger(config.step) || config.step < 6 || config.step > 11)
    throw new Error('이 단계의 자기 점검을 구현해 주세요.');
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash || app.pathname !== '/')
    throw new Error('자료실의 HTTPS 배포 주소를 확인해 주세요.');
  const { normal, suspicious } = fixtureRequests();
  const evaluate = decide;
  const result = await evaluate(normal);
  const attempts = [{ attackId: 'registered_device_local', expected: '등록 기기의 정상 가상 요청은 allow',
    observed: '로컬 가상 판정: ' + result.decision + ' · ' + result.reasonCode + ' (실제 접속·심판 판정 아님)' }];
  if (config.step >= 7) {
    for (const [attackId, input, expected] of [
      ['composite_event_local', suspicious, '복합 이상 가상 사건은 step_up'],
      ['reconfirmed_event_local', { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }, '가상 추가 확인 후 allow'],
    ]) {
      const output = await evaluate(input);
      attempts.push({ attackId, expected, observed: '로컬 가상 판정: ' + output.decision + ' · ' + output.reasonCode + ' (실제 재로그인·자료 차단 실측 아님)' });
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
      attempts.push({attackId,expected,observed:'로컬 가상 판정: '+output.decision+' · '+output.reasonCode+' (실배포 API·운영 권한 등록 검증 아님)'});
    }
  }
  if (config.step >= 9) {
    const checks = await checkDetection(detect);
    const passed = checks.filter(item => item.passed).length;
    const deviceChecks = await checkDeviceDetection(detect);
    const devicesPassed = deviceChecks.filter(item => item.passed).length;
    attempts.push({attackId:'detection_proposal_local',
      expected:'제공 원본 계약의 대상 선택자·이유가 있는 회수 제안과 정상 유지; 확장 입력은 확인 기기 한 개만 제안',
      observed:'제공 원본 연습 '+passed+'/'+checks.length+' · 확장 기기 연습 '+devicesPassed+'/'+deviceChecks.length+' 통과 (실제 회수·경과 시간·심판 판정 아님)'});
  }
  if (config.step >= 10) {
    const checks = await runRestoreAccessChecks();
    if (!checks.data.aOwnAllowed || !checks.data.bToADenied || !checks.data.bOwnRestoredReadable
      || !checks.policy.aOwnAllowed || !checks.policy.bToADenied || !checks.policy.itemsRestored) {
      throw new Error('복구 뒤 정상·금지 자료 요청 확인에 실패했습니다.');
    }
    attempts.push({attackId:'restored_note_access_local',
      expected:'가상 B 메모 복원 뒤 A 본인 조회 허용·B의 A 자료 거부·B 복원 자료 조회 허용',
      observed:'격리된 합성 사본으로 복원한 뒤 API 확인 통과: A 본인 200 · B→A 404 거부 · B 본인 200 (실제 백업·배포 시험 아님)'});
    attempts.push({attackId:'restored_policy_access_local',
      expected:'시험 정책 복원 뒤 A의 GET/PUT/DELETE 허용·B의 A 메모 GET/PUT/DELETE 거부',
      observed:'격리 시험 정책 복원 뒤 판정기 재호출 통과: A 요청 allow · B 요청 deny/resource_zone (실제 운영 정책 아님)'});
  }
  if (config.step >= 11) {
    const response = { statusCode: 200, body: null,
      setHeader() {},
      status(code) { this.statusCode = code; return this; },
      json(body) { this.body = body; return this; } };
    const allowed = await enforceApprovedDevice({ headers: {} }, response,
      { kind: 'student', userId: '00000000-0000-4000-8000-000000000001' });
    attempts.push({ attackId: 'unregistered_browser_local',
      expected: '브라우저 등록 쿠키가 없으면 자료 없이 JSON 403으로 거부',
      observed: allowed === false && response.statusCode === 403
        && response.body?.error === 'DEVICE_NOT_APPROVED'
        ? '로컬 서버 검사: 등록 쿠키 없는 요청 JSON 403 거부 (실제 배포 승인 시험 아님)'
        : '로컬 서버 검사에서 미등록 브라우저 거부를 확인하지 못함' });
  }
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
