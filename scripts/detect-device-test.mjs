import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';
const deviceId = '0123456789abcdef';

function reads(count, { intervalSeconds = 2, owner = subject, start = START,
  network = 'usual', source = 'judge_fixture', device = deviceId, registered = true } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalSeconds * 1000).toISOString(),
    method: 'GET', identity: { sub: owner },
    signals: { source, network },
    deviceId: device, deviceRegistered: registered,
  }));
}

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '낯선 네트워크 · 10분 안에 120건', events: reads(120,{network:'unusual'}), expected: { action: 'observe' } },
  { name: '낯선 네트워크 · 10분 안에 121건', events: reads(121,{network:'unusual'}), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId } },
  { name: '낯선 네트워크 · 폭주 조회 200건', events: reads(200,{network:'unusual'}), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject, deviceId } },
  { name: '낯선 네트워크 · 서로 다른 사용자 각 100건', events: [...reads(100,{network:'unusual'}),
    ...reads(100, { owner: 'other_fixture',network:'unusual' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 조회 200건', events: reads(200,
    { intervalSeconds: 7,network:'unusual' }), expected: { action: 'observe' } },
  { name: '평소 네트워크 · 다량 조회만 200건', events: reads(200), expected: { action: 'observe' } },
  { name: '낯선 네트워크만 · 조회 30건', events: reads(30,{network:'unusual'}), expected: { action: 'observe' } },
  { name: '지역 차이만 · 평소 네트워크 200건', events: reads(200).map(e=>({...e,
    signals:{...e.signals,region:'other_fixture_region'}})), expected: { action: 'observe' } },
  { name: '네트워크 신호 누락 · 조회 200건', events: reads(200).map(({signals,...e})=>e), expected: { action: 'observe' } },
  { name: '검증된 신호 없음 · 조회 200건', events: reads(200,{source:'none',network:'unusual'}), expected: { action: 'observe' } },
  { name: '복합 의심 · 기기 확인 정보 없음은 알림만',events:reads(121,{network:'unusual'})
    .map(({deviceRegistered,...e})=>e),expected:{action:'alert',reasonCode:'burst_read',subject} },
  { name: '복합 의심 · 미등록 기기는 알림만',events:reads(121,{network:'unusual',registered:false}),
    expected:{action:'alert',reasonCode:'burst_read',subject} },
  { name: '복합 의심 · 두 기기 각 80건은 알림만',events:[...reads(80,{network:'unusual'}),
    ...reads(80,{network:'unusual',device:'fedcba9876543210'})],
    expected:{action:'alert',reasonCode:'burst_read',subject} },
];

// This is a practice contract, not a live engine assertion or judge score.
export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  for (const item of cases) {
    const actual = await detect(item.events);
    const passed = isDeepStrictEqual(actual, item.expected);
    results.push({ name: item.name, passed: Boolean(passed) });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
