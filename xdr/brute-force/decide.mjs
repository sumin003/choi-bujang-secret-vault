const PATTERNS = Object.freeze([
  {
    "name": "같은 출발 주소의 짧은 시간 로그인 실패 연속",
    "condition": "경보의 시각·data.srcip·rule.description과 제공되는 실패 집계에서 같은 출발 주소의 로그인 실패가 짧은 시간에 반복되는지 확인한다. 규칙 수준만으로 이 패턴을 확정하지 않는다.",
    "evidence": "MITRE ATT&CK T1110은 반복적·체계적인 비밀번호 추측을 설명하고 인증 실패의 반복과 시간대 연관 분석을 탐지 근거로 제시한다.",
    "source": "https://attack.mitre.org/techniques/T1110/"
  },
  {
    "name": "여러 계정에 같은 비밀번호 대입",
    "condition": "경보 설명에 여러 계정을 대상으로 동일한 비밀번호를 반복 대입했다는 근거가 있는지 확인한다. 계정 수나 같은 주소만으로 동일 비밀번호 사용을 추정하지 않으며 실제 비밀번호는 읽거나 저장하지 않는다.",
    "evidence": "MITRE ATT&CK T1110.003 Password Spraying은 한 개 또는 소수의 비밀번호를 여러 계정에 시도하는 무차별 대입 형태이다.",
    "source": "https://attack.mitre.org/techniques/T1110/003/"
  }
].map(pattern => Object.freeze(pattern)));

// Local learning scores, not MITRE-defined thresholds or statistical probabilities.
// A single aggregate alert is evaluated; no cross-alert state or credentials are used.
export function decide(alert) {
  const description = typeof alert?.rule?.description === 'string'
    ? alert.rule.description.slice(0,4096) : '';
  const source = typeof alert?.data?.srcip === 'string' && alert.data.srcip.length > 0;
  const rawCount = alert?.data?.count;
  const count = typeof rawCount === 'number' && Number.isFinite(rawCount) && rawCount >= 0
    ? rawCount : typeof rawCount === 'string' && /^\d{1,9}$/.test(rawCount)
      ? Number(rawCount) : 0;
  const describedCounts = [...description.matchAll(/(?:실패\s*(\d+)\s*건|(\d+)\s*건[^.]*실패)/g)]
    .map(match => Number(match[1] ?? match[2]));
  const failures = Math.max(count, 0, ...describedCounts);
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const failureSignal = /실패/.test(description);
  const multipleAccounts = /여러\s*계정|서로\s*다른\s*계정|계정\s*(?:[2-9]|\d{2,})\s*개|계정\s*이름을\s*바꿔/.test(description)
    || (typeof alert?.data?.accounts === 'string'
      && new Set(alert.data.accounts.slice(0,4096).split(',').map(x=>x.trim()).filter(Boolean)).size > 1);
  const samePassword = /(?:같은|동일한?)\s*비밀번호/.test(description);
  const attemptSignal = /실패|대입|연속으로\s*넣|시도/.test(description);
  let confidence = 0;
  let reason = '패턴 일치 없음';

  if (multipleAccounts && samePassword && attemptSignal) {
    confidence = source ? 0.94 : 0.8;
    reason = PATTERNS[1].name;
  } else if (failureSignal) {
    confidence = failures >= 2 ? 0.5 : 0.2;
    if (failures >= 15) confidence += 0.24;
    if (failures >= 40) confidence += 0.04;
    if (source && failures >= 2) confidence += 0.03;
    if (level >= 10 && failures >= 15) confidence += 0.1;
    const shortWindow = /(?:[1-3])\s*분\s*(?:안|동안)/.test(description);
    const repeated = /같은\s*주소|한\s*주소|연속|이어|쌓|간격|글자씩/.test(description);
    if (shortWindow && failures >= 2) confidence += 0.04;
    if (repeated && failures >= 2) confidence += 0.03;
    // Few failures followed by success remain ambiguous; success alone is not an attack.
    if (failures < 15) confidence = Math.min(confidence, 0.79);
    reason = PATTERNS[0].name;
  }
  confidence = Math.round(Math.max(0,Math.min(1,confidence))*100)/100;
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}
