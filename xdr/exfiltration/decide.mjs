const PATTERNS = Object.freeze([
  {
    "name": "명령 통로를 통한 비정상 대량·반복 전송",
    "condition": "신뢰 가능한 경보가 기존 명령 통로를 통한 외부 송신을 명시하고, 큰 파일·기준 대비 급증한 양·동일 목적지 반복 전송 등 단서가 함께 있는지 찾는다. 처음 보는 목적지는 보조 신호다. 짧은 자료 이름·작은 상태 확인·읽기 요청만으로 대용량 반출을 추정하지 않으며, 일반 네트워크 전송이나 MITRE 태그만으로 C2 사용을 확정하지 않는다.",
    "evidence": "MITRE ATT&CK T1041은 기존 명령·제어 통로와 같은 프로토콜을 이용해 수집한 데이터를 외부로 유출하는 기법을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1041/"
    ]
  },
  {
    "name": "낯선 목적지·비정상 경로의 대량 반출",
    "condition": "자료가 외부로 송신되었다는 경보와 처음 보는 목적지, 대용량·다수 자료·반복 전송·평소 쓰지 않던 통신 경로 등 서로 다른 단서를 결합한다. 수치가 있으면 해당 필드의 단위와 집계 범위를 확인하고, 평소 대비 기준이 없으면 임의의 정상 전송량을 만들지 않는다. 기존 C2와 다른 프로토콜 사용이 확인될 때 T1048로 분류한다. 포트 번호만으로 프로토콜을 단정하지 않으며 정상 동기화·승인 백업·작은 단발 전송과 구분한다.",
    "evidence": "MITRE ATT&CK T1048은 기존 명령·제어 통로와 다른 프로토콜로 데이터를 유출하는 기법이며 목적지·전송 행위·통신 경로의 근거를 함께 확인해야 한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1048/"
    ]
  },
  {
    "name": "업무 시간 밖 압축 자료의 외부 반출",
    "condition": "압축 파일의 실제 외부 송신과 신뢰 가능한 업무 시간 밖 표시가 함께 있고, 낯선 목적지·복수 목적지·연속 송신 같은 보조 단서가 있는지 찾는다. 업무 시간표·시간대가 없으면 임의 계산하지 않는다. 압축 생성이나 파일 열기만 수행, 아직 전송 없음, 실패한 전송, 승인된 야간 백업을 명확한 반출과 구분한다. 압축 파일 내용은 읽지 않으며 T1041 또는 T1048 여부는 별도 통신 경로 근거에 따라 결정한다.",
    "evidence": "MITRE ATT&CK T1560.001은 유출 전에 도구로 자료를 압축하는 준비 행위를 설명하며 실제 반출 경로는 T1041·T1048과 구분해 확인한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1560/001/",
      "https://attack.mitre.org/techniques/T1041/",
      "https://attack.mitre.org/techniques/T1048/"
    ]
  }
].map(Object.freeze));

// Standalone metadata classifier: no imports, I/O, network, clock or shared state.
const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';
const number = value => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value
  : typeof value === 'string' && /^\d{1,15}$/.test(value) && Number.isSafeInteger(Number(value)) ? Number(value) : null;
// Absolute learning thresholds, not an invented per-user normal traffic baseline.
const LARGE_BYTES = 50_000_000;
const MANY_FILES = 100;
const REPEAT_COUNT = 3;
function result(confidence, reason) {
  return {action:confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason};
}

export function decide(alert) {
  try {
    const description = text(alert?.rule?.description);
    const rawLevel = alert?.rule?.level;
    const level = Number.isInteger(rawLevel) && rawLevel >= 0 && rawLevel <= 16 ? rawLevel : 0;
    const bytes = number(alert?.data?.bytes), files = number(alert?.data?.files), count = number(alert?.data?.count);
    const relevant = /전송|나갔|올라갔|송신|목적지|압축|자료\s*이름|파일\s*수|upload|transfer|archive|destination/i.test(description);
    const deniedTransfer = /실패|취소|전송(?:은|이)?\s*(?:아직\s*)?없|failed|cancelled|no\s+(?:outbound\s+)?transfer/i.test(description);
    const outbound = !deniedTransfer && /나갔|올라갔|전송|외부.*복사|uploaded|sent|transfer|exfiltrat/i.test(description);
    const unfamiliar = /처음\s*보는\s*(?:목적지|주소)|목적지(?:는|가)?\s*처음|평소와\s*다른\s*주소|unfamiliar\s+(?:destination|address)/i.test(description);
    const offHours = /(?:수업|업무)\s*시간\s*밖|outside\s+(?:business|work|class)\s+hours/i.test(description);
    const archive = /압축\s*파일|\barchive\b|\bzip\b/i.test(description);
    const c2 = /명령\s*(?:통로|제어)|\bc2\b|command.and.control/i.test(description);
    const unusualRoute = /평소에\s*쓰지\s*않던\s*포트|비정상\s*(?:경로|프로토콜)|unusual\s+(?:port|protocol)/i.test(description);
    const repeated = (count !== null && count >= REPEAT_COUNT)
      || /반복|연속|repeated/i.test(description);
    const multipleDestinations = /목적지\s*(?:두|여러|[2-9])\s*곳|multiple\s+destinations/i.test(description);
    const large = (bytes !== null && bytes >= LARGE_BYTES)
      || /대용량|큰\s*파일(?!은?\s*아니)|large\s+(?:file|transfer)/i.test(description);
    const many = (files !== null && files >= MANY_FILES);
    const fullExport = /자료실\s*전체.*외부.*복사|entire.*(?:vault|repository).*external/i.test(description);
    const shortWindow = /짧은\s*시간|\d+\s*분\s*안|short\s+(?:time|window)/i.test(description);
    const explicitSmall = /작은\s*파일|큰\s*파일(?:은|이)?\s*아니|small\s+file|not\s+a\s+large\s+file/i.test(description);
    const approved = /승인된\s*(?:야간\s*)?(?:백업|전송)|approved\s+(?:backup|transfer)/i.test(description);
    const names = [];
    if (outbound && c2 && large && !explicitSmall && (unfamiliar || repeated)) names.push(PATTERNS[0].name);
    if (outbound && !explicitSmall && (
      (unfamiliar && (large || many))
      || (large && repeated)
      || (unusualRoute && repeated && (large || many))
      || (offHours && repeated && large)
      || (fullExport && shortWindow && (large || many)))) names.push(PATTERNS[1].name);
    if (outbound && archive && offHours && (unfamiliar || multipleDestinations || repeated))
      names.push(PATTERNS[2].name);
    // Do not infer a C2/protocol label from an IP address, port, bytes or ATT&CK tag.
    if (names.length) return result(approved ? 0.6 : level >= 10 ? 0.94 : 0.78, names.join(' · '));
    if (level >= 5 && relevant) {
      const name = c2 ? PATTERNS[0].name : archive ? PATTERNS[2].name : PATTERNS[1].name;
      return result(0.6, name + ' · 단서 부족');
    }
    return result(0.1, '패턴 일치 없음');
  } catch {
    return result(0, '패턴 일치 없음');
  }
}
