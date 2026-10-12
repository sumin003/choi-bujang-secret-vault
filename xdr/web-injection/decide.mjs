const PATTERNS = Object.freeze([
  {
    "name": "요청 인자의 SQL 주입 형태",
    "condition": "요청 인자를 안전하게 문자열로 해석해 SQL 연산·질의 구문과 구문 경계를 바꾸는 기호가 결합되어 있는지 확인한다. 단순 SQL 용어 검색이나 교육용 코드만으로 공격을 확정하지 않으며 경보 설명·수준·같은 주소의 반복 근거를 함께 확인한다.",
    "evidence": "MITRE ATT&CK T1190은 공개 앱에 대한 SQL 주입 사례를 기록하며 CWE-89는 외부 입력이 의도한 SQL 명령 구조를 바꾸는 약점을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1190/",
      "https://cwe.mitre.org/data/definitions/89.html"
    ]
  },
  {
    "name": "요청 인자의 스크립트 주입 형태",
    "condition": "요청 인자의 스크립트 태그와 실행 문맥이 의심되는지 확인한다. HTML 예시·이스케이프된 텍스트·학습 자료와 구분하고, 태그 하나만으로 공격 성공이나 주소 차단을 결정하지 않는다.",
    "evidence": "T1190은 공개 웹 앱의 약점 악용을 다루며 CWE-79는 외부 입력이 웹 페이지에 적절히 중화되지 않아 브라우저 실행 코드로 해석되는 스크립트 주입을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1190/",
      "https://cwe.mitre.org/data/definitions/79.html"
    ]
  },
  {
    "name": "상위 경로 이동 반복",
    "condition": "요청 경로·인자에서 ../ 형태의 상위 경로 이동이 반복되고 허용 디렉터리 밖의 자원을 향하는지 확인한다. 정상 상대 경로 하나와 구분하고 URL 인코딩을 문자열로만 확인하며 파일을 열거나 요청을 보내지 않는다.",
    "evidence": "MITRE ATT&CK T1190은 디렉터리 탐색 취약점 악용 사례를 기록하며 CWE-22는 상위 경로 이동 등을 이용해 제한된 디렉터리 밖에 접근하는 약점을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1190/",
      "https://cwe.mitre.org/data/definitions/22.html"
    ]
  },
  {
    "name": "요청 인자의 명령 주입 형태",
    "condition": "요청 인자에서 명령 구분자와 추가 명령 형태가 결합되었거나 경보에 명령 삽입 형태가 명시되었는지 확인한다. 구분 문자 하나나 교육용 예시만으로 공격을 확정하지 않고 같은 주소의 반복 근거와 높은 경보 수준을 함께 확인하며 입력을 실행하지 않는다.",
    "evidence": "CWE-78은 외부 입력의 특수 요소가 의도한 운영체제 명령 구조를 바꾸는 약점을 설명하며 명령 구분자로 추가 명령이 실행되는 사례를 제시한다.",
    "sources": [
      "https://cwe.mitre.org/data/definitions/78.html"
    ]
  }
].map(pattern => Object.freeze(pattern)));

// These are learning scores, not MITRE thresholds or probabilities of successful exploitation.
// Bounded string inspection only: never execute payloads or send a request.
const MAX_TEXT = 8192;
const REPEAT_THRESHOLD = 3;
const text = value => typeof value === 'string' ? value.slice(0, MAX_TEXT) : '';
function decode(value) {
  let current = text(value);
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(current.replace(/\+/g, ' ')).slice(0, MAX_TEXT);
      if (next === current) break;
      current = next;
    } catch { break; }
  }
  return current;
}
function sourcePresent(value) {
  if (typeof value !== 'string' || value.length > 45) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return value.split('.').every(n => Number(n) <= 255);
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value);
}

export function decide(alert) {
  const description = text(alert?.rule?.description);
  const input = decode(text(alert?.data?.url) + ' ' + text(alert?.data?.query));
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const rawCount = alert?.data?.count;
  const count = typeof rawCount === 'number' && Number.isSafeInteger(rawCount) && rawCount >= 0
    ? rawCount : typeof rawCount === 'string' && /^\d{1,9}$/.test(rawCount) ? Number(rawCount) : 0;
  const repeated = count >= REPEAT_THRESHOLD && !/반복은\s*없|반복되지\s*않/.test(description);
  const source = sourcePresent(alert?.data?.srcip);
  const educational = /수업|교육|학습\s*(?:자료|예시)|이스케이프|삽입\s*표식은\s*아닙니다/.test(description);
  const matched = [];

  // Fixture doc-* markers describe shapes without carrying executable attack payloads.
  const sqlMarker = /doc-sql-(?:chain|or|select-chain)\b|doc-mixed-marker\b/.test(input);
  const scriptMarker = /doc-script-marker\b|doc-mixed-marker\b/.test(input);
  const traversalMarker = /doc-up-repeat\b/.test(input);
  const commandMarker = /doc-cmd-separator\b/.test(input);
  const sqlShape = /\bunion\s+(?:all\s+)?select\b|;\s*(?:select|insert|update|delete|drop)\b|['"]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^'\r\n]{0,80}'\s*=\s*'[^'\r\n]{0,80}')/i.test(input);
  const scriptShape = /<script(?:\s|>)[^>]{0,512}>?[\s\S]{0,1024}|<[^>]{1,512}\s+on[a-z]+\s*=|(?:javascript|vbscript)\s*:/i.test(input);
  const traversalShape = /(?:\.\.[/\\]){2,}/.test(input);
  // Require a command name after a separator; punctuation alone is insufficient.
  const commandShape = /(?:;|\|\||&&|\|)\s*(?:id|whoami|uname|cat|curl|wget|sh|bash|cmd|powershell)\b/i.test(input);
  const commandDescription = /명령\s*(?:구분자|삽입|주입)/.test(description);
  const sqlDescription = /SQL\s*(?:구문|표식)|데이터베이스\s*조회.*이어\s*붙/.test(description);
  const scriptDescription = /스크립트\s*(?:삽입|표식|표기)/.test(description);
  const traversalDescription = /경로.*(?:거슬러\s*올라|이탈)/.test(description);
  if (sqlMarker || sqlShape || (sqlDescription && !educational)) matched.push(0);
  if (scriptMarker || scriptShape || (scriptDescription && !educational)) matched.push(1);
  if (traversalMarker || traversalShape || (traversalDescription && !educational)) matched.push(2);

  if (commandMarker || commandShape || (commandDescription && !educational)) matched.push(3);

  let confidence = 0;
  let reason = '패턴 일치 없음';
  if (matched.length) {
    reason = matched.map(i => PATTERNS[i].name).join(' · ');
    confidence = educational ? 0.55 : source && repeated && level >= 10 ? 0.96 : 0.74;
  } else if (description && level >= 5 && level <= 16) {
    // An unexplained web alarm needs review; level alone never creates a block candidate.
    confidence = 0.52;
  }
  const action = confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record';
  return { action, confidence, reason };
}
