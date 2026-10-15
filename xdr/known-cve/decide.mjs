const PATTERNS = Object.freeze([
  {
    "name": "요청 머리글의 JNDI 원격 조회 형태",
    "condition": "요청 머리글 값(이 가상 경보에서는 data.useragent)에 jndi 조회 지시와 LDAP 등 원격 대상 참조가 결합된 형태가 있는지 문자열로만 확인한다. 일반 브라우저 이름, jndi라는 단어 하나, 경보 수준만으로는 일치시키지 않는다.",
    "evidence": "Apache의 CVE-2021-44228 설명은 로그 메시지·매개변수의 JNDI가 공격자 제어 LDAP 등 외부 대상을 참조하는 문제를 설명하고, 공식 log4j-scan 문서는 HTTP 머리글 점검을 명시하며 T1190은 공개 앱의 약점 악용을 분류한다.",
    "sources": [
      "https://logging.apache.org/security.html#CVE-2021-44228",
      "https://github.com/fullhunt/log4j-scan",
      "https://attack.mitre.org/techniques/T1190/"
    ]
  },
  {
    "name": "요청 인자의 JNDI 원격 조회 형태",
    "condition": "요청 URL의 질의 인자 또는 명시적으로 제공된 요청 인자(이 가상 경보에서는 data.url)에 jndi 조회 지시와 원격 대상 참조가 결합되어 있는지 확인한다. CVE 번호·문서 제목·검색어만 있는 정상 요청과 구분하며 값이 없으면 임의의 요청 본문을 추정하지 않는다.",
    "evidence": "Apache의 CVE-2021-44228 설명은 외부 입력이 로그 메시지나 매개변수에 들어올 때의 JNDI 위험을 명시하고, 공식 log4j-scan 문서는 GET·POST 인자 점검을 설명하며 T1190은 공개 앱 취약점 악용을 다룬다.",
    "sources": [
      "https://logging.apache.org/security.html#CVE-2021-44228",
      "https://github.com/fullhunt/log4j-scan",
      "https://attack.mitre.org/techniques/T1190/"
    ]
  },
  {
    "name": "알려진 취약점 점검 도구의 보조 흔적",
    "condition": "User-Agent 또는 Wazuh 규칙 설명에 공식 도구 자료로 확인 가능한 Log4j 취약점 점검 식별자가 있는지 확인한다. log4j-scan 같은 도구 표식은 위조 가능하고 정당한 점검에도 쓰이므로 단독으로 악용·악용 성공·차단을 확정하지 않는다. 일반 curl·브라우저 문자열이나 CVE 번호만으로는 점검 도구라고 판단하지 않는다.",
    "evidence": "FullHunt의 공식 log4j-scan 저장소는 CVE-2021-44228 탐지용 점검 도구임을 설명하며 MITRE T1595.002는 취약점 점검을 별도로 분류하므로 도구 흔적만으로 T1190 악용을 확정하지 않는다.",
    "sources": [
      "https://github.com/fullhunt/log4j-scan",
      "https://attack.mitre.org/techniques/T1595/002/",
      "https://attack.mitre.org/techniques/T1190/"
    ]
  }
].map(pattern => Object.freeze(pattern)));

// Learning scores describe pattern clarity, not proof of successful exploitation.
// Inspect bounded strings only; keep this module stateless and self-contained.
const MAX_TEXT = 8192;
const text = value => typeof value === 'string' ? value.slice(0, MAX_TEXT) : '';
function decoded(value) {
  let result = text(value);
  for (let i = 0; i < 2; i++) {
    try {
      const next = decodeURIComponent(result.replace(/\+/g, ' ')).slice(0, MAX_TEXT);
      if (next === result) break;
      result = next;
    } catch { break; }
  }
  return result;
}
function shape(value) {
  return /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns):\/\/[^{}\s]{1,1024}\s*\}/i.test(value);
}
function fragment(value) {
  return /\$\{\s*jndi\s*:/i.test(value) && !shape(value);
}
function result(confidence, reason) {
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
}

export function decide(alert) {
  const data = alert?.data;
  const rule = alert?.rule;
  const description = text(rule?.description);
  const level = Number.isInteger(rule?.level) && rule.level >= 0 && rule.level <= 16 ? rule.level : 0;
  const headers = data?.headers;
  // Never enumerate an arbitrary alert or inspect Authorization/password fields.
  const headerFields = [data?.useragent];
  if (headers && typeof headers === 'object' && !Array.isArray(headers)) {
    for (const key of ['User-Agent','user-agent','Referer','referer','X-Api-Version','x-api-version'])
      headerFields.push(headers[key]);
  }
  const header = headerFields.map(decoded).join(' ').slice(0, MAX_TEXT);
  const parameters = [data?.url, data?.query, data?.params].map(decoded).join(' ').slice(0, MAX_TEXT);
  const names = [];
  const headerMatch = shape(header), parameterMatch = shape(parameters);
  if (headerMatch) names.push(PATTERNS[0].name);
  if (parameterMatch) names.push(PATTERNS[1].name);
  // An explicit tool name is a weak, spoofable identifier, not a default UA claim.
  const scanner = /\blog4j[-_ ]scan(?:ner)?\b/i.test(header + ' ' + description);
  if (scanner) names.push(PATTERNS[2].name);
  const educational = /교육|학습\s*(?:자료|예시)|수업|문서\s*(?:예시|내용)|코드\s*예시|이스케이프/i.test(description);
  if (headerMatch || parameterMatch) {
    const confidence = educational ? 0.68 : level >= 10 ? 0.96 : level >= 5 ? 0.88 : 0.78;
    return result(confidence, names.join(' · '));
  }
  if (scanner) return result(0.65, PATTERNS[2].name);
  if (fragment(header) || fragment(parameters)) {
    const name = fragment(header) ? PATTERNS[0].name : PATTERNS[1].name;
    return result(0.62, name + ' · 불완전한 구문');
  }
  // Moderate CVE-related Wazuh warnings are uncertain leads, never block evidence.
  // No payload is inferred and no full-pattern match is asserted for these leads.
  const context = /CVE-2021-44228|log4j|log4shell|jndi|lookup|취약점|원격\s*조회|조회\s*(?:형태|구문)|점검\s*도구|라이브러리/i
    .test(description + ' ' + header + ' ' + parameters);
  if (level >= 5 && context) {
    const candidate = /점검\s*도구/.test(description) ? PATTERNS[2].name
      : header.trim() ? PATTERNS[0].name : PATTERNS[1].name;
    return result(0.52, candidate + ' · 단서 부족');
  }
  return result(0.1, '패턴 일치 없음');
}
