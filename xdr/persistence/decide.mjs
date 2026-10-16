const PATTERNS = Object.freeze([
  {
    "name": "서명 없는 새 서비스 등록·실행 대상 변경",
    "condition": "새 서비스 등록 또는 기존 서비스 실행 파일 변경이 실제로 기록되어 있고, 서명 없음이 명시되거나 평소 허용 목록에 없는 자동 실행 서비스임이 확인되는지 찾는다. 임시 폴더 실행 대상·자동 시작 설정·동일 출발 주소의 반복 등록은 보조 신호로만 결합한다. 서명 미확인, 설명만 변경, 같은 파일의 재시작, 승인된 기존 서비스의 정상 실행은 명확한 악성 등록으로 분류하지 않는다.",
    "evidence": "MITRE ATT&CK T1543은 서비스를 생성하거나 변경해 시작 시 또는 반복 실행으로 지속성을 확보하는 기법을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1543/",
      "https://attack.mitre.org/techniques/T1543/003/"
    ]
  },
  {
    "name": "낯선 예약 작업의 의심 실행 대상",
    "condition": "새롭거나 평소 목록에 없는 예약 작업의 생성·실행 대상 변경을 찾고 임시 폴더 실행 대상, 확인된 비정상 실행 시각 등 독립적인 단서가 함께 있는지 본다. 임의 이름이나 시각 하나만으로 악성을 확정하지 않는다. 기존 업데이트·수업 자료 복사 작업, 승인된 예약 작업, 단순 존재나 서명 미확인만 있는 경우는 구분하며 명확한 공격으로 단정하지 않는다.",
    "evidence": "MITRE ATT&CK T1053은 예약 기능을 악용해 프로그램이나 스크립트를 지정 시각 또는 반복적으로 실행하는 기법을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1053/",
      "https://attack.mitre.org/techniques/T1053/005/"
    ]
  },
  {
    "name": "시작 폴더의 낯선 자동 실행 항목 추가·변경",
    "condition": "시작 폴더나 시작 프로그램 항목에 평소 목록에 없는 실행 파일·바로가기의 추가 또는 실행 대상 변경이 기록되는지 찾는다. 임시 파일을 가리키거나 예약 작업과 동일한 의심 대상을 가리키는 것은 보조 신호다. 목록 읽기만 수행, 정상 승인된 도구, 실행 여부가 불명확한 단일 변경을 명확한 악성 실행과 구분한다. 이 가상 경보의 data.path는 참고 경로이며 실제 파일 존재·서명·실행을 직접 검사한 증거로 취급하지 않는다.",
    "evidence": "MITRE ATT&CK T1547.001은 시작 폴더에 항목을 추가해 로그인 시 프로그램을 자동 실행하는 지속성 기법을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1547/001/"
    ]
  }
].map(Object.freeze));

// Standalone metadata classifier. No imports, I/O, clock, state or code execution.
const MAX_TEXT = 8192;
const text = value => typeof value === 'string' ? value.slice(0, MAX_TEXT) : '';
function result(confidence, reason) {
  return {action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason};
}

export function decide(alert) {
  try {
    const description = text(alert?.rule?.description);
    const path = text(alert?.data?.path);
    const suppliedLevel = alert?.rule?.level;
    const level = Number.isInteger(suppliedLevel) && suppliedLevel >= 0 && suppliedLevel <= 16
      ? suppliedLevel : 0;
    const service = /서비스|\bservice\b/i.test(description);
    const task = /예약\s*작업|예약|scheduled\s+task|\bcron\b/i.test(description);
    const startup = /시작\s*(?:폴더|프로그램|항목)|startup\s*(?:folder|item)|autostart/i.test(description);
    const temporary = /임시\s*(?:폴더|파일)|temporary\s*(?:folder|file)/i.test(description)
      || /(?:^|[\\/])(?:temp|tmp)(?:[\\/]|$)/i.test(path);
    // Unknown/unverified signatures are not evidence of an unsigned executable.
    const unsigned = /서명\s*없는|서명(?:이|은)?\s*없|\bunsigned\b/i.test(description);
    const unfamiliar = /처음\s*보는|평소\s*(?:허용\s*)?목록에\s*없|낯선|\bunfamiliar\b|\bunknown\s+(?:service|task|program)\b/i.test(description);
    const registrationAbsent = /서비스\s*등록(?:은|이)?\s*없|no\s+service\s+(?:registration|created)/i.test(description);
    const registered = !registrationAbsent && /등록|\bregister(?:ed|ing)?\b|\binstall(?:ed)?\b/i.test(description);
    const changedExecutable = /실행\s*파일(?:이|을)?\s*(?:바뀌|변경)|(?:binary|executable)\s*(?:changed|modified)/i.test(description);
    const newService = service && /새\s*서비스|new\s+service/i.test(description);
    const added = /추가|\badded\b|\bcreated\b/i.test(description);
    const outsideHours = /수업\s*시간\s*밖|outside\s+(?:class|business)\s+hours/i.test(description);
    const arbitraryName = /이름(?:이|은)?\s*임의\s*문자열|random(?:ized)?\s+(?:task\s+)?name/i.test(description);
    const persistent = /다시\s*켜도\s*남|자동\s*시작|부팅.*(?:유지|실행)|surviv\w*\s+reboot|auto.?start/i.test(description);
    const countValue = alert?.data?.count;
    const count = typeof countValue === 'number' && Number.isSafeInteger(countValue) ? countValue
      : typeof countValue === 'string' && /^\d{1,6}$/.test(countValue) ? Number(countValue) : 0;
    const repeated = count >= 3 && /연속|반복|repeated/i.test(description);
    const jointTarget = task && startup && temporary && /같은|동일|same/i.test(description)
      && /가리|대상|target|point/i.test(description);
    const startupPath = /[\\/]startup[\\/]/i.test(path);

    const names = [];
    if (service && ((unsigned && (newService || registered || changedExecutable)
      && (temporary || repeated || changedExecutable))
      || (registered && unfamiliar && persistent))) names.push(PATTERNS[0].name);
    if (task && ((unfamiliar && temporary && outsideHours)
      || (arbitraryName && temporary) || jointTarget)) names.push(PATTERNS[1].name);
    if (startup && ((added && unfamiliar && (startupPath || level >= 10)) || jointTarget))
      names.push(PATTERNS[2].name);

    // Level supports a concrete match; high level/ATT&CK tags alone never block.
    if (names.length) return result(level >= 10 ? 0.94 : 0.78, names.join(' · '));

    const readOnly = /읽기만|조회만|read.only/i.test(description);
    const knownNormal = /기존|평소|승인된|approved|existing/i.test(description)
      && /서명된|그대로|복사.*마|업데이트.*(?:완료|끝)|signed|unchanged/i.test(description);
    if (readOnly || knownNormal) return result(0.1, '패턴 일치 없음');

    // Relevant but incomplete evidence is an alert, not invented registration/execution proof.
    if (level >= 5) {
      if (service) return result(0.6, PATTERNS[0].name + ' · 단서 부족');
      if (task) return result(0.6, PATTERNS[1].name + ' · 단서 부족');
      if (startup) return result(0.6, PATTERNS[2].name + ' · 단서 부족');
    }
    return result(0.1, '패턴 일치 없음');
  } catch {
    // Fixed reason only; malformed fields/accessors must never leak input values.
    return result(0, '패턴 일치 없음');
  }
}
