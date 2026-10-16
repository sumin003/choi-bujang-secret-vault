const PATTERNS = Object.freeze([
  {
    "name": "관리자 그룹의 의심스러운 권한 추가·재추가",
    "condition": "관리자 권한을 주는 로컬·도메인 그룹에 계정이 추가되거나 제거 직후 다시 추가된 실제 변경을 찾는다. 원격 출발 주소, 여러 계정의 연속 추가, 기존 일반 계정의 직후 권한 명령 실행은 결합할 보조 신호다. 수업·과제 그룹 추가, 그룹 설명만 변경, 목록 조회, 승인된 관리자 변경과 구분한다. 그룹명이 없으면 관리자 그룹으로 추정하지 않는다.",
    "evidence": "MITRE ATT&CK T1098.007은 추가 그룹 멤버십으로 권한을 확보하는 계정 조작을, T1078은 정상 계정을 악용한 접근과 권한 사용을 설명한다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1098/007/",
      "https://attack.mitre.org/techniques/T1078/"
    ]
  },
  {
    "name": "낯선 관리자 명령과 갑작스러운 권한 전환",
    "condition": "확인된 일반 계정·세션의 관리자 권한 전환 직후 관리자 명령 실행, 다른 계정 권한의 사용, 낯선 출발 주소에서의 권한 명령 등 복합 단서를 찾는다. 명령 이름을 입력값처럼 실행하거나 토큰 원문을 읽지 않는다. 취약점 악용 경보가 명시된 경우에만 T1068 근거를 적용하며 단순 관리자 실행을 취약점 악용 성공으로 표시하지 않는다. 취소된 상승 창, 실패한 명령, 권한 조회만 수행, 평소 승인된 관리자 작업은 명확한 공격과 구분한다.",
    "evidence": "MITRE ATT&CK T1068은 소프트웨어 취약점 악용에 의한 권한 상승을 다루고 T1078은 유효 계정의 악용을 다루므로 관리자 실행 단독으로 두 기법을 확정하지 않는다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1068/",
      "https://attack.mitre.org/techniques/T1078/"
    ]
  },
  {
    "name": "업무 시간 밖의 비정상 권한 사용 조합",
    "condition": "신뢰 가능한 경보에서 업무·수업 시간 밖 권한 사용이 명시되고, 처음 보는 주소·관리자 그룹 추가·직후 관리자 명령 실행 등 별도 단서가 함께 나타나는지 찾는다. 기준 시간대나 업무 일정이 없으면 임의로 시간 밖이라고 계산하지 않는다. 시간 하나만으로 차단하거나 도용을 확정하지 않으며, 정상 야간 운영·예약 점검·평소 관리 계정 접속은 구분한다.",
    "evidence": "MITRE ATT&CK T1078은 유효 계정 악용을 설명하며 비정상적인 시간·출발지·권한 사용의 조합은 해당 계정의 정상 사용과 대조할 탐지 단서다.",
    "sources": [
      "https://attack.mitre.org/techniques/T1078/"
    ]
  }
].map(Object.freeze));

// Standalone metadata matching only. No imports, I/O, external lookups or execution.
const text = value => typeof value === 'string' ? value.slice(0, 8192) : '';
function result(confidence, reason) {
  return {action:confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason};
}

export function decide(alert) {
  try {
    const description = text(alert?.rule?.description);
    const group = text(alert?.data?.group).toLowerCase();
    const rawLevel = alert?.rule?.level;
    const level = Number.isInteger(rawLevel) && rawLevel >= 0 && rawLevel <= 16 ? rawLevel : 0;
    const relevant = /관리자|권한|계정\s*종류|그룹|administrator|privilege|elevat|\bgroup\b/i.test(description);
    const names = [];
    const adminGroup = ['administrators','domain admins','enterprise admins','sudo','wheel'].includes(group)
      || /관리자\s*그룹|admin(?:istrator)?s?\s+group/i.test(description);
    const notAdminGroup = /관리자\s*그룹(?:은|이)?\s*아니|not\s+(?:an?\s+)?admin(?:istrator)?\s+group/i.test(description);
    const added = /추가|들어가|들어왔|\badd(?:ed)?\b|\bjoined\b/i.test(description);
    const remote = /원격\s*주소|remote\s+(?:address|source)/i.test(description);
    const unfamiliar = /처음\s*보는\s*주소|주소(?:는|가)?\s*처음|낯선\s*주소|unfamiliar\s+(?:source|address)/i.test(description);
    const offHours = /(?:수업|업무)\s*시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|outside\s+(?:work|business|class)\s+hours/i.test(description);
    const command = /(?:관리자|권한)\s*명령.*실행|admin(?:istrative|istrator)?\s+command.*execut/i.test(description);
    const anyExecution = /명령\s*실행|명령.*실행|command.*execut/i.test(description);
    const justElevated = /방금\s*관리자가\s*된|관리자\s*권한으로\s*(?:바뀌|변경)|just\s+(?:became|elevated)/i.test(description);
    const ordinary = /평범한\s*계정|일반\s*계정|ordinary\s+(?:user|account)/i.test(description);
    const immediate = /곧바로|직후|방금|immediately/i.test(description);
    const otherAccount = /다른\s*계정의\s*권한|another\s+account.s\s+(?:rights|privileges)/i.test(description);
    const readded = /빠진|제거|removed/i.test(description) && /다시\s*관리자로\s*들어|재추가|re.?added/i.test(description);
    const rawCount = alert?.data?.count;
    const count = Number.isSafeInteger(rawCount) ? rawCount
      : typeof rawCount === 'string' && /^\d{1,6}$/.test(rawCount) ? Number(rawCount) : 0;
    const multiAccount = count >= 3 && /계정\s*\d+\s*개|multiple\s+accounts/i.test(description);
    const unsuccessful = /취소|실패|명령(?:은|이)?\s*없|변경(?:은|이)?\s*없|cancel|failed|no\s+(?:command|change)/i.test(description);
    const approved = /승인된\s*(?:관리자\s*)?(?:변경|작업)|approved\s+(?:admin\s+)?(?:change|maintenance)/i.test(description);

    if (!unsuccessful && !notAdminGroup && adminGroup &&
      ((added && (remote || multiAccount || (ordinary && immediate && command) || (offHours && anyExecution)))
      || readded)) names.push(PATTERNS[0].name);
    if (!unsuccessful && ((justElevated && (command || unfamiliar))
      || (command && otherAccount) || (command && unfamiliar && offHours))) names.push(PATTERNS[1].name);
    if (!unsuccessful && offHours && ((command && unfamiliar) || (adminGroup && added && anyExecution)))
      names.push(PATTERNS[2].name);

    // The label identifies a matching pattern, not proof of a T1068 exploit.
    // A high level or ATT&CK tag alone never establishes a match.
    if (names.length) return result(approved ? 0.6 : level >= 10 ? 0.94 : 0.78, names.join(' · '));
    if (level >= 5 && relevant) {
      const name = /그룹|\bgroup\b/i.test(description) ? PATTERNS[0].name
        : offHours ? PATTERNS[2].name : PATTERNS[1].name;
      return result(0.6, name + ' · 단서 부족');
    }
    return result(0.1, '패턴 일치 없음');
  } catch {
    return result(0, '패턴 일치 없음');
  }
}
