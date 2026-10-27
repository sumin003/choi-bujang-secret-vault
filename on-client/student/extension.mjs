// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions }) {
      const root = document.createElement('div');
      const deviceStates = {
        compliant: '보안 기준 충족',
        noncompliant: '보안 기준 미충족',
        unknown: '확인 불가',
      };
      const sessionStates = {
        active: '활성',
        expired: '만료',
        revoked: '철회됨',
        unknown: '확인 불가',
      };
      const value = (input) => input == null || input === '' ? '확인 불가' : String(input);
      const deviceState = (status) => Object.hasOwn(deviceStates, status) ? deviceStates[status] : '확인 불가';
      const sessionState = (status) => Object.hasOwn(sessionStates, status) ? sessionStates[status] : '확인 불가';
      const line = (parent, text) => {
        const paragraph = document.createElement('p');
        paragraph.textContent = text;
        parent.appendChild(paragraph);
      };
      const showDevice = (parent, device) => {
        line(parent, '기기 이름: ' + value(device?.label));
        line(parent, '기기 ID: ' + value(device?.id));
        line(parent, '기기 보안 상태: ' + deviceState(device?.status));
      };
      const showSession = (parent, session) => {
        line(parent, '세션 ID: ' + value(session?.id));
        line(parent, '세션 상태: ' + sessionState(session?.status));
      };
      const section = (title, resource, showData) => {
        const box = document.createElement('section');
        const heading = document.createElement('h3');
        heading.textContent = title;
        box.appendChild(heading);
        root.appendChild(box);

        const modes = {
          demo: '예제 자료',
          disconnected: '연결 없음',
          unknown: '확인 불가',
        };
        if (Object.hasOwn(modes, resource?.mode)) line(box, modes[resource.mode]);

        if (resource?.status === 'loading') {
          line(box, '불러오는 중');
        } else if (resource?.status === 'error') {
          line(box, '연결 실패: ' + value(resource.error?.message));
        } else if (resource?.status === 'ok') {
          showData(box, resource.data);
        } else {
          line(box, '확인 불가');
        }
      };

      section('현재 계정·기기·세션', me, (box, data) => {
        line(box, '사용자 이름: ' + value(data?.user?.label));
        line(box, '사용자 ID: ' + value(data?.user?.id));
        line(box, '현재 기기');
        showDevice(box, data?.device);
        line(box, '현재 로그인 세션');
        showSession(box, data?.session);
      });
      section('기기 목록', devices, (box, data) => {
        if (!Array.isArray(data)) {
          line(box, '확인 불가');
          return;
        }
        if (data.length === 0) {
          line(box, '기기 목록이 비어 있습니다.');
          return;
        }
        const list = document.createElement('ul');
        for (const device of data) {
          const item = document.createElement('li');
          showDevice(item, device);
          list.appendChild(item);
        }
        box.appendChild(list);
      });
      section('세션 목록', sessions, (box, data) => {
        if (!Array.isArray(data)) {
          line(box, '확인 불가');
          return;
        }
        if (data.length === 0) {
          line(box, '세션 목록이 비어 있습니다.');
          return;
        }
        const list = document.createElement('ul');
        for (const session of data) {
          const item = document.createElement('li');
          showSession(item, session);
          list.appendChild(item);
        }
        box.appendChild(list);
      });
      return root;
    },
    renderDecision({ status, mode, data, error, appId }) {
      const root = document.createElement('div');
      const line = (text) => {
        const paragraph = document.createElement('p');
        paragraph.textContent = text;
        root.appendChild(paragraph);
      };
      const value = (input) => input == null || input === '' ? '확인 불가' : String(input);
      const modes = {
        demo: '예제 자료',
        disconnected: '연결 없음',
        unknown: '확인 불가',
      };
      if (Object.hasOwn(modes, mode)) line(modes[mode]);

      if (status === 'idle') {
        line('앱을 골라 접속을 요청하세요.');
        return root;
      }

      line('업무 앱 ID: ' + value(status === 'ok' ? data?.appId ?? appId : appId));
      if (status === 'loading') {
        line('판정 확인 중');
      } else if (status === 'error') {
        line('요청 실패: ' + value(error?.message));
        line('요청 실패는 접근 거부 판정이 아닙니다. 접근 허용 여부를 확인할 수 없습니다.');
      } else if (status === 'ok') {
        const decisions = {
          allow: '접근 허용(allow)',
          deny: '접근 거부(deny)',
          challenge: '추가 인증 또는 확인 필요(challenge)',
          unknown: '판정 확인 불가(unknown)',
        };
        const decision = Object.hasOwn(decisions, data?.decision) ? data.decision : 'unknown';
        line('접근 판정: ' + decisions[decision]);
        line('판정 이유: ' + value(data?.reason));
        line('판정 시각: ' + value(data?.checkedAt));
        if (decision === 'allow') {
          line('정책상 접근 허용이며, 실제 업무 앱 접속 성공을 보장하지 않습니다.');
        } else if (decision === 'challenge') {
          line('이 앱은 추가 인증 또는 확인 절차를 대신 수행하지 않습니다.');
        } else if (decision === 'unknown') {
          line('판정을 확인할 수 없으며, 접근 허용으로 판단할 수 없습니다.');
        }
      } else {
        line('판정 확인 불가(unknown)');
        line('요청 상태를 확인할 수 없으며, 접근 허용으로 판단할 수 없습니다.');
      }
      return root;
    },
    renderEvents({ status, mode, data, error }) {
      const root = document.createElement('div');
      const value = (input) => input == null || input === '' ? '확인 불가' : String(input);
      const line = (parent, text) => {
        const element = document.createElement('p');
        element.textContent = text;
        parent.appendChild(element);
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (Object.hasOwn(modes, mode)) line(root, modes[mode]);
      if (status === 'loading') {
        line(root, '기록을 불러오는 중');
        return root;
      }
      if (status === 'error') {
        if (error?.code === 'CONTRACT_MISMATCH') line(root, '기록 응답 확인 불가(CONTRACT_MISMATCH)');
        line(root, '기록을 불러오지 못했습니다: ' + value(error?.message));
        return root;
      }
      if (status !== 'ok' || !Array.isArray(data)) {
        line(root, '기록 응답을 확인할 수 없습니다.');
        return root;
      }
      const records = [...data].sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
      if (records.length === 0) {
        line(root, '표시할 기록이 없습니다');
        return root;
      }

      const kinds = { access: '접속 기록', xdr: 'XDR 경보' };
      const accessStates = { allowed: '접근 허용', denied: '접근 거부', unknown: '확인 불가' };
      const sessionStates = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const deviceStates = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const describe = (labels, code) => Object.hasOwn(labels, code)
        ? labels[code] + '(' + code + ')' : '확인 불가(unknown)';
      const appName = (appId) => appId == null || appId === '' ? '앱 확인 불가' : String(appId);
      const filters = {};
      let selectedId = null;
      const controls = document.createElement('div');
      root.appendChild(controls);
      const count = document.createElement('p');
      const list = document.createElement('ul');
      const detail = document.createElement('div');
      root.appendChild(count);
      root.appendChild(list);
      root.appendChild(detail);

      const showDetail = (event) => {
        detail.replaceChildren();
        if (!event) return;
        const box = document.createElement('section');
        box.setAttribute('data-student-event-detail', event.id);
        const heading = document.createElement('h3');
        heading.textContent = event.id + ' 상세';
        box.appendChild(heading);
        line(box, '사건 ID: ' + value(event.id));
        line(box, '업무 앱: ' + appName(event.appId));
        const showEntries = (title, entries) => {
          const heading = document.createElement('h4');
          heading.textContent = title;
          box.appendChild(heading);
          if (entries.length === 0) line(box, title + ' 없음');
          for (const entry of entries) {
            line(box, 'ID: ' + value(entry.id));
            line(box, '내용: ' + value(entry.text));
          }
        };
        showEntries('근거', event.evidence);
        showEntries('규칙', event.rules);
        line(box, '접속 상태: ' + describe(accessStates, event.state.access));
        line(box, '세션 상태: ' + describe(sessionStates, event.state.session));
        line(box, '기기 상태: ' + describe(deviceStates, event.state.device));
        if (Array.isArray(event.supportedActions) && event.supportedActions.length > 0) {
          line(box, '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중입니다.');
          for (const action of event.supportedActions) {
            const button = document.createElement('button');
            button.type = 'button';
            button.textContent = action + ' 미지원';
            button.disabled = true;
            box.appendChild(button);
          }
        }
        detail.appendChild(box);
      };
      const draw = () => {
        const visible = records.filter((event) =>
          (filters.kind.value === 'all' || event.kind === filters.kind.value)
          && (filters.app.value === 'all' || event.appId === filters.app.value)
          && (filters.access.value === 'all' || event.state.access === filters.access.value));
        list.replaceChildren();
        count.textContent = '표시 기록: ' + visible.length + '건 / 받은 기록: ' + records.length + '건';
        if (visible.length === 0) {
          const empty = document.createElement('li');
          empty.textContent = '표시할 기록이 없습니다';
          list.appendChild(empty);
        }
        for (const event of visible) {
          const row = document.createElement('li');
          row.setAttribute('data-student-event-id', event.id);
          line(row, '사건 ID: ' + value(event.id));
          line(row, '시각: ' + value(event.at));
          line(row, '종류: ' + describe(kinds, event.kind));
          line(row, '업무 앱: ' + appName(event.appId));
          line(row, '요약: ' + value(event.summary));
          const button = document.createElement('button');
          button.type = 'button';
          button.textContent = event.id + ' 상세';
          button.addEventListener('click', () => {
            selectedId = event.id;
            showDetail(event);
          });
          row.appendChild(button);
          list.appendChild(row);
        }
        const selected = visible.find((event) => event.id === selectedId);
        if (!selected) selectedId = null;
        showDetail(selected);
      };
      const addFilter = (key, title, values, labelFor) => {
        const label = document.createElement('label');
        const caption = document.createElement('span');
        caption.textContent = title;
        const select = document.createElement('select');
        select.setAttribute('aria-label', title);
        const all = document.createElement('option');
        all.value = 'all';
        all.textContent = '전체';
        select.appendChild(all);
        for (const code of new Set(values)) {
          const option = document.createElement('option');
          option.value = code;
          option.textContent = labelFor(code);
          select.appendChild(option);
        }
        select.value = 'all';
        select.addEventListener('change', draw);
        label.appendChild(caption);
        label.appendChild(select);
        controls.appendChild(label);
        filters[key] = select;
      };
      addFilter('kind', '기록 종류', records.map((event) => event.kind), (code) => describe(kinds, code));
      addFilter('app', '업무 앱', records.map((event) => event.appId).filter((id) => id != null && id !== ''), appName);
      addFilter('access', '접속 상태', records.map((event) => event.state.access), (code) => describe(accessStates, code));
      draw();
      return root;
    },
    renderStatus({ devices, sessions, notifications, diagnostics, mode }) {
      const root = document.createElement('div');
      const line = (parent, text) => {
        const p = document.createElement('p');
        p.textContent = text;
        parent.appendChild(p);
        return p;
      };
      const value = (input) => typeof input === 'string' || typeof input === 'number'
        ? String(input) || '확인 불가' : '확인 불가';
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (Object.hasOwn(modes, mode)) line(root, modes[mode]);
      const deviceStates = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
      const sessionStates = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
      const describe = (labels, code) => Object.hasOwn(labels, code)
        ? labels[code] + '(' + code + ')' : '확인 불가(unknown)';
      const section = (title) => {
        const box = document.createElement('section');
        const heading = document.createElement('h3');
        heading.textContent = title;
        box.appendChild(heading);
        root.appendChild(box);
        return box;
      };
      const failure = (box, title, error) => {
        line(box, title + '를 불러오지 못했습니다: ' + value(error?.message));
        if (/TIMEOUT|TIMED_OUT|시간\s*초과/i.test(String(error?.code ?? '') + ' ' + String(error?.message ?? ''))) {
          line(box, '시간 초과로 결과를 확인하지 못했습니다.');
        }
        line(box, '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요.');
      };
      const showList = (title, resource, emptyText, showRow) => {
        const box = section(title);
        if (Object.hasOwn(modes, resource?.mode)) line(box, modes[resource.mode]);
        if (resource?.status === 'loading') {
          line(box, title + ' 불러오는 중');
        } else if (resource?.status === 'error') {
          failure(box, title, resource.error);
        } else if (resource?.status === 'ok' && Array.isArray(resource.data)) {
          if (resource.data.length === 0) line(box, emptyText);
          const list = document.createElement('ul');
          for (const row of resource.data) {
            const item = document.createElement('li');
            showRow(item, row);
            list.appendChild(item);
          }
          box.appendChild(list);
        } else {
          line(box, title + ' 확인 불가');
        }
      };
      showList('기기 정보', devices, '등록된 기기가 없습니다.', (item, device) => {
        line(item, '기기 이름: ' + value(device.label));
        line(item, '기기 상태: ' + describe(deviceStates, device.status));
      });
      line(root, '세션은 지금 검증된 연결 한 개를 대상으로 합니다. 과거 세션 전체 목록이 아닙니다.');
      showList('세션 정보', sessions, '현재 연결이 없습니다.', (item, session) => {
        line(item, '세션 ID: ' + value(session.id));
        line(item, '세션 상태: ' + describe(sessionStates, session.status));
      });
      const alerts = section('알림');
      if (Array.isArray(notifications)) {
        if (notifications.length === 0) line(alerts, '주의할 알림이 없습니다.');
        for (const notification of notifications) {
          const item = document.createElement('div');
          line(item, '자료(resource): ' + value(notification.resource));
          line(item, '코드(code): ' + value(notification.code));
          line(item, '내용: ' + value(notification.message));
          alerts.appendChild(item);
        }
      } else {
        line(alerts, '알림 확인 불가');
      }

      const help = section('진단 정보');
      if (Object.hasOwn(modes, diagnostics?.mode)) line(help, modes[diagnostics.mode]);
      let safeText = '';
      if (diagnostics?.status === 'loading') {
        line(help, '진단 정보 불러오는 중');
      } else if (diagnostics?.status === 'error') {
        failure(help, '진단 정보', diagnostics.error);
        line(help, '진단 정보 재조회는 제공 화면의 도움정보 불러오기 버튼을 직접 누르세요.');
      } else if (diagnostics?.status === 'ok' && diagnostics.data && typeof diagnostics.data === 'object') {
        const data = diagnostics.data;
        const safe = {
          requestId: value(data.requestId),
          component: value(data.component),
          version: value(data.version),
          checkedAt: value(data.checkedAt),
          engine: { mode: value(data.engine?.mode), code: value(data.engine?.code) },
        };
        line(help, 'requestId: ' + safe.requestId);
        line(help, 'component: ' + safe.component);
        line(help, 'version: ' + safe.version);
        line(help, 'checkedAt: ' + safe.checkedAt);
        line(help, 'engine.mode: ' + safe.engine.mode);
        line(help, 'engine.code: ' + safe.engine.code);
        safeText = JSON.stringify(safe, null, 2);
      } else if (diagnostics?.status === 'idle') {
        line(help, '진단 정보를 아직 불러오지 않았습니다.');
      } else {
        line(help, '진단 정보 확인 불가');
      }
      if (diagnostics?.status === 'idle') {
        line(help, '위쪽 도움정보 불러오기 버튼을 직접 누르세요.');
      }
      line(help, '도움 요청에 사용할 진단 정보의 지정된 여섯 값만 복사합니다.');
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.textContent = '도움정보 복사';
      copy.disabled = !safeText;
      const feedback = line(help, '');
      feedback.setAttribute('role', 'status');
      copy.addEventListener('click', async () => {
        if (!safeText) return;
        try {
          await navigator.clipboard.writeText(safeText);
          feedback.textContent = '도움정보를 복사했습니다.';
        } catch {
          feedback.textContent = '자동 복사를 완료하지 못했습니다. 아래 도움정보를 직접 선택해 복사하세요.';
          const manual = document.createElement('pre');
          manual.textContent = safeText;
          feedback.replaceChildren(manual);
          const notice = document.createElement('p');
          notice.textContent = '자동 복사를 완료하지 못했습니다. 위 도움정보를 직접 선택해 복사하세요.';
          feedback.appendChild(notice);
        }
      });
      help.appendChild(copy);
      return root;
    },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection({ status, mode, data, error, checkedAt, explanationAccepted }) {
      const root = document.createElement('div');
      const line = (text) => {
        const p = document.createElement('p');
        p.textContent = text;
        root.appendChild(p);
      };
      const modes = { demo: '예제 자료 · 실제 AI 연결 아님', disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
      if (Object.hasOwn(modes, mode)) line(modes[mode]);
      const messages = {
        "ON_AI_PROVISIONING_PENDING": "학생 앱 이용 권한의 발급·연결을 준비 중입니다. 담당자에게 확인하세요.",
        "WB_CLCO_AUTH_REQUIRED": "계정 연결을 다시 확인하고 담당자에게 앱 인증 확인을 요청하세요. Workbench 열쇠를 복사하지 마세요.",
        "WB_CLCO_ACCESS_BLOCKED": "학생 앱 AI 이용이 제한됐습니다. 운영 중지 상태와 이용 권한을 담당자에게 확인하세요.",
        "WB_CLCO_COHORT_BUDGET_EXHAUSTED": "반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.",
        "WB_CLCO_RATE_LIMITED": "AI 요청이 잠시 제한됐습니다. 잠시 후 직접 다시 요청하세요.",
        "WB_CLCO_LIMIT_REACHED": "AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.",
        "WB_CLCO_SESSION_CLOSED": "현재 AI 이용 시간이 아닙니다. 이용 시간을 확인하세요.",
        "WB_CLCO_TIMEOUT": "AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "REQUEST_TIMEOUT": "서버의 AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "ENGINE_TIMEOUT": "서버의 확인 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "TIMEOUT": "AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "WB_CLCO_CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "REQUEST_CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "MODEL_NOT_CONFIGURED": "사용할 AI 모델이 설정되지 않았습니다. 담당자에게 모델 허용 설정을 확인하세요.",
        "ON_AI_AUTHORIZATION_CHANGED": "AI 이용 권한 내용이 점검 도중 바뀌었습니다. 다시 점검하기 전에 담당자에게 현재 권한을 확인하세요.",
        "ON_AI_MODEL_LIST_EMPTY": "현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.",
        "SUBJECT_SCOPE_UNVERIFIED": "현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.",
        "ON_AI_INVALID_INPUT": "설명에 필요한 사건 근거·규칙을 확인할 수 없습니다.",
        "ON_AI_INVALID_OUTPUT": "AI 설명의 근거·조치·응답 형식을 확인할 수 없습니다.",
        "AI_REQUEST_UNVERIFIED": "AI 연결 또는 응답을 확인할 수 없습니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요.",
        "WB_CLCO_NETWORK_ERROR": "AI 게이트와의 네트워크 연결을 확인할 수 없습니다. 잠시 뒤 직접 다시 점검하세요.",
        "WB_CLCO_SERVER_UNAVAILABLE": "AI 게이트 서버를 이용할 수 없습니다. 잠시 뒤 직접 다시 점검하세요."
};
      const showError = (error) => {
        const code = Object.hasOwn(messages, error?.code) ? error.code : 'AI_REQUEST_UNVERIFIED';
        line('오류 코드: ' + code);
        line('오류 내용: ' + (code === error?.code && typeof error.message === 'string'
          ? error.message : messages[code]));
        line(messages[code]);
      };
      if (status === 'idle') {
        line('AI 연결 점검 전');
      } else if (status === 'loading') {
        line('AI 연결 점검 중');
      } else if (status === 'error') {
        line('AI 연결 점검 실패');
        showError(error);
      } else if (status === 'ok') {
        if (data?.transportChecked === true && ['test', 'verified'].includes(data.audienceAuthorization)
          && Number.isInteger(data.modelCount) && data.modelCount >= 0) {
          line(data.audienceAuthorization === 'test'
            ? '시험 연결 점검(test)' : '앱 권한 확인 후 점검(verified)');
          line('사용 가능한 모델 수(modelCount): ' + data.modelCount);
          line('점검 시각(checkedAt): ' + (typeof checkedAt === 'string' ? checkedAt : '확인 불가'));
          line('연결과 모델 목록 응답만 점검했습니다. 사건 설명은 아직 실행하지 않았습니다.');
          if (data.audienceAuthorization === 'test') line('시험 연결이며 실제 앱 권한 확인을 완료한 결과가 아닙니다.');
          if (data.modelCount === 0) line('사용할 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.');
        } else {
          line('AI 연결 점검 결과 확인 불가');
          line('연결 또는 사건 설명 성공으로 판단할 수 없습니다.');
        }
      } else {
        line('AI 연결 점검 상태 확인 불가');
      }
      line('다시 점검하려면 제공 화면의 현재 API 연결 점검 버튼을 직접 누르세요. 자동으로 다시 점검하지 않습니다.');
      return root;
    },
    renderExplanation({ event, explanation, checkedAt }) {
      const root = document.createElement('div');
      const line = (text) => {
        const p = document.createElement('p');
        p.textContent = text;
        root.appendChild(p);
      };
      const messages = {
        "ON_AI_PROVISIONING_PENDING": "학생 앱 이용 권한의 발급·연결을 준비 중입니다. 담당자에게 확인하세요.",
        "WB_CLCO_AUTH_REQUIRED": "계정 연결을 다시 확인하고 담당자에게 앱 인증 확인을 요청하세요. Workbench 열쇠를 복사하지 마세요.",
        "WB_CLCO_ACCESS_BLOCKED": "학생 앱 AI 이용이 제한됐습니다. 운영 중지 상태와 이용 권한을 담당자에게 확인하세요.",
        "WB_CLCO_COHORT_BUDGET_EXHAUSTED": "반의 AI 사용량이 소진됐습니다. 담당자에게 확인하세요.",
        "WB_CLCO_RATE_LIMITED": "AI 요청이 잠시 제한됐습니다. 잠시 후 직접 다시 요청하세요.",
        "WB_CLCO_LIMIT_REACHED": "AI 이용 한도에 도달했습니다. 담당자에게 확인하세요.",
        "WB_CLCO_SESSION_CLOSED": "현재 AI 이용 시간이 아닙니다. 이용 시간을 확인하세요.",
        "WB_CLCO_TIMEOUT": "AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "REQUEST_TIMEOUT": "서버의 AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "ENGINE_TIMEOUT": "서버의 확인 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "TIMEOUT": "AI 응답 시간이 초과됐습니다. 필요하면 직접 다시 요청하세요.",
        "WB_CLCO_CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "REQUEST_CANCELLED": "AI 요청을 취소했습니다. 이전 응답은 현재 결과가 아닙니다.",
        "MODEL_NOT_CONFIGURED": "사용할 AI 모델이 설정되지 않았습니다. 담당자에게 모델 허용 설정을 확인하세요.",
        "ON_AI_AUTHORIZATION_CHANGED": "AI 이용 권한 내용이 점검 도중 바뀌었습니다. 다시 점검하기 전에 담당자에게 현재 권한을 확인하세요.",
        "ON_AI_MODEL_LIST_EMPTY": "현재 앱 권한으로 쓸 수 있는 AI 모델이 없습니다. 담당자에게 모델 허용 설정을 확인하세요.",
        "SUBJECT_SCOPE_UNVERIFIED": "현재 로그인과 사건·프로젝트의 연결을 확인할 수 없습니다.",
        "ON_AI_INVALID_INPUT": "설명에 필요한 사건 근거·규칙을 확인할 수 없습니다.",
        "ON_AI_INVALID_OUTPUT": "AI 설명의 근거·조치·응답 형식을 확인할 수 없습니다.",
        "AI_REQUEST_UNVERIFIED": "AI 연결 또는 응답을 확인할 수 없습니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요.",
        "WB_CLCO_NETWORK_ERROR": "AI 게이트와의 네트워크 연결을 확인할 수 없습니다. 잠시 뒤 직접 다시 점검하세요.",
        "WB_CLCO_SERVER_UNAVAILABLE": "AI 게이트 서버를 이용할 수 없습니다. 잠시 뒤 직접 다시 점검하세요."
};
      const showError = (error) => {
        const code = Object.hasOwn(messages, error?.code) ? error.code : 'AI_REQUEST_UNVERIFIED';
        line('오류 코드: ' + code);
        line('오류 내용: ' + (code === error?.code && typeof error.message === 'string'
          ? error.message : messages[code]));
        line(messages[code]);
      };
      if (explanation?.status === 'ok') {
        if (typeof event?.id === 'string' && event.id && typeof explanation.data?.summary === 'string') {
          root.setAttribute('data-student-explanation-event', event.id);
          line('사건 ID: ' + event.id);
          line('사건 설명: ' + explanation.data.summary);
          if (typeof checkedAt === 'string') line('확인 시각: ' + checkedAt);
        } else {
          line('사건 설명 확인 불가');
          line('기존 보안 기록은 그대로 유지됩니다.');
        }
      } else if (explanation?.status === 'error') {
        line('사건 설명 요청 실패');
        showError(explanation.error);
        line('기존 보안 기록은 그대로 유지됩니다.');
        line('다시 요청하려면 해당 사건의 AI 설명 버튼을 직접 누르세요.');
      } else if (explanation?.status === 'loading') {
        line('사건 설명 요청 중');
        line('기존 보안 기록은 그대로 유지됩니다.');
      } else {
        line('사건 설명은 아직 실행하지 않았습니다.');
        line('AI 연결 점검과 사건 설명 요청은 별개입니다.');
      }
      return root;
    },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
