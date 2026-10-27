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
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
