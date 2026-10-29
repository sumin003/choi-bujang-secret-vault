// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.
export function createStudentView({ api } = {}) {
  // 제공된 읽기 전용 측정 API를 재사용한다. OS 조회·자동 재요청·예시 값 없음.
  let pc = { status: 'idle' };
  const pcPanel = () => {
    const root = document.createElement('section');
    const add = (parent, tag, text) => {
      const node = document.createElement(tag);
      node.textContent = text;
      parent.appendChild(node);
      return node;
    };
    const reasons = {
      permission_denied: '일반 권한으로 읽을 수 없습니다',
      unsupported: '이 운영체제에서 지원하지 않습니다',
      timeout: '조회 시간이 초과됐습니다',
      query_failed: '시스템 조회에 실패했습니다',
      invalid_response: '응답 형식을 확인할 수 없습니다',
      invalid_sample: '유효한 CPU 측정 구간을 확보하지 못했습니다',
      cancelled: '측정이 취소됐습니다',
    };
    const finite = n => typeof n === 'number' && Number.isFinite(n) && n >= 0;
    const gib = n => (n / 1024 ** 3).toFixed(2) + ' GiB';
    const paint = () => {
      root.replaceChildren();
      add(root, 'h3', '케셰브 · 내 PC 실측');
      add(root, 'p', '제공된 로컬 PC 측정 기능을 사용합니다. 예시 값은 표시하지 않습니다. 보안 서버·AI 연결 상태와 별개입니다.');
      const button = add(root, 'button', pc.status === 'loading' ? 'PC 상태 측정 중' : 'PC 상태 새로 측정');
      button.type = 'button';
      button.disabled = pc.status === 'loading' || typeof api?.get !== 'function';
      button.addEventListener('click', async () => {
        if (pc.status === 'loading') return;
        pc = { status: 'loading' };
        paint();
        try {
          const reply = await api.get('/api/pc/status');
          const data = reply?.data;
          const stamp = typeof data?.measuredAt === 'string' ? Date.parse(data.measuredAt) : NaN;
          if (!reply?.ok) pc = { status: 'error', reason: '로컬 앱 서버의 PC 측정 요청에 실패했습니다' };
          else if (data?.schema !== 'aleph.on.pc-status.v1' || data.source !== 'local-pc'
            || !data.metrics || !Number.isFinite(stamp) || Math.abs(Date.now() - stamp) > 60000) {
            pc = { status: 'error', reason: '실측 출처·측정 시각·응답 형식을 확인할 수 없습니다' };
          } else pc = { status: 'ok', data };
        } catch {
          pc = { status: 'error', reason: '로컬 앱 서버에 연결하거나 측정 결과를 읽을 수 없습니다' };
        }
        paint();
        root.querySelector('button')?.focus();
      });
      const grid = document.createElement('div');
      grid.style.display = 'grid';
      grid.style.gridTemplateColumns = 'repeat(auto-fit, minmax(180px, 1fr))';
      grid.style.gap = '12px';
      root.appendChild(grid);
      const d = pc.status === 'ok' ? pc.data : null;
      const measured = d ? new Date(d.measuredAt).toLocaleString('ko-KR', {
        timeZone: 'Asia/Seoul', hour12: false
      }) + ' (한국 시각) · ' + d.measuredAt : null;
      const card = (name, metric, describe) => {
        const box = document.createElement('section');
        box.style.border = '1px solid currentColor';
        box.style.borderRadius = '12px';
        box.style.padding = '12px';
        grid.appendChild(box);
        add(box, 'h4', name);
        let text;
        if (pc.status === 'idle') text = '확인 불가 — 아직 측정하지 않았습니다';
        else if (pc.status === 'loading') text = '측정 중 — 이전 값을 현재 값으로 표시하지 않습니다';
        else if (pc.status === 'error') text = '확인 불가 — ' + pc.reason;
        else if (metric?.state !== 'ok') text = '확인 불가 — ' + (reasons[metric?.reason] || '읽을 수 있는 측정 결과가 없습니다');
        else text = describe(metric) || '확인 불가 — 측정 값의 형식 또는 범위가 올바르지 않습니다';
        add(box, 'p', text);
        add(box, 'p', measured ? '측정 묶음 시각: ' + measured : '측정 시각: 확인 불가 — 유효한 실측 결과 없음');
      };
      card('CPU 사용률', d?.metrics.cpu, m =>
        finite(m.usagePercent) && m.usagePercent <= 100
          ? m.usagePercent.toFixed(1) + ' %' + (finite(m.sampleMs) ? ' · 표본 구간 ' + m.sampleMs + ' ms' : '') : null);
      card('메모리 사용량', d?.metrics.memory, m =>
        finite(m.usedBytes) && finite(m.totalBytes) && m.totalBytes > 0 && m.usedBytes <= m.totalBytes
          ? gib(m.usedBytes) + ' / 전체 ' + gib(m.totalBytes) + ' · ' + (100 * m.usedBytes / m.totalBytes).toFixed(1) + ' %' : null);
      card('디스크 남은 공간', d?.metrics.disk, m =>
        finite(m.freeBytes) && finite(m.totalBytes) && m.totalBytes > 0 && m.freeBytes <= m.totalBytes
          ? gib(m.freeBytes) + ' / 전체 ' + gib(m.totalBytes) : null);
      card('방화벽 프로필', d?.metrics.firewall, m =>
        Array.isArray(m.profiles) && m.profiles.length === 3
          && ['Domain', 'Private', 'Public'].every(name => m.profiles.some(p => p.name === name && typeof p.enabled === 'boolean'))
          ? m.profiles.map(p => p.name + ': ' + (p.enabled ? '켜짐' : '꺼짐')).join(' · ') + ' · 단위: 해당 없음' : null);
      add(root, 'h4', '측정 결과 읽는 법');
      add(root, 'p', 'CPU는 짧은 표본 구간의 사용률입니다. 작업 관리자와 비교할 때 측정 시점과 집계 구간이 다르면 값이 다를 수 있습니다.');
      add(root, 'p', '메모리는 이 PC 전체의 사용량이며 케셰브 앱만의 사용량이 아닙니다. GiB는 1,073,741,824바이트입니다.');
      add(root, 'p', '디스크는 로컬 앱 서버의 프로젝트가 있는 파일시스템의 남은 공간입니다. 모든 드라이브의 합계가 아닙니다.');
      add(root, 'p', '측정 묶음 시각은 제공 API가 전체 조회를 마친 시각입니다. 각 항목을 정확히 동시에 측정했다는 뜻은 아닙니다. 자동 재측정과 관리자 권한 요청은 하지 않습니다.');
      if (typeof api?.get !== 'function') add(root, 'p', '확인 불가 — 제공 PC 조회 API가 연결되지 않았습니다.');
    };
    paint();
    return root;
  };

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
      root.appendChild(pcPanel());
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
    renderVulnerabilities({ status, mode, data, error }) {
      const root = document.createElement('div');
      const line = (parent, text) => {
        const p = document.createElement('p');
        p.textContent = text;
        parent.appendChild(p);
      };
      const field = (parent, name, value) => {
        if (value !== null && value !== undefined && ['string', 'number'].includes(typeof value)) {
          line(parent, name + ': ' + String(value));
        }
      };
      const modes = { demo: '예제 자료', disconnected: '연결 없음', unknown: '확인 불가' };
      if (Object.hasOwn(modes, mode)) line(root, modes[mode]);
      if (status === 'idle') {
        line(root, '조회 전');
        return root;
      }
      if (status === 'loading') {
        line(root, '조회 중');
        return root;
      }
      if (status === 'error') {
        line(root, '조회 실패: ' + (typeof error?.message === 'string' ? error.message : '패키지 조회 결과를 확인할 수 없습니다.'));
        field(root, '오류 코드', error?.code);
        line(root, '조회 실패는 취약점이 없다는 뜻이 아닙니다. 제공 화면의 설치 패키지 조회 버튼을 직접 눌러 다시 조회하세요.');
        return root;
      }
      const scanStates = {
        complete: '모두 조회(complete)',
        partial: '일부 조회 실패(partial)',
        not_checked: '아직 조회 안 함(not_checked)',
        not_configured: '조회 준비 미완료(not_configured)',
        unverifiable: 'lock 파일 확인 불가(unverifiable)',
      };
      if (status !== 'ok' || !data || !Object.hasOwn(scanStates, data.status) || !Array.isArray(data.packages)) {
        line(root, '조회 결과 확인 불가. 취약점이 없다는 뜻이 아닙니다.');
        return root;
      }
      line(root, '전체 조회 상태: ' + scanStates[data.status]);
      field(root, '잠금 파일 버전(lockfileVersion)', data.lockfileVersion);
      field(root, '잠금 파일 해시(lockfileHash)', data.lockfileHash);
      field(root, '전체 확인 시각(checkedAt)', data.checkedAt);
      if (data.status === 'not_configured') {
        line(root, '조회 대상 프로젝트 설정이 필요합니다. 담당자가 준비하며 학생이 임의로 설정을 변경하지 않습니다.');
      } else if (data.status === 'not_checked') {
        line(root, '승인된 공개 조회 대상이 없어 아직 조회하지 않았습니다. 미조회는 취약점 없음이 아닙니다.');
      } else if (data.status === 'unverifiable') {
        line(root, '잠금 파일과 설치 패키지 정보를 확인할 수 없습니다. 취약점 없음으로 판단하지 마세요.');
      } else if (data.status === 'partial') {
        line(root, '일부 조회에 실패했습니다. 이미 받은 취약점 식별자는 아래에 유지합니다.');
      }
      line(root, '설치 버전은 서버가 package-lock.json과 node_modules 메타데이터를 대조해 전달한 값입니다. 버전 범위를 설치 버전으로 바꾸어 표시하지 않습니다.');
      if (data.packages.length === 0) {
        line(root, '표시할 패키지 조회 결과가 없습니다. 이 문구는 취약점 없음 판정이 아닙니다.');
      }
      const packageStates = {
        known_vulnerabilities: '알려진 항목 있음(known_vulnerabilities)',
        none_found: '알려진 항목 없음(none_found)',
        unverifiable: '조회 확인 불가(unverifiable)',
      };
      for (const pkg of data.packages) {
        const row = document.createElement('section');
        row.setAttribute('data-student-package-name', pkg.name);
        row.setAttribute('data-student-package-version', pkg.version);
        const heading = document.createElement('h3');
        heading.textContent = pkg.name + ' · ' + pkg.version;
        row.appendChild(heading);
        field(row, '패키지 이름(name)', pkg.name);
        field(row, '정확한 설치 버전(version)', pkg.version);
        line(row, '패키지 조회 상태: ' + (Object.hasOwn(packageStates, pkg.status)
          ? packageStates[pkg.status] : '조회 확인 불가(unverifiable)'));
        field(row, '출처(source)', pkg.source);
        field(row, '패키지 확인 시각(checkedAt)', pkg.checkedAt);
        if (pkg.status === 'none_found') {
          line(row, '이 버전의 조회 범위와 조회 시점에서 알려진 항목이 없다는 뜻입니다.');
        }
        if (pkg.status === 'unverifiable') {
          line(row, Array.isArray(pkg.vulnerabilities) && pkg.vulnerabilities.length > 0
            ? '일부 확인·전체 조회 확인 불가. 이미 받은 취약점 ID를 표시합니다.'
            : '조회 결과를 확인할 수 없습니다. 취약점 없음으로 판단하지 마세요.');
        }
        if (Array.isArray(pkg.vulnerabilities)) {
          for (const vulnerability of pkg.vulnerabilities) {
            field(row, '취약점 ID', vulnerability.id);
            field(row, '수정 시각(modified)', vulnerability.modified);
          }
        }
        root.appendChild(row);
      }
      line(root, 'OSV는 알려진 취약점 데이터베이스입니다. 조회 결과가 없다는 사실만으로 패키지나 앱 전체의 안전을 보장하지 않습니다.');
      return root;
    },
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
      const reject = (reason, code = 'ON_AI_INVALID_OUTPUT') => {
        line('AI 설명을 사용할 수 없습니다: ' + reason);
        showError({ code, message: messages[code] });
        line('기록은 그대로입니다. AI 설명 실패 자체가 과제 실패를 의미하지는 않습니다.');
        return root;
      };
      if (explanation?.status === 'error') {
        line('AI 설명 실패');
        showError(explanation.error);
        line('기록은 그대로입니다. AI 설명 실패 자체가 과제 실패를 의미하지는 않습니다.');
        line('다시 요청하려면 해당 사건의 AI 설명 버튼을 직접 누르세요.');
        return root;
      }
      if (!event) {
        line('보안 기록에서 기록을 먼저 고르세요.');
        return root;
      }
      if (explanation?.status === 'loading') {
        line('AI 설명 요청 중');
        line('사건 ID: ' + event.id);
        line('기록은 그대로입니다.');
        return root;
      }
      if (explanation?.status !== 'ok') {
        line('사건 설명은 아직 실행하지 않았습니다.');
        line('AI 연결 점검과 사건 설명 요청은 별개입니다.');
        return root;
      }
      const data = explanation.data;
      if (data?.executed === true) {
        return reject('AI가 이미 조치를 실행했다고 답한 설명은 사용할 수 없습니다.');
      }
      if (!Array.isArray(event.evidence) || event.evidence.length === 0
        || !Array.isArray(event.rules) || event.rules.length === 0) {
        return reject('선택한 기록의 근거 또는 규칙이 부족합니다.', 'ON_AI_INVALID_INPUT');
      }
      if (typeof event.id !== 'string' || !event.id || !event.state
        || typeof data?.summary !== 'string' || !data.summary.trim()
        || !Array.isArray(data.evidenceIds) || !Array.isArray(data.proposals)
        || !Array.isArray(event.supportedActions)
        || data.executed !== false || data.requiresHumanConfirmation !== true) {
        return reject('현재 기록 또는 AI 설명의 형식을 확인할 수 없습니다.');
      }
      const evidence = new Map(event.evidence.map((entry) => [entry.id, entry.text]));
      const validRefs = (ids) => Array.isArray(ids) && ids.length > 0
        && new Set(ids).size === ids.length && ids.every((id) => evidence.has(id));
      if (evidence.size !== event.evidence.length || !validRefs(data.evidenceIds)
        || data.evidenceIds.length !== evidence.size) {
        return reject('근거가 맞지 않습니다. 현재 기록의 근거 ID와 일치하지 않거나 필요한 근거가 빠져 있습니다.');
      }
      if (!data.proposals.every((proposal) => proposal
        && event.supportedActions.includes(proposal.action)
        && validRefs(proposal.evidenceIds) && typeof proposal.reason === 'string' && proposal.reason.trim())) {
        return reject('제안의 조치 또는 근거가 현재 기록과 맞지 않습니다.');
      }

      root.setAttribute('data-student-explanation-event', event.id);
      if (explanation.mode === 'demo') line('예제 자료');
      const heading = document.createElement('h3');
      heading.textContent = 'AI 설명(참고용)';
      root.appendChild(heading);
      line('사건 ID: ' + event.id);
      line(data.summary);
      line('AI 설명은 참고용 해석입니다. 사실 판단은 근거 글과 연동 시스템이 알려 준 상태를 기준으로 합니다.');
      if (typeof checkedAt === 'string') line('확인 시각: ' + checkedAt);
      const title = (text) => {
        const heading = document.createElement('h4');
        heading.textContent = text;
        root.appendChild(heading);
      };
      title('인용한 근거');
      for (const id of data.evidenceIds) line(id + ' — ' + evidence.get(id));
      title('적용 규칙');
      for (const rule of event.rules) line(rule.id + ' — ' + rule.text);
      title('확인 불가 상태');
      const labels = { access: '접속', session: '세션', device: '기기' };
      let unknownCount = 0;
      for (const key of Object.keys(labels)) {
        if (event.state[key] === 'unknown') {
          line(labels[key] + ': 확인 불가(unknown)');
          unknownCount++;
        }
      }
      if (unknownCount === 0) line('없음');
      title('AI 제안 · 미실행');
      if (data.proposals.length === 0) {
        line(event.supportedActions.length === 0
          ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
          : 'AI가 제안한 조치가 없습니다.');
      } else {
        for (const proposal of data.proposals) {
          line('조치: ' + proposal.action);
          line('이유: ' + proposal.reason);
          for (const id of proposal.evidenceIds) line('제안 근거: ' + id + ' — ' + evidence.get(id));
          line('사람 확인이 필요하며 실행되지 않았습니다.');
        }
      }
      line('AI 설명이나 제안만으로 보안 조치가 실행되지는 않습니다.');
      return root;
    },
    renderAction({ status, event, actionId, target, receipt, observation, message, confirmationExpiresAt, error }) {
      const root = document.createElement('div');
      const line = (text) => {
        const p = document.createElement('p');
        p.textContent = text;
        root.appendChild(p);
      };
      const present = (value) => value !== null && value !== undefined && value !== '';
      const field = (name, value) => {
        if (present(value) && ['string', 'number', 'boolean'].includes(typeof value)) {
          line(name + ': ' + String(value));
        }
      };
      const labels = {
        idle: '아직 미실행(idle)',
        loading: '조치 준비 또는 결과 조회 중(loading) · 실행 결과 확인 전',
        prepared: '준비됨·미실행(prepared)',
        executing: '서버에 전달 중(executing) · 결과가 아직 확인되지 않았습니다.',
        pending: '서버 접수·처리 중(pending) · 접수 응답(ACK)은 실제 효과 확인이 아닙니다.',
        succeeded: '효과 확인(succeeded)',
        denied: '연동 시스템 거절(denied)',
        failed: '연동 시스템 실패(failed)',
        unknown: '결과 불명(unknown)',
        expired: '확인 기한 지남(expired)',
        error: '요청 처리 안 됨(error)',
      };
      const known = Object.hasOwn(labels, status);
      const confirmed = status === 'succeeded' && observation?.effectApplied === true;
      const shownStatus = !known || status === 'succeeded' && !confirmed ? 'unknown' : status;
      line(labels[shownStatus]);

      if (present(event?.id)) root.setAttribute('data-student-action-event', event.id);
      if (present(receipt?.requestId)) root.setAttribute('data-student-action-request', receipt.requestId);
      field('사건 ID(event.id)', event?.id);
      if (Array.isArray(event?.evidence)) {
        for (const entry of event.evidence) field('근거 ID', entry.id);
      }
      field('조치 ID(actionId)', actionId);
      field('실제 대상 ID(target.id)', target?.id);
      field('대상 세대(target.generation)', target?.generation);
      field('요청 ID(requestId)', receipt?.requestId);
      field('영수증 ID(receiptId)', receipt?.receiptId);
      field('결과 버전(version)', receipt?.version);

      if (shownStatus === 'idle') {
        line('AI 제안만으로 조치는 실행되지 않습니다.');
        if (Array.isArray(event?.supportedActions) && event.supportedActions.length === 0) {
          line('현재 기록에는 지원 조치가 없어 조치 준비 버튼이 표시되지 않는 것이 정상입니다.');
        } else if (!event) {
          line('현재 기록의 지원 조치가 비어 있으면 조치 준비 버튼이 표시되지 않는 것이 정상입니다.');
        }
      } else if (shownStatus === 'prepared') {
        field('사람 확인 기한(confirmationExpiresAt)', confirmationExpiresAt);
        line('실제 대상과 조치를 사람이 확인하기 전에는 실행되지 않습니다. 제공 화면에서 대상과 조치를 확인하세요.');
      } else if (shownStatus === 'executing' || shownStatus === 'pending') {
        line('실제 효과는 아직 확인되지 않았습니다. 중복 집행을 요청하지 마세요.');
      } else if (confirmed) {
        field('관측 시각(observation.observedAt)', observation.observedAt);
        line('effectApplied: true');
      } else if (shownStatus === 'unknown') {
        line('성공이나 효과 없음으로 판단하지 마세요. 제공 화면의 연동 시스템 결과만 재조회 버튼을 직접 누르세요.');
        line('같은 조치를 다시 집행하지 말고 기존 요청의 결과만 확인하세요.');
      } else if (shownStatus === 'expired') {
        line('이번 확인 기한으로는 집행할 수 없습니다. 제공 화면에서 조치를 다시 준비하고 실제 대상을 확인하세요.');
      }

      if (['idle', 'loading', 'denied', 'failed', 'unknown', 'expired', 'error'].includes(shownStatus)) {
        field('안내', message);
      }
      if (error && ['error', 'unknown', 'expired', 'denied', 'failed'].includes(shownStatus)) {
        field('오류 코드', error.code);
        field('오류 내용', error.message);
      }
      if (receipt?.replayed === true) line('기존 요청의 응답 재전달(replayed)입니다. 새 집행을 의미하지 않습니다.');
      if (receipt?.superseded === true) line('이전 결과가 대체됐습니다(superseded). 기존 결과를 현재 효과로 판단하지 마세요.');
      line('조치 준비·사람 확인·결과 재조회는 제공 화면 버튼을 사용하세요. 이 학생 영역은 요청을 전송하지 않습니다.');
      line('조치 화면 취소는 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.');
      return root;
    },
  };
}
