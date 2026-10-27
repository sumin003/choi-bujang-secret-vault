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
    renderDecision() { return '학생 구현 대기: 서버의 판정과 이유를 연결하세요.'; },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
