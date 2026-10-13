# 8단계 가상 판정과 실제 API

`src/resource-zone-policy.mjs`는 제공된 원본 fixture의 정상 요청을 기준으로 가상 정책을 명시합니다. 적용 범위는 class_fixture·project_fixture·judge_fixture이며 다른 반·프로젝트·실제 신호로 승격하지 않습니다.

원본 `/notes/demo`와 이전 로컬 UUID 별칭은 learner_fixture 소유입니다. 별도로 정의한 학습 사용자 other_learner_fixture는 other-demo만 소유하며, 학습 강사 teacher_fixture는 notice-demo만 소유합니다. 뒤의 두 사용자는 이 프로젝트가 정의한 가상 시험 주체이고 실제 계정이나 심판의 내부 주체라고 가정하지 않습니다. 소유자 이름 포함·부분 일치나 demo 무조건 허용은 사용하지 않습니다.

이 범위에서 export된 decide가 직접 자원 등록부의 소유자·정책 역할을 대조합니다. 등록되지 않은 사용자·자료·경로, 학생 공지 수정, 미등록 기기, 기능 쿼리·export 기능 경로는 거부합니다. 기존 추가 확인 규칙도 유지합니다. 과제용 메모 ID는 UUID로 한정하지 않지만 실제 API의 UUID 검사는 보존합니다.

가상 범위 밖에서는 기존 서버 DB의 검증된 사용자 연결·소유자·강사 권한 검사로 진행하며, 연결이나 조회가 실패하면 거부합니다. 가상 등록부는 실제 Supabase 메모나 권한을 변경하지 않습니다.

실제 /api/notes와 /api/announcements는 기존 로그인 검증과 DB owner_id·저장된 강사 권한을 사용합니다. 메뉴·본문 role·owner_id는 권한 근거가 아니며, API는 가상 판정 정책으로 인증·소유권 검사를 우회하지 않습니다. 단건 라우팅 복구와 동일 자료 id 선택을 유지합니다.

실행: `npm run test:stage8`, `npm run decider:test`, `npm run fixture:7`.
첫 명령은 기본 decide의 학습 구역 시험과 인증·DB 대체 API 시험을 포함합니다. 제공 fixture 기반 가상 시험 통과는 비공개 심판 시험 통과나 실제 운영 엔진 연결의 증거가 아닙니다.
