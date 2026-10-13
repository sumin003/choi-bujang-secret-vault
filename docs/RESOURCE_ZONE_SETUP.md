# 8단계 자원 구역 연결

- 메모: `notes`, 기존 `/api/notes` 및 `/api/notes/:id`.
- 공지: `instructor_announcements`, `/api/announcements` 및 `/api/announcements/:id`.
- UUID를 자료 ID로 사용하고 기능 선택 쿼리와 `/export` 같은 기능 경로를 거부합니다. 화면 메뉴는 변경하지 않습니다.

판정기는 엔진이 검증한 기존 18항목만 받습니다. 메모 소유권은 최종 API에서 확인합니다. 공지 사용자 연결은 서버 DB의 `learning_resource_subjects`에서 반·프로젝트·가명 사용자 ID를 검증된 로그인 사용자 UUID와 연결해 조회합니다. `subjectId`를 Supabase UUID라고 가정하지 않습니다. 공지의 등록되지 않은 연결은 거부합니다.

`learning_instructors`의 `(identity_kind,user_id)` 행에서 `enabled=true`인 사용자만 강사 권한을 가집니다. 강사도 본인이 소유한 공지만 수정할 수 있습니다. `judge` 토큰의 검증 결과를 강사 권한으로 자동 승격하지 않습니다. 클라이언트의 role·owner_id·메뉴는 권한 근거가 아닙니다.

운영자는 서버에서 검증된 엔진의 classId·projectId·subjectId와 실제 인증 사용자 ID의 대응을 확보한 뒤 연결 표에 등록해야 합니다. 추측한 ID나 실제 계정·권한 데이터를 Git에 넣지 않습니다. 강사 권한 등록도 운영자가 별도로 합니다. 새 권한 표와 공지 표는 빈 상태로 생성했으며 기존 메모는 변경하지 않았습니다.

SUPABASE_URL·SUPABASE_SECRET_KEY는 기존 서버 환경변수만 사용합니다. 세 새 테이블은 RLS를 켜고 PUBLIC·anon·authenticated의 직접 권한을 회수했습니다. 외부 사용자가 연결·강사 권한을 변경하는 API는 제공하지 않습니다.

시험: `node --test test/resource-zones.test.mjs`.
인증·DB를 대체한 가상 시험에서 자기 메모 허용·상대 메모 거부·학생 공지 수정 거부·등록된 강사 자기 공지 수정 허용·권한 위조 거부를 확인합니다. `npm run decider:test`와 `npm run fixture:7`도 서버와 분리된 가상 권한 연결로 연습합니다. 이 가상 연결은 운영 판정기의 기본 권한으로 사용하지 않습니다.

실제 배포와 운영 엔진 연결·A/B 실계정 HTTP 시험은 미실행입니다. 공지 판정은 서버 DB의 권한 연결이 없거나 조회에 실패하면 거부합니다. 메모 구역의 정상 판정 복구는 유지하며, 판정기 자체의 메모 소유권 연결은 미완료입니다. API는 기존 메모 소유자 검사를 독립적으로 유지합니다. 판정기의 구역 거부는 계약에 있는 starter_not_ready 사유와 resource_zone 규칙 ID를 반환하며, 자료 API는 짧은 instructor_required·not_found_or_not_owned 사유를 반환합니다.
