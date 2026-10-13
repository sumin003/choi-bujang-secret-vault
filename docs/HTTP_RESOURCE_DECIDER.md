# 실제 자료 API의 소유권 판정 연결

실제 메모·공지 API는 로그인 검증 후 src/decider.mjs의 decideAuthenticatedResource를 호출합니다. 이 진입점은 서버의 createLoginVerifier가 검증한 identity.userId·kind와 API가 확인한 서비스·메서드·정확한 경로를 사용합니다. 요청 본문의 사용자·role·owner_id는 전달하지 않습니다.

판정기는 공통 checkVerifiedResource 규칙으로 실제 DB의 owner_id를 비교합니다. 공지는 learning_instructors에 저장된 활성 강사 권한도 확인합니다. 메모의 소유자 불일치·없는 자료는 deny이며 조회·수정·삭제 전에 API가 중단합니다. 본인 요청은 allow로 진행하고, 최종 API의 원자적 owner_id 필터와 반환 행 검사도 유지합니다.

이 경로는 실제 사용자 UUID를 이미 검증했으므로 엔진 가명 subjectId와의 별도 연결 표가 필요하지 않습니다. 가상 자원 정책도 사용하지 않습니다. 엔진용 decide(request)의 18항목 입력·5항목 응답과 기존 기기·추가 확인 규칙은 보존합니다. API에는 없는 deviceRegistered·엔진 subjectId·stepUp 값을 만들어 넣지 않습니다. HTTP 진입점의 결과는 별도 aleph.resource.decision.v1 형식이며 엔진의 전체 기기·재인증 판정이 수행됐다는 의미는 아닙니다.

배포 후 브라우저 F12 → Network → 메모 요청 → Response Headers에서 확인합니다.

| 결과 | 헤더 |
| --- | --- |
| 자기 메모 판정 허용 | X-Resource-Decision: allow / X-Resource-Rule: resource_zone / X-Resource-Reason: owner_verified |
| 타인 메모 또는 없는 메모 거부 | X-Resource-Decision: deny / X-Resource-Rule: resource_zone / X-Resource-Reason: not_found_or_not_owned |
| 학생 공지 수정 거부 | X-Resource-Decision: deny / X-Resource-Reason: instructor_required |

목록은 verified_collection 사유로 진행하고 실제 DB 쿼리는 본인 owner_id로 제한합니다. 로그인·경로·본문 검사에서 먼저 실패한 요청에는 구역 판정 헤더가 없을 수 있습니다. 헤더는 구역 판정의 관측값이며 HTTP 상태도 함께 확인합니다. 사용자 UUID·토큰·본문·키는 헤더나 로그에 기록하지 않습니다.

검증: npm run test:stage8와 기존 서버/XDR 시험. 실제 API 함수가 판정기 모듈을 호출하는 상태에서 인증·DB를 대체해 소유자 허용/거부와 헤더를 검사했습니다. 실제 배포의 A/B 로그인 전체 시험은 배포 후 확인해야 합니다. 브라우저 요청의 Authorization이나 로그인 본문은 공유하지 않습니다.
