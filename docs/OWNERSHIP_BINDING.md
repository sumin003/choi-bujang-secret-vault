# 판정기 소유권 연결

등록 함수 register_learning_resource_subject는 SQL Editor의 DB 운영자만 사용합니다. anon·authenticated·service_role의 함수 실행 권한을 회수했습니다. 일반 자료 API는 이 등록 함수를 호출하지 않습니다.

함수 입력은 검증된 classId·projectId·subjectId와 인증 계정 이메일입니다. 이메일은 DB에서 사용자 UUID를 찾을 때만 쓰며 코드나 Git에 실제 계정 값을 넣지 않습니다. 계정이 없거나 중복이면 거부하고, 기존 subjectId를 다른 사용자에게 재연결하지 않습니다. 기존 메모·소유자·강사 권한은 변경하지 않습니다.

엔진의 검증된 대응 정보가 확보되면 운영자가 A/B 각각 등록합니다. 이후 판정기의 기본 authorizeResource를 createResourceAuthorizer로 연결해 저장된 대응과 메모 owner_id를 대조합니다. 두 계정의 대응을 먼저 검증하지 않고 이 경로를 활성화하면 정상 요청도 거부될 수 있습니다.

등록 함수만 설치했으며 실제 사용자 대응 행은 아직 등록하지 않았습니다. 기본 판정기의 정상 메모 구역 허용 복구와 최종 API의 소유권 검사는 유지합니다. 아직 판정기 자체의 실제 A/B 소유권 구분이 완료된 것은 아닙니다.
