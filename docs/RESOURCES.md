# 자료실 자원 ID

자원 종류의 ID는 `src/resources.mjs`의 `RESOURCE_IDS`에 정의합니다.
개별 메모의 UUID와 자원 종류 ID는 서로 다른 용도입니다.

| 자원 | 자원 ID | 주소·자료 보존 |
| --- | --- | --- |
| 메모 | `notes` | 기존 `/api/notes`와 `/api/notes/:id`, 메모 UUID·소유자·본문을 유지합니다. 판정 계약의 기존 서비스 `notes`도 유지합니다. |
| 강사 공지 | `instructor_announcements` | 엔진 경로 `/announcements`와 API `/api/announcements` 및 각 `/:id`로 구분합니다. 서버에 등록된 강사만 자기 공지를 읽기·추가·수정·삭제할 수 있습니다. |

`resourceIdForRequest`는 엔진이 검증한 `service`, `method`, `path`, `route`가 일치할 때만 자원 ID를 반환합니다. 본문·헤더의 자원 ID는 사용하지 않습니다. 불일치와 미지원 경로는 `null`이며 메모로 보완하지 않습니다.

판정기의 경로 검사와 resource_zone 권한 검사에 연결했습니다. 서버의 사용자 연결 표로 로그인 사용자와 엔진 가명 주체를 대응시키고 DB의 소유자·강사 권한을 대조합니다. 화면 메뉴는 변경하지 않습니다.
제공된 요청 계약에 없는 `request.resourceId`·`request.role`은 추가하지 않습니다.
실제 사용자 연결·강사 권한 등록과 배포 검증은 별도 설정이 필요합니다. [연결 방법](RESOURCE_ZONE_SETUP.md)에 기록했습니다.
