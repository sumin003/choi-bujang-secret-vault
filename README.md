# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 11단계 저장점

BYTE BACK 가상 자료실에 설치형 웹앱 manifest와 아이콘, 오프라인 안내, 기기 승인 요청·결과 화면을 추가했습니다. 설치 표시만으로 승인하지 않습니다. 별도 접속 프로그램·휴대전화·보안 키 등록은 요구하지 않습니다.

### 운영자가 승인하는 브라우저 등록

두 번째 참고 방식에 따라 쿠키는 브라우저 등록 기록을 찾는 용도로만 사용합니다. 기기 개인키·패스키는 만들지 않고 HttpOnly·Secure·SameSite=Strict 쿠키를 발급하며 서버에는 원본 대신 SHA-256 해시를 저장합니다. 요청 버튼은 `pending`만 생성합니다. 운영자가 SQL Editor에서 요청 번호와 사용자를 확인한 뒤 한 건을 승인합니다. 앱 서버 키는 승인 상태를 INSERT·UPDATE하거나 승인 함수를 실행할 수 없습니다. 대기 요청은 DB 잠금으로 사용자당 최대 5건입니다.

화면과 메모·공지·복원 API는 같은 서버 승인 서비스를 사용합니다. 서버가 사용자·브라우저 대응·운영자 승인 기록·만료를 검사해 허용합니다. 승인 전에는 자료가 없고, 승인 후 기존 본인 메모 기능을 엽니다. 취소·만료·다른 사용자·다른 브라우저는 자료 없는 JSON 403 `DEVICE_NOT_APPROVED`, DB 장애는 JSON 503, 미로그인은 JSON 401입니다. 기존 소유권·공지 권한 검사도 유지합니다. 승인·취소와 감사 기록은 같은 DB 트랜잭션으로 처리합니다.

심판용 `src/decider.mjs`의 `device_registered` 규칙은 별도로 유지합니다. 웹앱의 운영자 승인 서비스가 이 판정기 규칙을 호출하거나 반 엔진과 연결됐다고 주장하지 않습니다. 판정기의 18항목 입력·5항목 응답·기존 규칙은 변경하지 않았습니다. 브라우저 쿠키가 도난당하면 같은 사용자 인증과 함께 악용될 수 있으며 하드웨어에 묶인 기기 인증이 아닙니다.

### 설치·오프라인·로그인

manifest의 앱 이름은 BYTE BACK 자료실이며 시작 주소·독립 창·기존 아이콘을 유지합니다. `public/sw.js`는 오프라인 안내와 아이콘만 저장합니다. `/api` 요청·로그인 응답·메모는 가로채거나 저장하지 않습니다. 오프라인이면 열린 보호 화면을 닫고 안내를 표시하며, 오프라인 탐색 시 `public/offline.html`을 보여 줍니다. 설치 표시는 승인 증거가 아닙니다.

공식 Supabase SDK를 `persistSession: false`, `detectSessionInUrl: false`로 사용합니다. Auth 요청은 기존 서버 중계 경로를 이용하며 서버 전용 키와 Supabase 공개 키는 화면에 넣지 않습니다. 로그인·갱신 토큰은 브라우저 실행 메모리에만 유지하고 localStorage·sessionStorage·IndexedDB·쿠키에는 넣지 않습니다. 이전 로그인 쿠키는 서버가 만료시키고 SDK 저장 항목은 값을 읽지 않고 삭제합니다. 새로고침·창 종료 후 다시 로그인하지만, 별도 브라우저 등록 기록은 30일 만료 전까지 유지하므로 운영자가 매번 승인할 필요는 없습니다. 사용하지 않는 기존 서버 세션 테이블과 DB 자료는 삭제하지 않았습니다.

### 확인 순서와 결과

설정·승인·취소는 [운영자 안내](docs/BROWSER_OPERATOR_GUIDE.md)와 [SQL](docs/BROWSER_OPERATOR_APPROVAL.sql)을 따릅니다. 로그인 → 기기 승인 요청 → 운영자 SQL 승인 → 승인 결과 확인 → 본인 메모 CRUD → 운영자 취소 → 다음 요청 403 순서로 확인합니다. 다른 브라우저에서는 승인 전 자료가 없어야 합니다.

실행: `npm run test:stage11 && npm run decider:test && npm run build -- --local`. 로컬 11단계 시험 12건은 승인 전 차단·요청만으로 승인 불가·운영자 승인 뒤 본인 자료 허용·취소 거부·메모리 로그인·API 응답 캐시 제외를 확인했습니다. 기존 8~10단계 시험도 통과했습니다. DB 권한 분리·운영자 승인/취소·감사·5건 제한을 실제 학습 DB에서 확인한 뒤 시험 행을 롤백했습니다(`test/browser-registration-db.sql`). 실제 사용자 배포 로그인·승인·휴대폰 설치 시험은 미실행이며 심판 통과 증거가 아닙니다.

`aleph.config.json`의 step은 11입니다. GET/POST /api/device 및 기존 허용 경로·배포 주소·로그인 발급자·judgeIssuer·원본 API 주소를 보존합니다.

## 10단계 작업 기록

정책 복원은 [RESTORE_PREVIEW.md](docs/RESTORE_PREVIEW.md)의 격리된 시험 폴더에서만 수행합니다. 저장소에는 9단계 기준 커밋에 고정한 정책 파일 해시 사본만 둡니다. `npm run restore:preview`는 매번 사본의 자체 해시, 기준 커밋의 존재·현재 커밋 조상 여부, 기준 커밋에서 다시 읽은 정책 파일 해시를 확인한 뒤 복원 버전과 변경 경로를 표시합니다. 검증에 실패하거나 사본이 없으면 중단합니다. 이 미리보기는 읽기 전용이며 운영 정책을 쓰지 않습니다. 정책 원문·키는 사본·미리보기·감사 기록에 넣지 않습니다.

### 비공개 가상 메모 한 건 복원

| 서비스 | 메서드·정확한 경로 | 동작 |
|---|---|---|
| notes | POST /api/restore-notes/preview | 본인 사본의 ID·해시와 예정 변경 한 건 확인 |
| notes | POST /api/restore-notes | 확인한 사본으로 지정한 메모 한 건 복원 |
| notes | POST /api/restore/notes/:id | 설정에 등록된 호환 복원 경로; ID는 경로에서 받고 본문에 ID를 중복 전달하지 않음 |

aleph.config.json의 step은 10이며 allowedRoutes에 세 경로를 기록했습니다. restoreRoute는 심판 경로 형식인 "/api/restore/notes/:id"입니다. 기존 주소·로그인 발급자·judgeIssuer·원본 API와 이전 허용 경로를 유지합니다. 화면 메뉴와 기존 메모 CRUD는 변경하지 않습니다.

로그인은 기존 src/verify-login.mjs로 검증합니다. 서버가 확인한 사용자 UUID와 비공개 사본·남아 있는 메모의 owner_id를 대조합니다. UUID와 원래 숫자 ID를 대조하고, UUID·소유자·제목·본문으로 계산한 SHA-256도 확인합니다. 사전 확인 뒤 시험 메모가 바뀌면 거부합니다. 본문 owner_id·userId·role·새 메모 내용은 받지 않습니다. 소유자 변경이나 여러 메모 복원도 허용하지 않습니다.

사본은 learning_backup.note_copies에 두고 public 폴더·Git·브라우저 파일에는 보관하지 않습니다. RLS와 권한 회수로 PUBLIC·anon·authenticated의 직접 접근을 막았습니다. 서버 역할은 사본 SELECT만 가능하며, 복원 RPC는 서비스 역할만 실행합니다. 복원과 learning_backup.note_restore_audit의 감사 기록 추가는 같은 트랜잭션입니다. 감사 기록을 쓸 수 없으면 메모 변경도 롤백합니다. 다른 메모와 이전 감사 행은 수정·삭제하지 않습니다. 새 감사 기록에도 원문·토큰·키는 넣지 않습니다. 스키마는 [note-restore.sql](docs/note-restore.sql)에 기록했습니다.

확인 순서:

1. B로 로그인한 뒤 비공개 검증 사본이 있는 본인 메모의 UUID를 선택합니다. Authorization 값은 공유하거나 기록하지 않습니다.
2. POST /api/restore-notes/preview에 JSON {"id":"선택한 메모 UUID"}를 보냅니다. 응답의 id·backupId·contentSha256·currentSha256·operation을 확인합니다. 원문은 응답하지 않습니다.
3. 확인한 backupId·contentSha256·currentSha256 세 항목을 POST /api/restore/notes/{id}에 보냅니다. 메모 ID는 URL의 `{id}`에 넣고 본문에 중복 전송하지 않습니다. 정상 결과는 200과 restored: true입니다. 이후 기존 본인 메모 GET 경로로 내용을 확인합니다.

검증 사본이 없으면 RESTORE_SOURCE_NOT_FOUND와 404로 중단합니다. 미검증 사본·내용 해시 불일치·사전 확인 뒤 변경은 409로 거부합니다. 로그인이 없거나 검증에 실패하면 JSON 401이며 복원 DB 함수를 호출하지 않습니다. 사본을 자동 생성하거나 미검증 사본을 임의로 검증 완료로 지정하는 API는 없습니다.

### 복구 뒤 1~9단계 회귀 확인 순서

아래 순서는 복구 기능을 추가한 뒤 이전 단계의 허용·거부 동작을 다시 확인할 때 사용합니다. 로컬 자동 시험과 배포에서 직접 보낸 요청을 구분해 기록합니다. 테스트 계정·토큰·메모 본문은 로그나 공유 메시지에 남기지 않습니다.

1. 저장소 루트에서 `npm install` 후 `npm run build -- --local`을 실행합니다. 빌드가 끝나면 생성된 배포 파일에서 `/aleph.json`이 있고 `/data.json` 및 가상 메모 문장이 없는지 확인합니다. 첫 화면 응답의 `X-Content-Type-Options: nosniff`도 확인합니다.
2. `npm run test:r5`를 실행한 다음 로그인·메모 API를 확인합니다. 로그인 없이 `GET /api/notes`를 보내 JSON 401/403이 오는지 확인하고, 로그인한 A와 B가 각각 자기 목록·단건 조회·추가·수정·삭제를 할 수 있는지 확인합니다. 반대 계정의 UUID로 단건 GET·PUT·DELETE를 보내면 자료가 나오지 않고 404여야 합니다. 요청 본문의 `owner_id`·`userId`·`role`을 바꿔도 소유권이 바뀌지 않아야 합니다.
3. `npm run decider:test`를 실행합니다. 등록 기기의 정상 요청은 허용되고 미등록 또는 등록 상태 누락 요청은 `deny`·`device_not_registered`여야 합니다.
4. 7단계 가상 사건을 `npm run fixture:7`로 실행합니다. 정상 사건은 `allow`, 정해 둔 복합 이상 사건은 `step_up`이어야 합니다. 실제 재로그인 계약이 확인되지 않았으므로 새 로그인 뒤 허용 여부는 미실행으로 둡니다.
5. `npm run test:stage8`을 실행합니다. 자기 메모의 허용 경로와 지정한 단건 자료 동작은 유지되고, 전체 목록을 판정기에서 여는 요청, 다른 소유자의 자료, 학생의 공지 수정, 알 수 없는 경로는 거부되어야 합니다.
6. `npm run test:stage9`와 `npm run detect:test`를 실행합니다. 정상 가상 사건과 복합 의심 사건이 구분되고, 복합 의심에만 대상 기기와 이유 코드가 있는 `propose_revocation`이 나오는지 확인합니다. 정상 사건에는 제안이 없어야 합니다. 실제 기기 권한 회수는 미실행으로 둡니다.
7. 복구 기능의 로컬 회귀 시험으로 `npm run test:stage10`을 실행합니다. B의 가상 메모 한 건을 복원한 뒤 A의 자기 메모 조회는 허용, B의 A 메모 조회는 `resource_zone`·404로 거부, B의 복원 메모 조회는 허용되는지 확인합니다. 정책 시험도 복원 직후 A의 GET·PUT·DELETE 허용과 B의 같은 요청 거부를 확인합니다. ID·소유자·내용 해시 불일치·미검증 사본은 거부되어야 합니다. 이 통합 시험은 합성 사본을 사용하므로 실제 백업에서 복원한 증거로 기록하지 않습니다.
8. 위 명령을 통과한 뒤 배포된 커밋에서 로그인·메모 API의 정상·금지 요청을 다시 확인합니다. 로컬 시험 통과와 배포 실측을 구분해 기록합니다.

2026-10-14 로컬 회귀 확인: `npm run test:r5` 2건, `npm run decider:test`, `npm run fixture:7`, `npm run test:stage8` 20건, `npm run test:stage9` 26건, `npm run detect:test` 6항목, `npm run detect:device-test` 14항목, `npm run test:stage10` 28건 및 `npm run build -- --local`이 통과했습니다. stage10 통합 시험은 메모 복원 뒤 A 자기 조회 허용, B의 A 메모 조회 404 거부, B의 복원 메모 조회 허용과 정책 복원 뒤 B의 A 메모 요청 거부를 확인합니다. 배포에서 실제 A/B로 보낸 요청, 실제 침해 전 검증 사본에서의 복원 및 실제 안전 정책을 운영 환경에 적용하는 시험은 미실행입니다.

2026-10-14 학습 DB에서 실제 시험 계정 B 소유의 임시 가상 메모 한 건으로 수정 복원·삭제 후 재생성·소유자 거부·해시 불일치·미검증 사본·사전 확인 뒤 변경·감사 실패 시 메모 롤백을 확인했습니다. 서버 역할로 RPC를 실행했고 다른 메모와 이전 감사 이력의 불변을 비교했습니다. [B용 롤백 시험](docs/note-restore-test-b.sql)의 결과 12항목은 모두 true였으며 시험 메모·사본·추가 감사 행·임시 권한 변경은 전부 롤백했습니다. 기존 메모 7건을 유지합니다.

로컬 npm run test:stage10 28건, 기존 test:stage8 20건·test:stage9 26건과 build -- --local이 통과했습니다. 이 결과는 로컬 시험과 DB 통합 시험이며, 배포 주소에서 실제 B 로그인으로 POST한 증거는 아닙니다. 시험 후 보관된 검증 사본은 0건입니다. 운영용 복원은 신뢰할 수 있는 검증 사본을 따로 준비한 경우에만 가능합니다. 침해 전 안전 정책 사본의 존재나 실제 운영 정책 복원 완료도 주장하지 않습니다. 다시 실행: npm run test:stage10. 아래는 이전 저장점 기록입니다.

## 9단계 저장점

### 제공된 탐지 계약 호환성 복구

c8f918624009의 제출에서 복합 의심 사건에 propose_revocation이 없다는 결과를 받았습니다. 제공된 원본 사건은 at·method·identity.sub뿐인데 구현이 네트워크·기기·등록 정보를 필수로 요구해 121건·200건 사건을 observe로 돌려줬습니다. 원본 시험 여섯 항목을 변경 없이 복원하고, 세 항목 입력에서는 계약의 propose_revocation·burst_read·subject를 반환하도록 복구했습니다. 원본에 없는 네트워크나 기기 ID를 만들어 채우지 않습니다. subject와 실제 회수 기기를 대조하는 엔진 연결이나 집행을 완료했다고 주장하지 않습니다.

확장 네트워크·기기 입력에는 기존 복합 조건과 확인 기기 한 개 제한을 유지하며 npm run detect:device-test로 별도 검사합니다. 제공 원본 npm run detect:test 6항목, 확장 기기 시험 14항목, npm run test:stage9 26건과 기존 판정기 연습·로컬 빌드가 통과했습니다. 원본 시험이 구현에 맞춰 바뀌지 않았는지도 검사합니다. 회수 API·권한 변경은 추가하지 않았습니다. 새 커밋의 심판 결과는 재제출 후 확인합니다. 아래는 c8f918624009 당시 기록입니다.

GitHub의 eea9d9cb38c4(8단계 저장점)을 기준으로 탐지 입력과 복합 의심 규칙을 추가했습니다. 입력은 가명 사용자·기기·요청 종류·판정과 시각·필요한 가상 신호만 선별합니다. 비정상 가상 네트워크에서 10분 내 GET 120건 초과가 나타난 확인 기기 한 개에만 별도 propose_revocation·burst_read·deviceId 결과를 반환합니다. 정상은 observe, 확인 기기를 특정할 수 없는 복합 의심은 alert입니다. 실제 회수 API·권한 변경·경과 시간 측정은 구현하지 않았습니다. 확장 사건 형식의 심판 호환성과 실제 회수·시간 확인은 심판 검증 대상입니다. 자세한 형식은 [DETECT_EVENTS.md](docs/DETECT_EVENTS.md)를 따릅니다.

aleph.config.json의 step을 9로 올리고 기존 배포 주소·발급자·허용 경로·originalApiUrl·judgeIssuer는 유지했습니다. src/decider.mjs의 기존 18항목 요청·5항목 응답과 RULE_IDS는 변경하지 않았습니다. 계약 밖 role·identity·device 등의 값을 읽지 않는 검사와 JSON 직렬화 후 응답 형식·규칙 ID 검사를 추가했습니다. 단계 9에서 제출 자기 점검이 실행되도록 src/attack-check.mjs도 맞췄습니다.

2026-10-14 Node v24.19.0에서 npm run test:stage9의 23건, test:stage8의 20건, detect:test의 14항목, decider:test와 로컬 빌드가 통과했습니다. 패키지와 잠금 파일의 의존성 버전은 그대로 유지했습니다.

다시 실행: Node 22 이상에서 npm install → npm run test:stage9 → npm run decider:test → npm run detect:test → npm run build -- --local. 탐지 연습 출력에서 정상 observe 유지와 확인 기기 대상·이유 코드가 있는 회수 제안을 확인합니다. 브라우저 로그인·본인 메모 화면과 기존 자료는 보존합니다. 아래는 이전 단계 기록입니다.

## 8단계 저장점

### 전체 목록·공지 쓰기 구역 거부 보완

fb3c68aeb877의 심판 결과에서 GET /notes 허용이 구역 규칙 위반으로 지적됐습니다. 엔진 판정기의 GET /notes·GET /api/notes 전체 목록 요청을 resource_zone으로 거부하고, 역할 항목이 없는 엔진 계약에서 공지 쓰기(POST·PUT·PATCH·DELETE)는 모든 주체에게 거부하도록 수정했습니다. 가상 강사 이름이나 별도 소유자 확인으로 이 거부를 우회할 수 없습니다. 기존 단건 메모·기기·추가 확인·단독 로딩 규칙을 유지합니다.

화면의 실제 메모 목록은 별도 HTTP 진입점과 본인 owner_id 필터를 유지합니다. API의 로그인·소유자·저장된 강사 권한 검사, 기존 자료·주소·화면 메뉴는 변경하지 않았습니다. 다시 실행: npm run decider:test 및 npm run test:stage8. 2026-10-13 단독 로딩과 판정기 연습 여섯 항목, 8단계 시험 20건·기존 서버/XDR 시험 9건·로컬 빌드가 통과했습니다. 인증·DB 대체 시험에서 본인 API 목록이 유지되고 상대 메모가 반환되지 않는 것도 확인했습니다. 새 커밋의 심판 결과는 재제출 후 확인합니다. 아래는 앞선 저장점 기록입니다.

### 판정기 격리 로딩 복구

77a3fd9322a9 제출에서 판정기를 불러오지 못했다는 결과를 받았습니다. 저장소 전체의 decider:test는 통과했지만 판정기 한 파일만 불러오는 시험은 상대 경로 import에서 실패했습니다. 자원 경로·소유권 정책을 src/decider.mjs에 모으고 기존 보조 파일은 같은 정의를 다시 내보내도록 변경했습니다. 판정기에는 import가 없으며 로딩 시 서버 환경변수·fetch·DB에 접근하지 않습니다. 서버 설정과 네트워크 기능은 실제 저장소 조회 요청 시에만 확인하고, 사용할 수 없으면 접근을 거부합니다. 실제 API의 공통 소유권 판정과 최종 소유자 필터, 기존 기기·추가 확인 규칙을 유지합니다.

확인 순서: npm run decider:test → npm run test:stage8 → npm run build -- --local. decider:test도 판정기 소스만 단독으로 불러오도록 바꿔 상대 경로 import가 다시 생기면 실패하게 했습니다. 2026-10-13 판정기 단독 로딩과 연습 네 항목, 8단계 시험 19건, 기존 서버/XDR 시험 9건, 로컬 빌드가 통과했습니다. 추가한 시험은 판정기 소스만 별도 프로세스에서 불러오며 보조 파일·패키지·process·fetch·URL 없이 본인 허용, 타인 거부, 미등록 기기 거부, 추가 확인을 검사합니다. 이는 로컬 격리 재현이며 심판 재제출 결과는 별도 확인해야 합니다. 아래는 앞선 저장점 기록입니다.

### 실제 자료 API의 판정기 연결

메모·공지 API가 서버에서 로그인 검증으로 얻은 실제 사용자 UUID를 판정기 모듈의 decideAuthenticatedResource에 전달하도록 연결했습니다. 실제 DB의 소유자와 저장된 강사 권한을 대조하며, 가상 정책으로 실제 API를 허용하지 않습니다. 최종 API의 소유자 필터와 검사를 추가로 유지합니다. 별도 엔진 ID 대응 없이 실제 API 요청의 소유권 규칙을 수행하고, 기존 엔진용 18항목 계약과 기기·추가 확인 규칙은 변경하지 않습니다. API에 없는 엔진·기기 정보를 만들어 채우지 않습니다.

응답의 X-Resource-Decision·X-Resource-Rule·X-Resource-Reason 헤더로 실제 서버 구역 판정을 확인할 수 있습니다. 사용자 ID·토큰·메모 본문·키는 기록하지 않습니다. 2026-10-13 8단계 시험 18건과 기존 시험 9건, 기기·추가 확인 연습 및 로컬 빌드가 통과했습니다. 인증·DB 대체 API 시험에서 판정기 연결과 허용·거부 헤더를 확인했으며, 실배포 A/B 전체 시험은 아직 실행하지 않았습니다. [HTTP_RESOURCE_DECIDER.md](docs/HTTP_RESOURCE_DECIDER.md)의 순서로 확인합니다. 아래 내용은 앞선 구현 기록입니다.

### 가상 구역 정책 보완

제공된 원본 fixture의 /notes/demo와 learner_fixture를 명시적 자원 정책으로 등록했습니다. 기본 decide가 소유자의 정상 요청을 허용하고 다른 가상 사용자의 같은 자료 요청을 resource_zone으로 거부합니다. 학생 공지 수정 거부와 등록된 가상 강사의 자기 공지 수정 허용도 검사합니다. 가상 정책은 지정한 반·프로젝트·judge_fixture에만 적용하며 실제 계정으로 승격하지 않습니다.

2026-10-13 `npm run test:stage8`의 18건, 기존 XDR·서버 시험 9건, decider:test·fixture:7·로컬 빌드가 통과했습니다. 정상 사건 allow, 복합 사건 step_up을 실제 export된 decide로 확인했습니다. 실제 메모·공지 API의 로그인·소유권·저장된 강사 권한 검사, 단건 조회 복구, 기존 자료·주소·화면 메뉴를 유지합니다. 자세한 구분은 [STAGE8_VIRTUAL_POLICY.md](docs/STAGE8_VIRTUAL_POLICY.md)에 기록합니다. 비공개 심판의 내부 요청과 실배포의 전체 권한 흐름을 확인한 결과는 아닙니다. 아래는 앞선 저장점 기록입니다.

정상 메모 판정 복구(9fd5308)와 단건 메모 조회 라우팅 복구(ae22b5e)를 포함한 저장점입니다. 메모·공지 자원 ID, 기기·추가 확인·정확한 경로 검사, 메모 API 소유자 검사 및 공지 API의 저장된 강사 권한 검사를 유지합니다. 동적 라우팅의 동일 자료 id만 허용하고 기능 쿼리·서로 다른 id·중복 id는 거부합니다. 기존 자료·주소·화면 메뉴는 보존합니다.

2026-10-13 관련 가상 시험 9건이 통과했습니다. 사용자는 단건 조회·수정 불러오기 복구와 B의 A 메모 UUID 조회 거부를 확인했습니다. 이는 사용자 확인이며 도구의 실계정 전체 CRUD 검증과 구분합니다.

판정기의 기본 메모 구역 검사는 정상 경로를 허용하고, 실제 소유권은 최종 API가 검증된 사용자 UUID와 DB owner_id로 제한합니다. 판정기 자체의 A/B 소유권 구분은 미완료입니다. 사용자 연결 등록 함수는 설치했지만 실제 엔진 사용자 연결은 0건입니다. 엔진의 검증된 대응 정보가 확보되기 전에는 연결을 추측하거나 정상 요청을 다시 차단하지 않습니다. 자세한 상태는 [OWNERSHIP_BINDING.md](docs/OWNERSHIP_BINDING.md)에 기록합니다.

다시 실행: `node --test test/resource-zones.test.mjs test/xdr-gate.test.mjs`. 배포 후 자기 메모 불러오기·수정과 타인 메모 거부를 확인합니다. step 8, 기존 배포 주소·발급자·허용 경로·원본 API·judgeIssuer를 유지합니다.

## 8단계 저장점 (d03f0cb 당시 기록)

메모·공지 자원을 구분하고 판정기에 resource_zone을 추가했습니다. 서버의 사용자 연결·소유자·강사 권한 정보를 조회해 허용하며 정보가 없으면 거부합니다. 기존 기기·추가 확인 규칙과 메모 자료·주소·화면은 보존합니다. 공지 API는 /api/announcements 및 /api/announcements/:id에 추가했습니다.

2026-10-13 가상 자원 구역 시험 3건과 기존 기기·추가 확인 연습이 통과했습니다. 학습 DB에 사용자 연결·강사 권한·공지 표를 생성하고 RLS 및 브라우저 직접 권한 회수를 확인했습니다. 기존 메모 7건을 보존했으며 새 표에는 권한이나 자료를 임의로 넣지 않았습니다. 실제 운영 사용자 연결과 강사 권한 등록·배포 시험은 미실행입니다.

확인 명령: `node --test test/resource-zones.test.mjs`. 연결 방법과 실측 범위는 [RESOURCE_ZONE_SETUP.md](docs/RESOURCE_ZONE_SETUP.md)를 따릅니다. 7단계까지의 기록은 아래에 보존합니다. 설정의 step을 8로 맞췄으며 제출 점검은 가상 판정과 실제 HTTP 요청 결과를 구분합니다.

## 7단계 저장점

2026-10-13 docs/DECIDER_REQUEST.md와 제공된 서버·시험 코드를 확인했습니다. stepUp의 verified·authAgeSeconds 형식은 있지만, 같은 로그인 주체가 추가 확인 요청 이후 다시 로그인했음을 검증하고 자료 요청을 재개하는 엔진 절차는 제공된 파일에서 확인되지 않았습니다. 이 두 값만으로 실제 재로그인 연결 완료를 기록하지 않습니다.

가상 신호 judge_fixture에서 GET 요청·23~05시·unusual 네트워크·최근 120초 내 risk_signal 20건 이상이 함께 나타나면 step_up·step_up_required를 반환합니다. 지역 하나만으로 영구 차단하지 않고 기존 device_registered 거부를 먼저 유지합니다. 접속 정보의 누락·불명확한 출처를 정상값으로 채우지 않습니다.

npm run fixture:7 실행 결과는 정상 사건 allow, 복합 이상 사건 step_up입니다. npm run decider:test에서는 등록 정상 요청, 미등록 기기 거부, 복합 사건 추가 확인, 가상 stepUp 확인 후 허용 네 항목이 통과했습니다. 가상 verified 입력을 이용한 연습이며 실제 재로그인 시각 확인 증거가 아닙니다.

설정의 step은 7이며 기존 배포 주소·발급자·허용 경로·원본 API·judgeIssuer를 유지합니다. 다시 실행: `npm run fixture:7` 및 `npm run decider:test`.

실제 자료 차단과 새 로그인 뒤 자료 요청 재판정은 미실행입니다. 자료실 API·로그인 화면은 변경하지 않았고 토큰 원문은 기록하지 않았습니다.

## 6단계 저장점

src/decider.mjs의 device_registered 규칙은 엔진이 전달한 request.deviceRegistered가 true인 요청만 기존 판정으로 진행시킵니다. false이거나 값이 없으면 deny·device_not_registered와 규칙 ID device_registered를 반환합니다. 등록 기기라도 기존 신원·요청 형식·허용 경로 검사를 통과해야 허용됩니다. 인증서·CA·서명 키를 새로 만들지 않았습니다.

확인 순서:
1. 저장소 루트의 터미널에서 `npm run decider:test`를 실행합니다. 이번 과정에는 따로 설치할 접속 프로그램이 없습니다.
2. 출력의 “통과 · 등록 기기의 정상 요청”과 “통과 · 미등록 기기의 가상 요청”을 확인합니다.
3. 등록 기기의 정상 요청은 allow·approved, 미등록 기기의 가상 요청은 deny·device_not_registered여야 합니다. 미등록 요청의 ruleIds는 ["device_registered"]입니다.

2026-10-13 위 명령을 실제 실행해 두 항목 통과를 확인했고, 판정기를 직접 호출해 등록 요청 allow·approved와 미등록 요청 deny·device_not_registered를 대조했습니다. 이는 로컬 가상 요청 연습이며 실제 접속이나 심판 통과 증거가 아닙니다. 실제 미등록 기기 공격의 확인은 심판이 맡습니다. 설정의 step을 6으로 변경했고 기존 자료실 주소·브라우저 화면·로그인 발급자·허용 경로·원본 API 주소·judgeIssuer는 유지합니다. 제출 묶음의 직접 HTTP 점검은 실행 결과만 기록하며 접근 제한이나 통신 오류는 미확인으로 남깁니다. 브라우저에서 기기 상태를 위조하거나 실제 공격을 수행하는 절차는 포함하지 않습니다.

## 보너스 xdr-02 저장점

2026-10-12 `npm run xdr:run -- web-injection`를 다시 실행해 xdr/web-injection/result.json을 갱신했습니다. 경보 26건의 counts는 block 8 · alert 9 · record 9이며 정상 이벤트 9건 중 block은 0건입니다. 실행 오류는 없었습니다.

read-alerts.mjs는 다섯 항목만 추출하고 비밀값처럼 보이는 내용을 가립니다. 원본 26건과 추출 26행이 일치합니다. patterns.json에는 T1190 및 CWE-89·79·22·78 근거가 있는 SQL·스크립트·경로 이동·명령 주입 패턴을 기록했습니다. 독립형 decide.mjs에 패턴을 상수로 복사했으며 import·파일 입출력·네트워크 호출 없이 action/confidence/reason을 반환합니다. 단발 시도·단순 구분 문자·교육용 예시를 자동 차단하지 않습니다.

respond.mjs는 decide의 명확한 차단 후보만 15분 만료·근거 경보 번호를 가진 주소 거부 규칙으로 저장하고 xdr/alerts.log에 한 줄씩 기록합니다. 정상 이벤트가 함께 있는 공유 주소는 차단 대신 알림으로 낮춥니다. 실제 src/decider.mjs 기본 판정기에 거부 검사만 추가하는 createConnectedDecider를 제공하며 기존 로그인 공격 검사 뒤에 연결할 수도 있습니다. 기존 기본 규칙·로그인 공격 모듈·원본 경보·자료실 기능을 변경하지 않았습니다.

실제 기본 판정기에 로그인 공격 검사와 웹 주입 검사를 연결한 로컬 재생 시험: 명확한 공격 8건 거부, 애매한 시도 9건 알림 및 통과, 정상 9건 통과. 만료 해제·공유 주소 보호·기존 거부 유지·민감한 원문을 로그에 남기지 않는 검사 2건이 통과했습니다. 학습용 재생 결과이며 실제 운영 공격 차단이나 심판 통과 결과가 아닙니다. 과거 경보로 만든 해당 시험 시점의 활성 웹 주입 규칙은 0건입니다. 웹 주입 검사 부품을 만들었으며 자료실 서버의 기존 XDR 검사 경로는 변경하지 않았습니다.

다시 실행: `npm run xdr:run -- web-injection`. 연결 시험: `node --test test/xdr-web-respond.test.mjs`. 결과 counts와 판정 배열의 건수가 같고 정상 이벤트는 record여야 합니다.

## 보너스 xdr-01 저장점

2026-10-12 `npm run xdr:run -- brute-force`를 다시 실행해 result.json을 갱신했습니다. block 10 · alert 9 · record 9이며 정상 이벤트 9건 중 block은 0건입니다.

src/decider.mjs에 엔진의 18개 항목 요청 계약, 등록 기기, 허용 메모 경로, 신원 필드 형식, 요청 시각 및 세션 확인 형식이 정상일 때만 허용하는 verified_request.allow 규칙을 추가했습니다. 기존 starter.deny는 조건 불충족 요청의 거부 규칙으로 보존했습니다. 요청 본문의 userId·role·IP처럼 계약 밖의 필드는 거부합니다. 새 허용 규칙은 이번 사용자 승인에 따라 추가했으며 XDR 자체가 허용을 대신하지 않습니다.

connected-decider.mjs는 실제 src/decider.mjs의 기본 판단에 XDR 거부 검사만 추가합니다. replay.mjs의 가짜 허용 판정기를 제거하고 실제 기본 판정기 코드로 요청을 검사합니다. 출발 주소는 시험의 별도 서버 연결 문맥에만 두며 18개 항목 요청에 추가하지 않습니다. 응답은 다섯 항목이고 RULE_IDS에 구현된 세 규칙만 기록했습니다. 거부 사유는 기존 starter_not_ready, 정상 허용은 approved를 사용합니다.

실제 기본 판정기를 사용한 로컬 재생 결과: 공격 10건 거부 · 애매한 시도 9건 통과 및 알림 · 정상 9건 통과. 만료 후 해제, 기존 거부 유지, 미등록 기기·허용되지 않은 경로·오래된 요청·추가 신원 필드 거부, 공유 주소 보호, 원본 경보 보존을 확인했습니다. 관련 시험 10건이 통과했습니다. 외부 연결은 이번 완료 기준에 포함하지 않습니다. 학습용 재생을 운영 공격 차단이나 심판 통과로 기록하지 않습니다.

로그인·메모 API의 추가 XDR 검사 연결도 유지합니다. 배포용 활성 규칙은 0건이며 시험 규칙은 임시 경로에서만 사용합니다. 기존 로그인·소유자 검사와 DB 자료는 변경하지 않았습니다.

다시 실행: `npm run xdr:run -- brute-force` / 연결 검사: `node xdr/brute-force/replay.mjs` / 관련 시험: `node --test test/xdr-decider.test.mjs test/xdr-gate.test.mjs test/xdr-run.test.mjs`.

## XDR 보너스: 로그인 공격 분류와 서버 추가 검사

- xdr/brute-force/read-alerts.mjs는 원본 경보 28건에서 다섯 항목만 추출하고 비밀값처럼 보이는 필드를 가립니다. 원본 경보는 변경하지 않습니다.
- patterns.json의 MITRE T1110 근거를 독립형 decide.mjs 상수로 복사했습니다. 파일 입출력·네트워크·import 없이 block/alert/record와 확신도·패턴 이름을 반환합니다.
- respond.mjs는 주소·계정별 3분 시간창으로 중복 경보 번호를 제외해 집계한 뒤 같은 decide 함수를 호출합니다. 입력 count는 겹치지 않는 실패 묶음이어야 하며 누적 집계 경보는 먼저 정규화해야 합니다. 명확한 후보만 15분 만료형 IP 거부 규칙으로 저장하고 근거 경보 번호를 기록합니다. 정상 로그인 근거가 있는 공유 주소는 차단 대신 알림으로 낮춥니다.
- src/xdr-gate.mjs를 로그인 /api/auth와 메모 /api/notes 및 /api/notes/:id 서버 경로에 연결했습니다. Vercel 환경의 x-vercel-forwarded-for 주소만 사용하며 브라우저 본문·일반 전달 헤더를 주소 근거로 사용하지 않습니다. 로컬에서는 TCP 연결 주소만 사용합니다. 기존 로그인·소유자 검사를 유지하며, src/decider.mjs에는 정상 허용 규칙을 추가하고 기존 starter.deny를 조건 불충족 요청의 거부 규칙으로 보존합니다.
- 운영용 live 규칙만 서버가 검사합니다. 차단 시 403 JSON XDR_BLOCKED, 정상 주소는 기존 서버 검사로 진행하며, 활성 규칙이 없으면 X-XDR-Check: no-active-rules 응답 헤더를 붙입니다. 시험용 replay 규칙은 배포에 포함하지 않습니다.
- 시험에 사용한 가상 경보는 과거 시각이므로 배포용 deny-rules.json은 rules: []입니다. 규칙 파일은 배포에 포함되는 스냅샷입니다. 새로운 규칙을 배포에 반영하려면 신뢰할 수 있는 경보로 respond를 실행하고 검토 후 재배포해야 합니다. 실행 중인 Vercel의 파일을 수정하거나 Wazuh 실시간 수집이 연결됐다고 기록하지 않습니다.
- 로컬 검증: 읽기 28건=28행, result.json block 10/alert 9/record 9, 정상 오차단 0건. 재생 연결에서 공격 10건 거부·애매 9건 및 정상 9건 통과, 공유 주소 보호·만료 해제 통과. 서버 경로 시험에서 차단 주소가 Auth/DB에 도달하지 않고 정상 CRUD와 미로그인 401이 유지됨을 확인했습니다. 이 결과는 가상 입력과 상위 서버 대체 시험이며 실제 공격 트래픽 차단 증거가 아닙니다.
- connected-decider.mjs는 실제 기본 판정기의 정상 허용을 유지하고 공격 주소만 추가로 거부합니다. 실제 기본 판정기 연결 재생이 통과했으며, 외부 연결은 이번 과제의 완료 기준에서 제외합니다.

실행: `npm run xdr:run -- brute-force` / 연결 재생: `node xdr/brute-force/replay.mjs` / 서버 검사 시험: `node --test test/xdr-gate.test.mjs`.
배포 확인: 브라우저 개발자 도구 Network에서 로그인·메모 API의 응답 헤더 X-XDR-Check를 확인합니다. 메모 요청 헤더의 토큰과 로그인 본문을 공유하지 마세요.

## 5단계 저장점

메모 CRUD는 기존 서버 함수와 로그인·소유자 검사를 유지합니다. public.learning_notes의 PUBLIC·anon·authenticated 직접 권한을 회수했고 service_role 권한과 네 RLS 정책을 유지했습니다. originalApiUrl에는 쿼리 없는 원본 HTTPS 경로를 기록했습니다. step은 5이고 allowedRoutes의 메모 GET·POST·PUT·DELETE 경로와 nosniff 설정은 유지합니다.

화면에는 Supabase 공개 키가 없습니다. 공식 SDK의 로그인·세션 갱신·사용자 확인·로그아웃 요청은 /api/auth 서버 함수를 거치며 서버가 환경변수의 SUPABASE_URL과 SUPABASE_SECRET_KEY를 사용합니다. SDK가 세션을 관리하며 비밀번호나 JWT를 직접 생성하지 않습니다. 서버 키와 상위 서버 오류 원문은 응답·로그에 넣지 않습니다.

다시 실행: `npm run build -- --local`. 배포 후 로그인 → 자기 메모 CRUD → 새로고침 → 로그아웃을 확인하세요. 틀린 비밀번호는 화면 오류, 상대 메모는 404, 미로그인 메모 요청은 401 JSON이어야 합니다. 로그인 실패가 새 서버 경로 때문에 발생하면 이 로그인 변경만 되돌립니다. 2026-10-11 사용자 브라우저 확인: 실제 배포에서 메모 읽기·추가·수정·삭제가 정상 동작함을 확인했습니다. 이 결과는 사용자 확인이며 도구의 모의 검증과 구분합니다.


저장점 확인: step 5, 메모 allowedRoutes 5개, originalApiUrl의 쿼리 없는 HTTPS 경로, Supabase identityProvider와 기존 judgeIssuer를 확인했습니다. Auth 중계와 화면 세션·CRUD·로그아웃 모의 검증은 통과했고 앞선 코드 변경 배포의 READY를 확인했습니다. 해당 단계 배포의 보안 헤더·aleph.json 직접 응답과 정적 메모 문장 검색은 도구로 재확인하지 못했습니다. src/attack-check.mjs는 아직 1단계용이며 npm run bundle은 실행하지 않았습니다. 아래 이전 단계의 미확인 기록은 당시 상태이며 5단계 CRUD 확인 결과는 위 사용자 확인 기록을 따릅니다.

## 4단계 저장점 (과거 기록)

- 기존 Supabase SDK 로그인·로그아웃과 토큰 검증 도우미를 유지합니다. 메모 API는 검증된 사용자 ID로 목록·단건 읽기·수정·삭제의 owner_id를 제한합니다. 추가·수정에서 브라우저가 보낸 소유자 값은 사용하지 않습니다.
- 기존 가상 메모 네 건을 A에 연결하고 B의 공개 가능한 시험 메모 한 건을 DB에 보존했습니다. 메모 본문과 계정 정보는 이 기록에 포함하지 않습니다.
- public.learning_notes에 RLS 및 네 소유자 정책을 적용했습니다. SELECT·DELETE는 USING, INSERT는 WITH CHECK, UPDATE는 USING과 WITH CHECK에서 auth.uid() = owner_id를 검사합니다.
- 적용 전후 information_schema.role_table_grants와 has_table_privilege 확인: anon은 모든 테이블 권한 없음, authenticated는 SELECT·INSERT·UPDATE·DELETE만 허용하며 TRUNCATE·REFERENCES·TRIGGER는 거부됩니다. 다른 테이블은 변경하지 않았습니다.
- aleph.config.json의 step 4, 실제 배포 주소, Supabase issuer·authenticated audience·JWKS, GET·POST·PUT·DELETE 경로를 구현과 대조했습니다. judgeIssuer와 판정기의 starter.deny 규칙은 유지합니다.
- 최신 API 코드의 모의 시험에서 A/B 자신의 CRUD 허용, 상대 단건 GET·PUT·DELETE 404, 소유자 위조 무시, 미로그인 목록 401 JSON을 확인했습니다. 사용자는 B에서 A UUID 조회가 거부되는 화면을 확인했습니다. 실제 배포 A/B 전체 CRUD는 미확인입니다.
- 빌드 스크립트는 public/data.json만 제거하고 배포 시 public/aleph.json을 생성합니다. vercel.json의 전체 경로 nosniff 설정을 확인했습니다. 해당 단계 배포의 직접 HTTP 확인은 실행 환경 접근 차단으로 미확인입니다.
- 서버 비밀키는 RLS를 우회할 수 있으므로 API 소유자 검사를 유지해야 합니다. 최신 정적 파일·배포 자산의 네 메모 문장 검색은 미확인입니다. 옛 공개 커밋·배포에 남은 자료가 회수되었다고 단정하지 않습니다.
- 제출 묶음은 이번 저장점에서 실행하지 않았습니다. src/attack-check.mjs는 여전히 1단계용이며 후속 제출 전 갱신이 필요합니다.

해당 단계의 주소: https://choi-bujang-secret-vault-mocha.vercel.app
다시 실행: `npm run build -- --local`. 배포 화면에서 A/B 각각 로그인 → 자기 메모 목록 → 추가 → UUID 불러오기 → 수정 → 삭제를 확인합니다. 상대 UUID의 읽기·수정·삭제는 404, 미로그인 /api/notes는 401 JSON이어야 합니다. 로그아웃하면 화면 메모가 사라져야 합니다.

아래 1~3단계 내용은 당시의 작업 기록이며 위 내용은 4단계 기록입니다.

## 3단계 저장점 (과거 기록)

- 이메일·비밀번호 로그인 및 로그아웃은 Supabase 공식 SDK를 사용합니다. 자료 API는 기존 src/verify-login.mjs로 토큰을 검사하며, 미로그인·검증 실패 시 메모 없는 401 JSON 오류를 반환합니다.
- 로그인 사용자의 메모 목록과 UUID 기반 추가·단건 조회·수정·삭제를 구현했습니다. 새 owner_id는 서버가 검증한 사용자 ID입니다. 삭제 후 단건 조회는 404입니다.
- step은 3이며 실제 저장소·배포 주소, Supabase 발급자·대상·JWKS 주소와 GET·POST·PUT·DELETE 경로를 설정과 대조했습니다. judgeIssuer 및 기존 판정기 starter.deny 규칙은 유지합니다.
- 기존 가상 메모 네 건의 소유자를 A로 바꾸거나 A 목록에 강제로 표시하는 작업은 이번 저장점에 포함하지 않습니다. 기존 DB 자료는 보존하며 원래 소유자에 맞춰 목록을 표시합니다.
- 단건 소유자 검사는 아직 없습니다. B가 A의 UUID를 알면 조회·수정·삭제할 수 있으며 4단계에서 보완합니다. 옛 공개 커밋·배포의 과거 노출도 해소되었다고 단정하지 않습니다.
- API·화면 모의 시험과 DB UUID 보존 확인을 수행했습니다. 실제 A/B 계정의 전체 CRUD와 해당 단계의 배포 응답·메모 문장 검색은 미확인입니다. src/attack-check.mjs는 아직 1단계용이며 제출 묶음은 생성하지 않았습니다.

해당 단계의 주소: https://choi-bujang-secret-vault-mocha.vercel.app
다시 실행: `npm run build -- --local`. 화면 새로고침 → 로그인 → 새 가상 메모 추가 → 수정 → 삭제 순서로 확인합니다. 미로그인 /api/notes는 401 JSON, 삭제된 UUID의 GET은 404여야 합니다. /aleph.json 생성과 nosniff 설정은 유지합니다.

## 3단계 진행: 가상 메모 CRUD

로그인 사용자는 화면에서 가상 메모를 추가·불러오기·수정·삭제할 수 있습니다. 목록 응답은 서버가 검증한 사용자 ID의 메모 배열이며 새 메모 owner_id도 그 ID로 저장합니다. 요청의 owner_id·userId·role은 믿지 않습니다. 새 메모가 없다면 빈 목록이 정상입니다. 기존 네 자료는 원래 소유자 값과 숫자 ID를 보존했습니다.

| 경로 | 계약 |
| --- | --- |
| GET /api/notes | 로그인 사용자의 메모 배열 [{id,title,body}] |
| POST /api/notes | {id?,title,body}, UUID 생략 시 서버 생성, 201 {id} |
| GET /api/notes/:id | 200 {id,title,body}, 없거나 삭제된 UUID는 404 |
| PUT /api/notes/:id | {title,body}, 200 {id,title,body} |
| DELETE /api/notes/:id | 삭제 성공 204, 이후 GET 404 |

실제 메서드·경로를 aleph.config.json의 allowedRoutes에 기록했습니다. UUID는 기존 숫자 PK를 바꾸지 않고 learning_notes.note_id에 저장하며 API body는 기존 content 열에 연결합니다. docs/notes-api-schema.sql은 적용된 스키마 변경입니다. 기존 로그인 검증 도우미와 RLS는 변경하지 않았습니다.

**4단계에서 고칠 허점:** 단건 GET·PUT·DELETE는 로그인만 검사하고 소유자를 검사하지 않습니다. B는 A의 UUID를 알면 A의 메모를 읽거나 수정·삭제할 수 있습니다. 목록을 사용자별로 제한하는 것만으로 단건 소유권이 보호되지는 않습니다.

검증: API 경계 모의 시험에서 인증 거부·서버 owner_id·UUID 생성·단건 조회/수정/삭제·삭제 후 404·B→A 수정을 확인했습니다. DB UUID 추가 후 기존 네 건 보존과 고유 UUID를 확인했습니다. DB CRUD 트랜잭션 시험은 도구 오류로 미확인이며 후속 조회는 기존 네 건과 시험 자료 0건입니다. 실제 A/B 계정 및 실배포 CRUD 시험은 미확인입니다.

실행 명령: npm run build -- --local. 배포 화면에서 로그인 → 제목·내용 입력 → 메모 추가 → 수정 → 수정 저장 → 삭제를 확인하세요. 삭제된 UUID를 ID로 불러오면 없는 메모 안내가 나와야 합니다. 로그인하지 않은 요청은 401이어야 합니다.

## 3단계 진행: 자료 API 토큰 검증 (이전 작업 기록)

3단계 당시 /api/notes는 기존 src/verify-login.mjs의 createLoginVerifier로 Authorization 토큰을 검사합니다. 토큰이 없거나 검증에 실패하면 HTTP 401과 LOGIN_REQUIRED만 반환하고 자료를 읽지 않습니다. 브라우저가 보낸 userId·role은 사용하지 않습니다. 로그인 SDK의 세션 토큰만 요청 헤더에 보내며 로그아웃 즉시 화면의 메모를 지웁니다.

aleph.config.json은 step 3이고 identityProvider에는 Supabase issuer·authenticated audience·JWKS 공개 주소만 기록했습니다. judgeIssuer는 유지했습니다. 3단계 당시 목록은 로그인 사용자 소유 메모만 반환하며, 단건 소유자 검사는 아직 구현하지 않았습니다.

확인 방법: 사이트 새로고침 → A 로그인 시 A 소유 메모 목록 표시 → 로그아웃 시 메모 제거. 비로그인 /api/notes 직접 요청은 401이어야 합니다. 모의 검증에서 API 거부·허용 분기를 확인했으며 실제 A 계정과 실배포 응답 검증은 미확인입니다. 아래 1~2단계 기록은 과거 상태입니다.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계에서는 `/data.json`으로 가상 메모가 공개되었습니다. 2단계 당시에는 `/` 화면이 `/api/notes`를 호출하고 서버가 Supabase의 `learning_notes`에서 가상 메모 ID 1–4를 읽습니다. `/data.json`은 더 이상 배포하지 않습니다. 접수와 심판 판정은 포털에서 확인합니다.

## 2단계 당시 실행과 보안 한계

Vercel 프로젝트 Settings → Environment Variables의 비밀 입력란에 `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`를 직접 설정한 뒤 해당 환경으로 다시 배포하세요. 실제 값은 코드, Git, 브라우저 파일, 로그, 응답, 제출 묶음에 넣지 않습니다. 서버는 키를 환경변수에서만 읽고, 응답에는 가상 메모의 `id`, `title`, `content`만 반환합니다. 소유자 ID와 원본 오류는 반환하지 않습니다.

**서버 API는 아직 공개되어 있습니다.** 로그인이나 사용자별 권한 검증이 없으므로 누구나 `GET /api/notes`로 가상 메모 네 건을 읽을 수 있습니다. 서버 전용 키는 RLS를 우회하므로 DB의 RLS만으로 이 공개 API가 보호되지는 않습니다. 이 단계는 키와 정적 메모 파일 노출을 줄이는 작업이며, 접근 제한은 이후 단계에서 구현합니다. 실제 비밀 자료를 저장하지 마세요.

실행 명령: `npm run build -- --local`. 이 명령은 정적 파일 정리만 수행하며 서버 API는 Vercel 배포에서 확인합니다. 배포 주소를 열고 브라우저 새로고침을 누르면 가상 메모 네 건이 보여야 합니다. `/aleph.json`은 `step: 2`와 실제 커밋을 표시해야 합니다. `/data.json`은 404, `POST /api/notes`는 405여야 합니다. 환경변수가 없으면 API는 503, DB 요청 오류는 세부 정보 없이 502를 반환합니다.

기존 `src/attack-check.mjs`는 1단계 전용이며 2단계 자기 점검은 아직 구현하지 않았습니다. 로컬 시험이나 배포 확인을 심판 판정으로 해석하지 않습니다.


## 최신 파일과 해당 단계 배포의 메모 문장 확인 절차

이 절차는 **확인 대상 커밋과 배포의 정적 파일**에 가상 메모 본문이 포함되어 있는지 확인합니다. 화면에 카드 네 개가 보이는 것은 서버 API가 반환한 결과이며, 정적 파일에 본문이 들어 있다는 뜻은 아닙니다. 실제 메모 문장을 README, 검색 예시, Git, 제출 묶음이나 공유 로그에 복사하지 마세요.

1. GitHub 저장소의 최신 `main` 커밋 SHA를 기록합니다. Vercel에서 그 커밋의 배포가 `READY`인지 확인한 뒤 해당 단계의 배포 주소의 `/aleph.json`을 열어 `commit`이 같은 SHA이고 `step`이 2인지 확인합니다. 서로 다르면 같은 버전을 확인한 것으로 기록하지 않습니다.
2. 다른 작업을 보존하기 위해 새 폴더에 최신 저장소를 내려받습니다. 그 폴더에서 `git rev-parse HEAD`로 SHA를 확인하고, 가상 메모 네 건의 본문에서 식별 가능한 문장을 하나씩 선택해 각 문장을 아래 명령으로 검색합니다. 이는 확인 대상 HEAD의 추적 파일 전체를 검색하며 Git 이력은 검색하지 않습니다. 입력 문장은 명령 자체나 Git 파일에 넣지 않고, 일치한 문장 본문도 출력하지 않습니다.

   ```bash
   IFS= read -r -p '검색할 가상 메모 문장: ' note_sentence
   if [ -n "$note_sentence" ]; then
     git grep -l -F -e "$note_sentence" HEAD -- .
   fi
   unset note_sentence
   ```

   파일명이 출력되면 해당 최신 파일에 문장이 남아 있는 것입니다. `git grep`의 종료 코드 1은 일치 없음이며, 1 이외의 오류는 검색 완료로 기록하지 않습니다. 네 메모 모두 검색해야 합니다.
3. 해당 단계의 배포 화면에서 브라우저 개발자 도구 → Network를 열고 캐시를 끈 뒤 새로고침합니다. 메모 카드 네 개가 표시되고 `/api/notes` 요청이 성공하는지 확인합니다. 공개 키를 이용한 별도 요청의 판정은 심판 확인 범위입니다.
4. 같은 배포의 `/data.json`을 직접 엽니다. **HTTP 404이며 가상 메모가 없어야 합니다.** 빈 화면만으로 판정하지 말고 Network에서 상태 코드와 응답 본문을 함께 확인합니다. 403, 로그인 화면, 통신 오류는 파일 제거 확인으로 인정하지 않습니다.
5. Network의 문서(HTML), JS, CSS와 `/aleph.json` 응답을 열어 같은 네 문장을 각각 검색합니다. 추가 정적 파일과 소스맵이 있다면 그것도 확인합니다. 렌더링된 Elements 화면이나 `/api/notes` 응답에는 메모가 보이는 것이 이 단계의 정상 동작이므로 정적 파일 검색 결과와 구분합니다. 파일이 없다는 추측이나 API 응답 검색으로 정적 자산 검색을 대신하지 않습니다. JSON 이스케이프나 인코딩된 문자열은 읽을 수 있는 형태로 확인하고, 확인하지 못한 자산은 미확인으로 남깁니다.

결과에는 확인 시각, 커밋 SHA, 배포 주소, 검색한 정적 파일 목록, 네 문장의 일치 유무, `/data.json` 상태 코드만 기록합니다. 메모 본문과 키는 기록하지 않습니다. 모든 항목을 실제 확인했을 때만 “확인한 최신 파일과 해당 단계 배포의 정적 파일에서 검색한 가상 메모 문장이 발견되지 않았다”고 씁니다.

최신 파일에서 삭제하거나 새 배포에서 `/data.json`을 제거해도 옛 공개 커밋과 옛 배포 URL의 자료는 자동으로 없어지지 않습니다. 옛 공개 커밋과 옛 배포가 남아 있는 한 과거 노출은 남아 있으며, 이미 복사·다운로드된 자료도 회수됐다고 단정할 수 없습니다. 2단계 당시 서버 API도 아직 공개되어 있으므로 이 확인은 전체 메모 비공개나 보안 완성을 의미하지 않습니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.

## 2단계 저장점

해당 단계 기능: 서버 API로 가상 메모 네 건 조회, 정적 data.json 제거, step 2 배포 식별 파일 생성, nosniff 헤더 설정. 서버 환경변수는 Vercel에만 저장합니다.

2026-10-10 사용자 브라우저 확인: /data.json은 404, /aleph.json은 step 2 및 커밋 919429268cefbdb4428c6fbc2d3a32110dfe74f7 표시, 첫 화면 응답은 nosniff 표시. 카드 네 개 표시는 앞선 사용자 확인이며 환경변수 재배포 이후 재확인은 미기록입니다. 도구의 직접 HTTP 점검은 접근 오류로 미확인입니다. 최신 파일과 배포 자산의 네 메모 문장 검색 결과는 미확인입니다. 공개 키 요청은 심판 확인 범위입니다.

해당 단계의 주소: https://choi-bujang-secret-vault-mocha.vercel.app · 저장소: https://github.com/sumin003/choi-bujang-secret-vault

다시 실행: npm run build -- --local. 실제 서버 확인은 배포 주소 새로고침으로 수행합니다. 제출 묶음은 npm run bundle로 생성하며 bundle-notes.json과 artifacts/submission.json은 Git에 포함하지 않습니다. 아직 공개 API에는 로그인·권한 검증이 없으며 옛 공개 커밋과 옛 배포의 과거 노출도 남아 있습니다.
