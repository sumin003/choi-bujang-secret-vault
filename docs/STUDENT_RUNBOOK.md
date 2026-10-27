# 케셰브 학생용 실행 설명서 · 21단계

## 목적과 현재 범위

케셰브(KESHEV)는 직원이 본인의 계정·기기·현재 세션, 선택 업무 앱의 접근 판정, 최근 접속 기록과 저장된 XDR 경보를 확인하는 보안 Agent 앱입니다. AI 설명은 참고 정보이며, 제안·접수 응답(ACK)과 실제 조치 효과를 구분합니다. 설치 패키지 조회는 정확한 버전의 OSV 결과와 미조회·부분 실패를 구분합니다.

기존 1~12단계 자료실과 Git 기록을 유지한 채 같은 저장소의 on-client에서 13~20단계 학생 표시 함수를 구현했습니다. 이 문서는 21단계에 새로 작성한 학생 문서입니다. 제공 문서·실행 도구·서버·인증 설정은 수정하지 않았습니다. 코드 작성·커밋·예제 동작이 공식 단계 통과나 실제 연동 성공을 뜻하지 않습니다.

## 지원 환경과 버전

| 항목 | 코드와 확인 근거 |
|---|---|
| 시작 틀 | on-client/package.json: alekov-client-starter, 0.2.14 |
| Node.js | package.json의 기준은 24.19.0. 실행 도구는 주 버전 22~24를 허용. 사용자의 PC 정확한 버전은 미확인 |
| 코드 점검 환경 | AI 작업 환경의 node --version은 v24.22.1. Windows 실행 검증이나 사용자 PC 버전으로 간주하지 않음 |
| Windows·PowerShell | 사용자 제공 화면에서 Windows 경로와 PowerShell 실행을 확인. Windows·PowerShell 세부 버전은 미확인 |
| Git·VS Code | 사용자가 GitHub 복제와 git pull 후 화면 갱신을 보고. 정확한 버전은 미확인 |
| 브라우저 | PC 브라우저로 화면 확인. 브라우저 종류·버전과 다른 운영체제·모바일 동작은 미확인 |

새 PowerShell에서 버전은 다음 명령으로 읽을 수 있습니다. 표시된 값을 실제 실행 환경 기록에 사용하며 추정해서 채우지 않습니다.

~~~powershell
node --version
git --version
$PSVersionTable.PSVersion
~~~

이 실행 설명은 Windows PowerShell용입니다. macOS·Linux의 제공 실행 도구 동작을 확인했다고 주장하지 않습니다.

## 실제 폴더와 코드 경계

사용자가 확인한 프로젝트 위치는 C:\Users\sum\Desktop\방어전\choi-bujang-secret-vault 입니다. 다른 사람은 자신의 실제 프로젝트 위치를 사용합니다.

| 프로젝트 기준 경로 | 역할·작성 구분 |
|---|---|
| README.md, package.json, package-lock.json, api/, public/, src/, xdr/ | 기존 1~12단계 자료실. on-client 실행 명령과 혼동하지 않음 |
| on-client/package.json | 케셰브 실행·문법 검사 스크립트. 외부 npm 의존성 없음 |
| on-client/tools/start-alekov.ps1 | 제공 Windows 실행 도구. 이름 유지 |
| on-client/tools/prepare-native-host.ps1 | 제공 개인 호스트 설정 준비·검사 도구 |
| on-client/public/app.js | 제공 메뉴·조회·입력 검증·새 요청 세대 관리·학생 DOM 교체 |
| on-client/src/server.mjs | 제공 loopback HTTP 서버, API·원천 연결 경계 |
| on-client/src/engine.mjs, student/engine-adapter.mjs | 제공 예제 엔진·기존 접근 제어/XDR 시스템 어댑터. 기본 미연결 |
| on-client/src/connection/, src/ai/ | 제공 계정 승인·앱 AI 승인·보관함·게이트 통신 |
| on-client/src/actions/, src/vulnerabilities/ | 제공 조치 처리 경계와 설치 패키지·OSV 조회 |
| on-client/.env.example | 비밀 없는 설정 견본. 실계정 자격 파일이 아니며 수정하지 않음 |
| on-client/student/extension.mjs | 학생 작성 표시 함수 8개. 서버·인증·정책·조치 실행을 대체하지 않음 |
| docs/STUDENT_RUNBOOK.md | 이번 단계 학생 실행 설명서와 글로 된 구성도 |

on-client에는 별도 package-lock.json이 없습니다. 최상위 잠금 파일은 기존 자료실용입니다. 케셰브 실행을 위해 최상위에서 npm ci를 실행하거나, 새 잠금 파일·node_modules를 임의로 만들 필요는 없습니다. 20단계 조회 대상은 별도 서버 설정에 의해 정해지며, 최상위 잠금 파일이 자동으로 조회 대상이라는 뜻은 아닙니다.

## 기존 작업 보존과 최신 코드 받기

이미 작업 중인 프로젝트나 on-client에 ZIP을 다시 덮어쓰지 않습니다. 새 복제가 필요한 사람만 빈 상위 폴더를 선택해 저장소를 복제합니다. 이미 복제한 사용자는 프로젝트 최상위의 새 PowerShell에서 상태부터 읽습니다.

~~~powershell
cd "C:\Users\sum\Desktop\방어전\choi-bujang-secret-vault"
git status --short
git remote -v
git log -1 --format="%H %s"
~~~

원격 주소는 https://github.com/sumin003/choi-bujang-secret-vault 입니다. Git 최상위·origin·현재 커밋을 실제 출력과 대조합니다. 변경·커밋 준비 중인 파일이 있으면 내용을 먼저 확인하고 보존합니다. 다른 변경을 지우거나 reset --hard로 맞추지 않습니다. 보존을 확인했고 가져오기가 가능한 상태에서만 다음을 실행합니다.

~~~powershell
git pull --ff-only origin main
~~~

분기나 로컬 변경 충돌로 중단하면 임의 초기화·덮어쓰기를 하지 않습니다. 이 명령은 새 문서의 보수적인 갱신 절차로, 사용자 PC에서 이 옵션까지 실행한 결과는 아직 미확인입니다.

## 실행·종료·재실행

### 1. 앱 폴더에서 PowerShell 열기

탐색기에서 프로젝트의 on-client 폴더를 열고 주소 표시줄에 powershell을 입력해 Enter를 누릅니다. VS Code에서는 새 터미널에서 다음을 실행할 수 있습니다.

~~~powershell
cd "C:\Users\sum\Desktop\방어전\choi-bujang-secret-vault\on-client"
~~~

tools/start-alekov.ps1과 package.json이 있는 위치인지 확인합니다. 프로젝트 최상위에서 .\tools\start-alekov.ps1을 실행하면 파일을 찾지 못합니다.

### 2. 공식 기본 실행

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1
~~~

실행 도구는 기존 개인 설정을 검사·재사용하거나 준비합니다. 이 준비만으로 계정 로그인·AI 승인·SDP가 연결되지는 않습니다. 사용자 PC에서는 이 기본 명령이 “계정 연결 설정을 확인하지 못했습니다”로 중단된 이력이 있습니다. 이를 해결됐다고 기록하지 않습니다.

on-client/package.json의 npm start는 node src/server.mjs, npm run demo는 node src/server.mjs --demo입니다. PowerShell 실행 도구의 계정 설정 준비와 시작 확인까지 똑같이 수행하는 명령은 아닙니다. .env.example을 복사했다고 자동 연결되는 것도 아닙니다.

### 3. 예제 화면 확인

다른 서버를 먼저 Ctrl+C로 종료한 뒤 같은 앱 폴더에서 실행합니다.

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -Demo
~~~

사용자가 이 방법으로 예제 화면을 확인했습니다. 연습 사용자·연습 PC·event-01과 학습 자료실(allow)·개발 저장소(deny)·확인할 업무 앱(challenge)은 제공 예제 자료입니다. 실제 로그인·정책·위협 탐지나 조치 성공이 아닙니다. 예제 모드는 계정 연결 준비를 생략합니다.

계정 연결 없이 미연결 화면만 보는 제공 옵션은 -NoNativeHost입니다. 실제 연결 설정 문제를 고치는 옵션은 아닙니다.

### 4. 이미 검증한 개인 설정으로 실행

사용자는 제공 도구의 읽기 검사 결과 ok:true, reused:true를 확인한 개인 설정을 명시하여 앱을 열고 계정 연결을 진행했습니다. 다음 절차는 기존 설정을 검색·삭제·작성하지 않으며 같은 프로젝트 경로에서 계산한 파일이 있을 때만 사용합니다. 설정 경로는 비밀값이 아니지만 파일 내용·자격은 공유하지 않습니다.

~~~powershell
$projectRoot = (Get-Item ..).FullName
$sha = [System.Security.Cryptography.SHA256]::Create()
$projectKey = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($projectRoot.ToLowerInvariant())))).Replace('-','').ToLowerInvariant()
$sha.Dispose()
$hostRoot = Join-Path ([Environment]::GetFolderPath('UserProfile')) ('.aleph-keshev-' + $projectKey)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\prepare-native-host.ps1 -ProjectRoot $projectRoot -HostRoot $hostRoot -ReuseExisting
~~~

-Create를 사용하지 않으므로 준비 도구는 새 설정을 만들지 않습니다. 검사 결과가 ok:true이고 검증한 기존 파일이 있을 때만 실행합니다. 새 PC·옮긴 프로젝트에서는 이 조건이 보장되지 않습니다.

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\start-alekov.ps1 -NativeHostConfig "$hostRoot\native.json"
~~~

이 명령만 새 창에서 따로 실행하면 $hostRoot가 없으므로 앞의 경로 계산·검사가 먼저 필요합니다. 계정 연결은 제공 화면에서 같은 ALEPH 계정·확인 번호를 대조해 승인합니다. AI 연결은 별도 “AI 연결 시작 → 승인 페이지 열기 → 승인 → 승인했으며 연결 확인” 절차입니다. 연결 완료 후에만 현재 API 연결 점검으로 진행합니다. 확인 목적으로 유료 사건 설명을 반복하지 않습니다.

### 5. 시작 신호·브라우저·정지

실행 도구의 시작 확인 문구는 다음과 같습니다.

- 케셰브가 켜졌습니다. 브라우저에서 http://127.0.0.1:5189/ 을 여세요.
- 서버가 응답한 것만 확인했습니다. AI 연결 상태는 화면에서 따로 확인해 주세요.

브라우저에서 http://127.0.0.1:5189/ 을 열고 보호 현황·업무 앱·보안 기록 메뉴를 확인합니다. 코드를 받은 뒤에는 Ctrl+F5로 갱신합니다. 예제 자료·연결 없음·확인 불가는 실제 연결 성공과 구분합니다.

종료는 실행한 서버 터미널에서 Ctrl+C입니다. 재실행은 같은 on-client에서 원하는 모드의 실행 명령을 다시 사용합니다. 브라우저만 닫는 것은 서버 종료가 아닙니다. 다른 프로그램이나 node 프로세스를 일괄 종료하지 않습니다. 포트 5189 사용 중이면 해당 서버가 본인이 실행한 것인지 확인하고, 다른 프로그램이면 그대로 둔 채 제공 옵션 -Port 5190과 브라우저 :5190을 함께 사용합니다. 다른 포트의 사용자 실측은 미확인입니다.

## 글로 쓴 시스템 구성도

아래 점선은 선택적 연동 경로이며 현재 연결 성공을 뜻하지 않습니다.

~~~mermaid
flowchart TD
  B["PC 브라우저: public/app.js·student/extension.mjs"] --> L["로컬 앱 서버: on-client/src/server.mjs"]
  L --> D["예제 엔진: src/engine.mjs · Demo일 때"]
  L -.-> S["접근 제어·XDR: src/engine/sdp-host.mjs"]
  L -.-> A["AI 게이트웨이: src/ai/ · 서버 경유"]
~~~

| 흐름 | 실제 코드와 경계 |
|---|---|
| 브라우저 → 로컬 서버 | GET /api/me, /api/apps, /api/events, /api/devices, /api/sessions. 앱 접근 판정은 제공 UI가 POST /api/access로 요청 |
| 서버 → 접근 제어·XDR 시스템 | src/engine.mjs와 student/engine-adapter.mjs. 명시적으로 준비된 경우 src/engine/sdp-host-config.mjs·sdp-host.mjs 사용. 계정 승인만으로 자동 연결되지 않음 |
| 서버 → 예제 엔진 | -Demo일 때 demoEngine(). 실제 시스템 요청을 대체한 예제 데이터 |
| 계정·AI 승인 | public/ai-connect.mjs → 서버 → src/connection/·src/ai/의 개인 호스트·앱 자격 경계. 개인 설정·보관함은 프로젝트 밖. student/extension.mjs에는 열쇠·확인 티켓을 전달하지 않음 |
| 브라우저 → 서버 → AI 게이트웨이 | 제공 화면의 POST /api/ai/check는 연결·모델 목록 점검, POST /api/ai/explain은 선택 사건 설명. 점검 성공만으로 설명 성공이 아님 |
| 브라우저 → 서버 → OSV | 제공 설치 패키지 조회가 GET /api/vulnerabilities를 요청. src/vulnerabilities/가 잠금 파일·설치 메타데이터와 승인된 공개 패키지 범위를 확인. 공개 출처 https://api.osv.dev/v1/querybatch |
| 진단 | 제공 화면이 GET /api/diagnostics를 조회. 학생 함수는 받은 여섯 필드만 표시·수동 복사 |
| 조치 | 제공 화면·src/actions/가 준비·사람 확인·전달·결과 재조회를 담당. 학생 함수는 상태만 표시. 실제 학생 집행 연결은 UNV |

위 API들은 구현 경로 설명이며 이 문서를 읽는 것만으로 요청을 실행하지 않습니다. 실제 원천 주소·개인 인증서·키·토큰·설정 파일 원문은 적지 않습니다. 서버는 127.0.0.1에 바인딩하며 브라우저가 외부 AI에 열쇠를 직접 보내는 구조가 아닙니다.

## 학생 함수와 제공 기능의 경계

모든 학생 표시 함수는 on-client/student/extension.mjs의 createStudentView()가 반환합니다. document.createElement·textContent로 만들고 제공 public/app.js가 반환 DOM으로 학생 영역을 교체합니다.

| 학생 함수 | 구현한 표시 | 제공 코드가 담당하는 것 |
|---|---|---|
| renderIdentity | me·devices·sessions의 로딩·오류·모드, 사용자·기기·세션 구분 | 인증·조회·입력 검증·새 세대 응답 |
| renderDecision | idle/loading/ok/error, 네 판정·이유·시각 | 앱 목록·선택·접근 요청·실제 판정 |
| renderEvents | 배열 복사·최신순·세 필터·근거/규칙/세 상태 상세, 미지원 비활성 버튼 | 본인 기록 조회·관측 범위·오류 정규화 |
| renderStatus | 빈 목록·실패·알림·진단 여섯 필드와 도움정보 복사 | 진단 조회와 안전한 입력 제공 |
| renderAiConnection | test/verified·모델 수·시각, 오류·수동 재점검 안내 | 앱 승인·권한·게이트·취소·이전 응답 차단 |
| renderExplanation | 현재 기록 근거 대조·규칙·unknown·참고용 설명·미실행 제안 | 실제 AI 호출·서버 검증·취소·사건 결속 |
| renderAction | 준비·전송·ACK·실제 효과·결과 불명 | 티켓 보관·대상 결속·중복 방지·전달·재조회 |
| renderVulnerabilities | 전체/패키지 상태·정확한 버전·OSV 식별자·부분 결과 보존 | 조회 대상·허용 목록·설치 대조·외부 조회·취소 |

수업용 AI는 코드 작성을 돕고, 앱 내부 AI는 사건 설명을 제공하며, ALEPH 공식 판정 AI는 제출 원문을 단계 기준과 대조합니다. 서로 다른 역할입니다.

## 확인 기록과 미확인 항목

아래 모의 점검은 대화 중 AI 작업 환경의 간단한 DOM 대체 구현으로 실행한 점검입니다. 실제 브라우저·공식 판정 결과가 아니며 새 Windows 환경 실행 증거도 아닙니다.

| 구분 | 확인한 내용 | 남은 범위 |
|---|---|---|
| 코드·문법·모의 DOM | 단계별 점검: 13단계 10개, 14단계 15개, 15단계 15개, 16단계 10개, 17단계 20개 및 오류 보완 7개, 18단계 18개, 19단계 19개, 20단계 11개 성공 기록 | 단계별 작성 시점 결과이며 최신 전체에 대한 통합 시험이라고 주장하지 않음 |
| 사용자 예제 화면 | 메뉴 마우스·Tab/Enter, 학습 자료실 allow·개발 저장소 deny·확인할 업무 앱 challenge와 이유·시각 | 실제 정책·앱 접속 성공은 미확인 |
| 사용자 기록 화면 | event-01 상세 근거·규칙·세 상태, 새로고침 후 상세 초기화·키보드 이동 | 실제 여러 기록·실제 AI 설명·기록 전환 경합 미확인 |
| 사용자 상태·진단 | 도움정보 복사 활성·복사, 비밀번호·키·토큰 없음 보고, 다시 불러오기 | 실제 오류 복구·네트워크 반복 여부는 모의/코드 확인과 구분 |
| 사용자 계정·AI | 검증된 개인 설정 재사용, 계정 연결·AI 승인 수행 보고. AI 연결 결과 ALEKOV_CONNECT_OUTCOME_UNKNOWN 유지 | 실제 AI 연결·모델 점검·사건 설명 성공 미확인. 원인 확정 못 함 |
| 사용자 조치 | idle 안내·지원 조치 없음 안내·다시 불러오기 | 실제 집행·대상·권한·결과 재조회는 UNV. 시험 삼아 실행하지 않음 |
| 사용자 패키지 조회 | 제공 PROJECT_NOT_CONFIGURED와 학생 not_configured 일치, 수동 재조회 후 동일 표시 | 실제 설치 버전/해시·OSV 결과·부분 실패·취소 경합 미확인 |
| 21단계 문서 | 실제 코드·파일 경로·실행 옵션을 읽어 대조 | 이 문서만 보고 새 PowerShell에서 처음부터 재현하는 확인은 미실행 |

실제 연결이 불가능한 상태를 성공으로 기록하지 않습니다. 등록 기기는 본인 범위 최대 100개, 세션은 현재 검증된 연결 한 개, 보안 기록은 본인 최근 40건이라는 제공 계약이며 실제 전체 조회 성공을 주장하지 않습니다. XDR은 저장된 경보 조회로 화면을 여는 순간 새 탐지를 하는 것이 아닙니다. 기기 상태 표시는 악성코드 검사·치료가 아닙니다. OSV 결과 없음은 앱 전체 안전 보장이 아닙니다.

## 장애 확인·수동 복구 순서

| 증상·코드 | 확인과 다음 행동 | 성공으로 보지 않는 것 |
|---|---|---|
| -File 대상이 없음 | 현재 폴더가 on-client인지, tools/start-alekov.ps1이 있는지 확인하고 그 위치에서 재실행 | 파일 재다운로드·덮어쓰기로 임의 해결하지 않음 |
| Node 없음·버전 범위 밖 | node --version 확인, 공식 안내의 Node.js 범위 준비 후 새 PowerShell | 사용자 PC 버전을 추정하지 않음 |
| 포트 사용 중 | 본인 서버는 해당 창에서 Ctrl+C. 타 프로그램은 종료하지 않고 -Port 옵션 사용 | 전체 node 강제 종료하지 않음 |
| 계정 연결 설정을 확인하지 못함 | 기존 설정 보존. 위 읽기 검사로 코드·stage 확인. ok:true인 검증 사본만 명시 경로로 실행. 실패하면 담당자 확인 | 설정 삭제·키 복사·권한 검사 완화 금지 |
| ENGINE_NOT_CONNECTED·연결 어댑터 안내 | 기본 미연결인지 확인. Demo는 화면 점검용, 실제 원천 연결은 담당 안내가 있을 때만 사용 | ALEPH 계정 승인과 SDP 원천 연결을 같은 것으로 보지 않음 |
| ALEKOV_CONNECT_OUTCOME_UNKNOWN | 상태 다시 확인은 저장 상태 조회임. 승인 수행 여부와 연결 도움정보의 phase/reason을 확인하고 담당자에게 전달 | 반복 승인·기존 설정 삭제·연결 성공 단정 금지 |
| AI 권한·인증·한도·시간 초과 | 학생 칸의 안전한 code/message 읽기. 권한/한도는 담당자, 이용 시간 확인, 일시 오류는 잠시 뒤 수동 점검 | 모델 목록을 실제 사건 설명으로 간주하지 않음 |
| 설명 근거 불일치·executed:true | 설명을 사용하지 않고 기록을 유지. 원 기록 근거와 오류 코드 확인 | 근거 ID를 만들거나 제안을 실행하지 않음 |
| 조치 unknown | 제공 결과 재조회만 사용. 실제 효과 있음/없음 모두 단정하지 않음 | 새 집행·화면 취소로 효과가 취소됐다는 주장 금지 |
| PROJECT_NOT_CONFIGURED·not_configured | 대상 프로젝트 설정이 없음. 담당 확인 전 그대로 표시 | 취약점 없음으로 간주하지 않음 |
| NO_APPROVED_PACKAGES·not_checked | 승인된 조회 대상이 없는 미조회. 허용 목록을 임의 수정하지 않음 | 비공개 패키지를 외부로 보내지 않음 |
| partial·패키지 unverifiable | 받은 취약점 ID·modified 유지, 전체 조회 미확인으로 표시. 직접 재조회 | 의존성 하향·취약점 재현을 위해 패키지 변경 금지 |
| 조회 취소·오류 | 제공 조회 버튼을 직접 눌러 재요청. 취소·새 세대 뒤 늦은 응답 배제는 코드 확인, 실제 경합 미확인 | 자동 재요청 추가하지 않음 |

코드 오류가 생기면 git status와 diff로 이번 변경과 다른 작업을 구분하고 이전 검증 커밋과 비교합니다. 복구는 확인한 변경만 대상으로 하며 기존 파일·성취·DB·Git 기록을 지우지 않습니다. 서버 재실행은 인증/운영 연동 복구나 조치 효과 취소가 아닙니다.

도움정보는 화면에서 직접 읽은 뒤 필요한 안전한 코드·시각만 공유합니다. 개인 설정 파일은 프로젝트 밖에 유지하고 문서·Git·제출물에 넣지 않습니다. .env를 사용한다면 실제 제외 여부를 확인해야 하며 .env.example은 공개 견본일 뿐입니다. 비밀번호·API 키·토큰·쿠키·개인키 원문을 요구하거나 복사해 제출하지 않습니다.

## 21·22단계 커밋과 원문 제출

21단계 변경은 이 문서와 README의 학생 안내입니다. 같은 커밋에 기록하며 UI·서버는 변경하지 않습니다. 이미 준비 중인 다른 변경이 있으면 먼저 내용을 확인하고 보존합니다. 제출 전 프로젝트 최상위에서 git status와 git log -1 --format="%H %s"로 실제 상태·40자리 커밋을 확인합니다. 문서 안에 미래 커밋 번호를 추정해 쓰지 않습니다.

현재 과제 안내에 따라 21·22단계는 워크벤치의 13~20단계용 포털 제출 준비와 구분합니다. 과제 화면에 저장소 주소와 실제 40자리 커밋을 직접 입력합니다. 비공개 저장소를 공개로 바꿀 필요는 없습니다.

비공개 원문이 필요한 경우 해당 단계의 “비공개 저장소 원문 준비 방법”을 펼쳐 “원문 전달 도구 받기”를 사용합니다. 도구 ZIP과 출력 JSON용 새 폴더는 모두 프로젝트 밖에 둡니다. Git 최상위에서 과제 화면의 student-source-cli.mjs 명령을 실행하고 --commit에 제출할 실제 커밋을 지정합니다. 아직 실제 도구·전체 명령을 제공받지 않았으므로 여기서 옵션이나 명령을 만들어 쓰지 않습니다.

도구는 커밋된 원문만 묶으며 학생 코드 실행·업로드가 아닙니다. 생성한 JSON을 같은 단계의 비공개 저장소 원문 묶음에서 선택하고 저장소·커밋·단계를 다시 확인한 뒤 사용자가 제출합니다. 원문 전달과 AI 검토 통과는 다릅니다. 원문 전달만 실패하면 기존 접수를 유지하고 “원문만 다시 보내기”를 사용합니다. 실제 제출과 공식 판정은 이 문서 작성으로 실행하지 않았습니다.
