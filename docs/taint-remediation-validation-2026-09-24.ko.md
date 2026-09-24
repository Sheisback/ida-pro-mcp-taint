# Taint 수정 검증 현황 — 2026-09-24

이 문서는 수정 **전** 기준선인 `taint-validation-2026-09-24.ko.txt`를 대체하지
않는다. 아래 결과는 이 checkout의 실험적 정적 분석에만 해당하며 취약점 판정이나
전체 ISA 지원 승인이 아니다.

## 확인한 결과

- SDK-free 전체 `PYTHONPATH=src:. uv run pytest -q tests`: **1,647 passed,
  117 subtests passed**. 이 수치에는 acceptance 및 packaged-review 회귀가
  포함된다.
  변경 파일 scoped Ruff, compileall, Pyright(0 errors), `git diff --check`도
  통과했다. 전체 flow 디렉터리 Pyright에는 수정하지 않은 `p0_probe.py`의
  IDA stub `gen_microcode(retlist=None)` 오류 1건이 있다.
- IDA 9.3의 x86_64/arm64 Mach-O O0/O1 네 조합에서, 28개 C 사례를 각각
  정적으로 검사했다. 4개는 ABI 소스 선택 보정이고, 나머지 108개 중
  **90 match, 12 match_partial, 6 inconclusive_partial**이다. 작업 오류와
  소스 선택 실패는 0건이다. 네 입력 모두 원본 hash가 보존됐고 소유
  headless 세션은 `save=False`로 닫았다. 대상 바이너리는 실행하지 않았다.

| 원래 108개 의미 사례 | 수정 전 기준선 | 현행 정적 재검증 |
| --- | ---: | ---: |
| 라벨·범위 일치, 완전한 관측 | 0 | 90 |
| 라벨 일치, 근거 있는 partial | 95 | 12 |
| 라벨 불일치/불확정 partial | 9 | 6 |
| 작업 오류 | 2 | 0 |
| 정확한 소스 선택 불가 | 2 | 0 |

이 표의 `partial`은 오류나 취약점 판정이 아니다. 현행 불확정 6건은
무타입 별칭 4건과 임의 간접 호출 2건이며, 아래 제한에 기록한다.
- 별도 typed Mach-O 네 조합에서는 비계측 Return 관측과 IDB type/argloc
  가정에 묶인 direct identity callee-return 증거를 확인했다. 계측 C
  matrix의 volatile Store 관측을 native Return 증거로 오인하지 않는다.
- 추가한 비계측 Return/ABI matrix는 x86_64·arm64 O0/O1에서 13개
  함수씩 **52건**을 정적으로 확인했다. 8/16/32/64비트 identity,
  상수 반환, 8→32비트 부호·제로 확장, 다중 경로 및 selector control,
  미사용 인자, 포인터 반환, void `Exit`를 구별한다. 타입상 noreturn은
  정상 `Exit`/`Return`으로 꾸미지 않고 `typed_noreturn`과 불완전
  종료로 남긴다. 아홉 번째 stack 인자는 ABI 위치를 추측해 바인딩하지
  않고 `typed_argument_unmapped`와 unknown 반환 출처를 기록한다.
  x86_64의 1바이트 AL/DIL 역매핑은 IDA 9.3의 크기별
  `mreg2reg`→`reg2mreg`가 같은 microregister 바이트를 가리킬 때만
  받아들인다. 각 설정의 바이너리와 dSYM 두 번 빌드가 같은 hash이고,
  대상은 실행하지 않았으며 입력과 세션 종료는 보존됐다.
- 빌드 hash가 정확히 같은 16 normal profile 및 4 format variant를
  IDA 9.3의 두 독립 프로세스에서 각각 다시 추출했고, RV32 fallback은
  기존 정적 capture에서 현재 memory policy를 재평가했다. 전체 semantic
  matrix, frozen profile route, support audit가 일치한다. 지원 범위는
  `unverified` 그대로다.
- 위 extractor 변경 후에도 16 normal + 4 format semantic receipt를 실제
  IDA 9.3의 두 독립 프로세스에서 다시 추출했다. G007 memory 8건과
  G011 call 2건, 공개 sample 9건, BinCAT 및 공개 API/runtime도 각각
  고정된 입력에 대해 재수집했다. Pure replay와 packaged reviewed catalog는
  이 새 실제 snapshot에서 다시 만들었고, 기존 snapshot/hash를 단순히
  현재 구현으로 재라벨하지 않았다.
- G007 memory 8건, G011 call 2건, 공개 path/API/runtime, BinCAT PE/PDB,
  공개 sample 9건의 영향받은 증거를 실제 정적 IDA 경로 또는 명시적
  snapshot-only 파생 경로로 갱신했다. BinCAT의 소스-바이너리 대응은
  계속 `unproven`이다. 해시 문자열만 수정해 native 증거를 대신하지 않았다.
- MCP 별칭 원인 공개 뒤 `BUILD_ID`는
  `flow-build-sha256-v1:d6b972ddb428353c5e2ed2110be23bcfb62e02b3e81f9c1d1eb17169d9113124`다.
  영향을 받은 공개 API/path/reviewed-runtime 영수증을 실제 IDA에서 다시
  수집했고, 전체 1,647개 테스트·지원 감사·scoped Ruff/Pyright·compileall·
  격리 wheel import·disposable IDA `api_flow` 2건을 다시 확인했다.
  기존 `taint_scenarios_native.json`은 수정 전 보존 자료라 덮어쓰지 않았고,
  새로운 112건은 `build/taint-mcp-alias-acceptance-details.json`에 기록했다.
  같은 현재 BUILD_ID로 typed 36건, Return/ABI 52건, 유한 간접 호출 6건,
  output pointer 8건, bit-memory 16건의 실제 IDA probe도 다시 수집했다.
  전부 대상 미실행·입력 보존·`save=False`다. Return/finite fixture의
  두 독립 빌드가 간혹 한 초 차이의 Mach-O `N_OSO` 객체 mtime 때문에
  달라지던 회귀는 linker 입력 객체의 mtime을 0으로 고정해 해결했고,
  재수집에서 두 fixture의 바이너리·dSYM 동일 hash를 확인했다.
  output/bit probe에는 source·helper·runner·builder hash와 compiler·SDK·
  worker IDA/Hex-Rays 환경도 기록해 현재 빌드와 직접 대조했다.

## 남은 partial의 의미

- O0 `pointer_only`, `load_before_store`의 네 불일치는 untyped incoming
  pointer와 현재 stack frame의 교차 객체 별칭을 배제할 증거가 없어
  `cross_object_may_alias`와 `unknown_provenance`로 남는다. 관측된 라벨을
  확정적인 의존성으로 승격하지 않는다. SDK-free 반례 회귀
  `test_untyped_input_may_read_a_current_frame_spill_in_flat_binary_model`은
  입력 숫자 주소가 현재 프레임의 spill slot과 같을 수 있는 flat binary
  모델에서, spill의 X가 포인터 경유 Load/Return까지 가능한 의존성임을
  확인한다. 단순히 분석 순서를 바꾸거나 타입 없는 인자를 no-alias로
  간주해 이 라벨을 지우면 건전하지 않다.
- 사용자가 선택한 기본 정책은 무타입 입력 포인터↔현재 프레임의
  `may_alias_unknown` 유지다. MCP의 `flow_get_memory_analysis` dependency와
  `flow_explain_implicit_analysis` local cause는 해당 쌍에만
  `alias_boundary.reason_code=untyped_input_current_frame_noalias_unproven`,
  `status=unknown`, `alias_relation=may_alias`를 함께 내보낸다. 페이지
  metadata에는 정책과 해당 경계의 전체 개수가 있으므로 첫 페이지에서도
  알 수 있다. 이 표시는 가능한 의존성이지 확정된 흐름 또는 취약점 판정이 아니다.
- Acceptance 검사는 무타입 사례가 나중에 `unknown_provenance=false`의
  정확한 clean으로 바뀌더라도 자동으로 통과시키지 않는다. 해당 결과에는
  해당 포인터의 IDB 타입·argloc binding과 `typed_entry` 객체 증거가
  있어야 하며, 그렇지 않으면 `untyped_alias_promoted_without_proof`로
  실패한다. 현재 네 건은 근거 있는 unknown으로만 수용한다.
- 같은 C 사례를 debug type/dSYM과 함께 추출한 별도 네 조합에서는
  IDB `m_arg`의 포인터 형식 근거를 제공한다. 여기서 typed entry와 현재
  프레임의 no-alias는 타입만으로 증명되지 않는다. 입력 포인터가 유효한
  소스 객체 출처를 따르고 미래의 callee 프레임 주소를 숫자로 위조하지
  않았다는 별도 분석 가정 아래에서만 성립한다. x86_64/arm64 O0/O1 모두 `pointer_only`와
  `load_before_store`의 첫 인자 라벨은 Return에서 사라지고, pointee
  내용은 `possible_uninitialized_memory` unknown으로 남는다.
  `store_then_load`의 X는 네 조합 모두 정확히 유지된다. arm64 O0의
  pointer spill이 두 32비트 entry atom으로 나뉘는 경우도 동일한
  64비트 typed argloc에 속한 연속 조각과 정확한 spill store→load
  근거가 있을 때만 재조립한다. untyped 조각이나 별도 인자 두 개를
  임의로 하나의 포인터로 합치지 않는다.
- IDB argloc만 있고 형식은 정수인 `uint64_t address`를 포인터로 cast한
  대비 함수는 `typed_entry`로 승격하지 않는다. IDA 9.3 x86_64 O0
  정적 관측에서 이 함수의 object는 `argument`+`stack`, 교차 객체
  `may_alias` byte edge는 8개였다. 진짜 포인터 형식 인자의 대비
  함수에서는 `typed_entry`+`stack`, 해당 edge는 0개였다. 따라서
  `m_arg` 존재만으로 현재 프레임 no-alias를 선언하지 않는다.
- O1 `call_indirect` 두 건은 호출 인자로 들어온 임의 함수 포인터의
  완전한 target 집합을 모른다. `call_boundary`/
  `unmodeled_callinfo`의 unknown이므로 clean이나 취약점 판정이 아니다.
- `call_identity`의 네 계측 관측은 source label이 유지된다. typed 네
  조합은 실제 derived return proof를 갖는다. untyped arm64 O1에서는
  IDA의 `CallInfo.arguments=[]` 때문에 그 증거가 없지만, 관측 Store의
  값이 미해결 Call 결과가 아니라 호출 전 입력에서 온다는 독립적인
  caller-bypass 구조 증거를 확인했다. 호출 효과 자체는 partial이다.
- 추가한 동일 바이너리의 **유한 간접 호출**은 x86_64 O1에서 하나의
  `m_icall`과 두 개의 완전한 Phi 후보, arm64 O1에서 분기별 두 개의
  완전한 단일 후보 호출로 관측됐다. 각 후보의 typed scalar Return 증거를
  실제 caller CallResult에 합쳐 입력 X가 유지되고, 상수 반환 후보에서
  X는 제거된다. 높은 32비트만 오염시키면 32비트 인자 반환에 전파되지
  않는다. 상수 반환 후보 사이를 고르는 오염된 selector는 control
  provenance로 Return에 남는다. 입력 함수 포인터가 섞인 불완전 후보는
  known RVA를 기록하더라도 unknown remainder를 유지한다.
  두 아키텍처 모두 바이너리와 dSYM을 두 번 빌드해 각각 같은 hash를
  확인했고, 실제 입력 복사본은 보존됐다.
- 진단 runner는 불확정 partial이 있으면 의도적으로 nonzero를 반환한다.
  별도 `--mode acceptance`는 source/model 사전 조건, label, precision,
  원인, 112건 coverage, 입력 보존을 검증한 뒤에도 결과를
  `bounded_partial`로만 기록하고 지원 범위나 취약점 판정을 승격하지 않는다.

## 이번 계획 밖의 지원 범위

untyped 인자의 current-frame noalias를 증명 없이 가정해서 네 불일치를
거짓 clean으로 바꾸지 않는다. 간접 호출도 위의 완전한 SSA/타입/함수 시작
증거가 있는 최대 8개 scalar 후보에 한정되며, 일반 함수 포인터나
간접 output-pointer write 지원은 주장하지 않는다. 사용자 승인
`unknown`/MCP 설명 계약으로 조정된 P0–P7 수정·검증 범위는 완료했지만,
이는 전체 ISA 지원 또는 공식 배포 준비 완료를 뜻하지 않는다.

## 계획 완료 감사

| 단계 | 현재 증거 | 판정 |
| --- | --- | --- |
| P0 | 18개 partial 행의 원인 설명 모두 비절단; job 오류 reason allowlist·경로 비노출 회귀 | 범위 내 확인 |
| P1 | 기존 7개 xfail 제거, loop 작업 오류 0; scalar/Select/loop 음성 회귀 | 확인 |
| P2 | 실제 IDA 9.3 반환·인자 52건, `mop_a` 배열 4건, 32비트 source 선택 실패 0 | 확인 |
| P3 | seeded byte-memory 재분석, 정상 종료 및 국소/전체 partial 구분; SDK-free/공개 도구 회귀 | 범위 내 확인 |
| P4 | typed 네 설정의 별칭·spill 문제 해결, untyped O0 네 건은 `cross_object_may_alias` unknown; 사용자 승인 기본 unknown과 MCP 원인·객체 쌍 공개를 실제 IDA 9.3 네 설정에서 확인 | 원래 exact 라벨 제거 대신 승인된 보수 계약 확인 |
| P5 | 배열 index 네 native 설정의 두 4-byte 후보·X, 넓은/예산 초과 음성 회귀 | 확인 |
| P6 | direct scalar/output pointer와 완전 유한 간접 후보의 실제 caller SSA/MemorySSA 전파; 임의 `fn` unknown | bounded 범위 확인 |
| P7 | SDK-free 1,647 pass, IDA api_flow 2 pass, 16 normal+4 format 및 영향받은 실제 IDA receipt 재수집, support audit·wheel·Ruff·Pyright·compileall | 범위 내 확인 |

P4의 원래 무타입 exact 라벨 제거 조건은 달성했다고 주장하지 않는다.
타입/출처가 없는 바이너리에서 비별칭을 가정하면 거짓 clean이 될 수 있다.
사용자는 이 경우 **기본 unknown 유지**를 선택했고, MCP에 그 원인을
직접 공개하도록 요청했다. 현재 구현은 네 실제 O0 불확정 관측에서
`alias_boundary`와 객체 쌍을 제공하며, 가능한 라벨을 확정 흐름이나
취약점 판정으로 승격하지 않는다.
