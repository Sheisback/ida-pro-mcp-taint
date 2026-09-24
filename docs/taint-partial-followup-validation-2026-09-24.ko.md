# 남은 taint partial 후속 수정 검증 — 2026-09-24

이 문서는 `docs/taint-remediation-validation-2026-09-24.ko.md`의 후속이며,
원본 `tests/flow_fixtures/taint_scenarios.c`를 바꾸지 않았다. 분석은 모두
IDA 9.3의 disposable 복사본에서 정적으로 수행했고 대상은 실행하지 않았다.

## 이번에 바뀐 것

| 사례 | 수정 전 | 이번 수정 후 |
| --- | --- | --- |
| `call_identity` | 반환 X는 이미 확인됐지만 callee의 실제 전역 쓰기를 모르는 호출 메모리 havoc | 동일 바이너리·namespace·정확한 함수 시작점, 유일한 고정 전역 Store, 인자/상수 및 정확한 zero-extension·한 단계 current-stack 도달 Store→Load가 증명되면 caller MemorySSA에 전역 Store를 반영한다. 원본 untyped x86_64 O0/O1·arm64 O0 3설정에서 `unknown_call_or_write`가 사라졌다. arm64 O1은 `CallInfo.arguments=[]`라 증명하지 않고 유지한다. 네 설정 모두 X와 local `unknown=false`; 전체 scalar 효과 `partial`은 남는다. |
| `store_then_load` O0 | X는 유지되지만 특히 arm64에서 pointer spill 재로드가 unknown 주소로 확장된 원인이 관측값 설명에 연결되지 않음 | unresolved Load의 주소 의존성을 **설명용 bounded slice**에서만 따라가 간접 writer→pointer spill Load의 `cross_object_may_alias` 원인을 표시한다. arm64 O0 설명에 후보 16개, x86_64 O0에는 4개가 연결된다. taint graph/라벨은 바꾸지 않고 unknown을 유지한다. |
| `pointer_only`, `load_before_store` | 무타입 입력 포인터와 현재 프레임의 비별칭을 증명할 수 없음 | 사용자 승인 기본 `unknown`과 MCP `alias_boundary`를 유지한다. 거짓 clean으로 바꾸지 않았다. |
| `call_indirect` | 원본 `fn` 입력의 완전한 target 집합 없음 | 여전히 `call_boundary`/`unmodeled_callinfo` unknown이다. 기존 유한 후보 증명 경로는 유지한다. |
| `pointer_identity` | ABI 소스 선택 보정 4건 | 모두 exact/unknown=false 유지; 수정 대상 오류가 아니다. |

전역 쓰기 증명은 `memory_effects=none`을 주장하지 않는다. 한 개의 정확한
고정 전역 쓰기만 합치고, 반환값·spoiler·다른 효과의 불확실성은 분리한다.
반환 증명과 쓰기 증명이 같은 호출 지점에서 다른 callee snapshot에 묶이면
SSA가 거부한다. 공개 `flow_get_derived_call_evidence`는 새
`flow-derived-call-global-memory-evidence/1`을 원본 caller/callee snapshot과
CallInfo에서 다시 계산해 위조된 proof digest·snapshot을 거부한다.

## 검증

- 현재 `BUILD_ID`:
  `flow-build-sha256-v1:a9564c08f4b7304776037d97de2ba92b7ee459cf3ed2cb0126ade687ea5b34bf`.
- 원본 28 C 함수 × x86_64/arm64 × O0/O1 = 112 정적 관측:
  90 match, 12 match_partial, 6 inconclusive_partial, 4 calibration.
  `--mode acceptance` issues 0, 판정은 `bounded_partial`이며 지원 승격·
  취약점 판정 없음. 네 입력 원본 SHA 보존, 세션 `save=False`.
  증거: `build/taint-partial-final-checkpoint-details.json`.
- SDK-free 전체 `PYTHONPATH=src:. uv run pytest -q tests`:
  **1,688 passed, 117 subtests passed**. scoped Ruff/compileall/`git diff --check`;
  Pyright 0 errors(IDA SDK source stub 경고 11개); support audit 통과.
- 실제 IDA 9.3 정적 probe: typed 36, Return/ABI 52, finite indirect 6,
  output pointer 8, bit-memory 16 관측. 현재 BUILD_ID, 원본 보존,
  `save=False` 확인. disposable `ida-mcp-test -c api_flow` 2건 통과.
  새 wheel은 격리된 SDK-free import/roundtrip 통과.
- 영향받은 공개 API/path/reviewed-runtime 영수증은 실제 IDA에서 다시
  수집했다. G007 memory 8개와 SSA anchor 2개의 파생 영수증은 기존의
  진짜 native snapshot에서 recorder로 순수 재계산했다. 의미 본문은 동일하고
  현재 구현 해시만 달라졌으며 해시 문자열을 손으로 바꾸지 않았다.
- 파생 전역 쓰기 증명의 callee 메모리 고정점 계산에 job
  cancellation/deadline checkpoint를 전달하고, 전달 여부를 회귀로 검증했다.
  동기 evidence 페이지의 재검증은 여전히 bounded artifact에 의존하므로
  과도한 반복 paging 비용은 별도 운영상 관찰 대상이다.

## 남는 경계

원본 `call_identity`는 세 설정에서 메모리 효과가 좁혀져도 함수 전체
scalar uncertainty 때문에 `partial`이다. arm64 O1은 호출 인자 목록이
없으므로 전역 쓰기 증명을 만들지 않는다. 무타입 포인터의 스택 별칭,
초기 pointee 내용, 임의 함수 포인터 target, 보편적인 간접 메모리 쓰기,
경로 실행 가능성은 여전히 unknown이다. 이 상태를 오류 없이 완료된
정적 분석의 **명시적 한계**로 MCP에 전달한다.
