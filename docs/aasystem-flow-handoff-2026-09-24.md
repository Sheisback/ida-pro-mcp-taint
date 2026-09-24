# AASystem 전달문 — taint MCP 결과 해석

기존 MCP 도구 이름·입력은 그대로다. 이 변경은 주로 내부 정적 분석 수정과
**추가 응답 필드**다. AASystem이 결과를 표시하거나 자동 요약한다면 아래
계약을 적용한다.

1. `flow_get_memory_analysis(memory_result_artifact)`의 페이지 metadata에서
   `alias_policy.untyped_input_current_frame == "may_alias_unknown"`와
   `untyped_current_frame_alias_dependency_count`를 읽는다. 해당 dependency의
   `alias_boundary`에는
   `reason_code: "untyped_input_current_frame_noalias_unproven"`,
   `status: "unknown"`, `alias_relation: "may_alias"`,
   `source_target_pairs`가 있다. `alias_boundary`가 `null`인 dependency에는
   이 특정 경계를 적용하지 않는다.
2. 특정 관측값의 원인은
   `flow_explain_implicit_analysis(implicit_artifact, observation_node_id)`로
   조회한다. 첫 페이지 metadata의
   `untyped_current_frame_alias_cause_count`를 보고 cause 페이지를 끝까지
   순회한다. 관련 local cause에도 같은 `alias_boundary`가 붙는다.
3. `unknown_provenance: true`, `alias_relation: "may_alias"`, 또는
   `alias_boundary.status: "unknown"`은 **가능한 의존성**이다. 라벨이
   관측되지 않았다는 이유만으로 안전/clean이라고 하지 말고, 라벨이
   관측됐다는 이유만으로 확정 taint/취약점이라고 하지 않는다.
   함수 전체 `partial`과 특정 관측값의 local 원인은 따로 표시한다.
4. `alias_policy.typed_input_current_frame == "conditional_no_alias"`는
   IDB의 정확한 full-width 포인터 타입·argloc와 유효한 source-object
   pointer provenance를 모두 가정한 조건부 결과다. IDB 타입만으로 임의
   바이너리의 실제 포인터 출처를 증명하지 않는다.
5. tool call의 `database`는 경로가 아니라 `idb_open`이 반환한 세션 ID다.
   페이지는 bounded/cursor 기반이며 `target_executed: false` 및
   `no_auto_vulnerability_verdict: true` 계약을 유지한다. AASystem은
   자동 취약점 판정이나 지원 범위 승격을 하지 않는다.
6. `flow_get_job.result.callee_closure.boundaries`의
   `derived_call_effect_unavailable` 항목에는 `callinfo_argument_count`가
   추가된다. 값이 0이면 호출 지점에서 IDA가 인자 목록을 제공하지
   않았다는 **관측 사실**이지, 실제 함수가 무인자라거나 이것만이 증명
   실패 원인이라는 뜻이 아니다. `call_identity`처럼 반환 라벨은
   알려져도 전체 호출 효과가 `partial`일 수 있다.
7. `store_then_load`처럼 포인터를 현재 스택에 저장한 뒤 무타입 포인터로
   쓰면 그 쓰기가 저장된 포인터 자체를 부분 파괴할 수 있다. 관측값 설명의
   `unknown_address`만 표시하지 말고, 함께 반환되는
   `cross_object_may_alias` cause 및 `alias_boundary` 객체 쌍도 보여준다.
   이는 주소를 복구하지 못한 인과 후보 설명이지 확정된 clobber 증명이
   아니다.
8. `call_indirect`에서 `callee_closure.boundaries`에
   `unresolved_indirect`/`finite_target_set_incomplete`가 있으면 알려진
   후보가 일부 있더라도 전체 호출 집합이 닫히지 않았다. 반환이나 메모리
   효과를 clean으로 확정하지 말고 `unknown remainder`를 표시한다.
   `pointer_identity`는 입력 위치 보정 사례이며 partial 오류가 아니다.
9. `derived_call_memory_writes`에 `global_address`가 있는 경우에는
   같은 `proof_digest`의 `derived_call_memory_evidence`를
   `flow_get_derived_call_evidence`로 조회한다.
   증거 schema는 `flow-derived-call-global-memory-evidence/1`이고 페이지는
   caller/callee snapshot과 CallInfo를 다시 검증한다.
   `memory_effects: "single_fixed_global_write"`는 증명된 **한 전역
   쓰기**만 뜻하며 순수 함수·모든 호출 효과 해결을 의미하지 않는다.
   `call_identity`의 X 관측은 local known일 수 있어도 전체 scalar
   효과 때문에 `partial`은 남을 수 있다.

현재 정적 재검증: 원래 108개 의미 관측 중 90 complete match, 12
match_partial, 6 inconclusive_partial이다. 6건 중 4건은 무타입 포인터와
현재 프레임의 별칭 불확정, 2건은 임의 간접 호출 대상 불확정이다. 이 숫자는
IDA 9.3 x86_64/arm64 Mach-O O0/O1 네 설정의 고정 소스에만 해당한다.

근거: `src/ida_pro_mcp/ida_mcp/flow/service.py`의 `_ALIAS_POLICY`,
`_memory_page`, `explain_implicit`; `docs/flow-operator.md`의 memory 모델;
`build/taint-mcp-alias-acceptance-details.json`의 실제 정적 관측.
