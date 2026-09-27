# 윈도우 분할 메모리 분석 전환 계획

- 일자: 2026-09-27
- 대상 저장소: `ida-pro-mcp-taint` (`main` @ `3b00c30`, `629a89d` 포함 확인)
- 작성: AASystem 측 분석 → ida-pro-mcp 측 전달용
- 상태: 구현 완료 (Phase 0–5, 2026-09-27; Phase 6 live e2e만 남음)
- 구현 기록: `window_steps`(기본 64)·`window_max_dependencies`(기본 16384)를
  `MemoryPolicy`·스냅샷 요청·`flow_create_snapshot` 도구까지 스레딩.
  예산 초과분은 coarse(`interval: null`, `opaque`)로 넓히고
  `window_dependency_budget_widened` + `partial`로 기록. 설정은 결과에
  persist되어 seeded replay·refine이 그대로 재현. 잡 `progress`에
  `phase_times_ms` 기록. 상세는 `docs/flow-operator.md`의
  "Windowed memory analysis" 절 참조.

## Goal

어떤 크기의 함수에서도 `snapshot_ssa_v1` 잡이 120초 타임아웃 안에 끝나도록,
메모리 분석을 **고정 크기 윈도우 단위**로 분할한다. 분석의 깊이(완전성)는
유지하고, 계산·구체화·저장만 나눈다. 윈도우별 예산을 걸고, 넘기면 잘린
것을 숨기지 않고 `partial`/`widened` 상태로 기록한다. angr 경로 정제
(`refine_path_proof_v1`)는 윈도우 전환 후에도 경로 단위로 그대로 쓴다.

## Success Criteria

- 7차 증명에서 터진 함수(RxSetRenameLinkClusterInfo급, 116블록)의 스냅샷
  잡이 120초 안에 완료된다.
- 윈도우 분할 결과 == 전체 일괄 결과 (동등성 테스트로 증명).
- 예산 초과 시 `partial`/`widened` 상태가 artifact·조회에 정직하게 남는다.
- 기존 단일-graph artifact 경로와 공존한다 (계약 파기 없음).
- angr refine이 윈도우 그래프에서도 경로 단위로 동작한다.
- rdbss.sys live e2e에서 `lease_expired`가 해소된다.

## 배경/원인

### 측정된 사실 (Evidence)

7차 증명(`analysis_6e2f8b4d…`)의 flow 저장소를 뜯은 결과:

| # | 관찰 | 출처 |
|---|---|---|
| E1 | `snapshot_ssa_v1` 잡 2개가 전부 `interrupted` / `lease_expired` | jobs 테이블 (`state`, `error.code`) |
| E2 | 그래프 artifact 1개 = 엣지 254,705개, 증거 239,285개, 노드 2,853개, 350MB | graph blob 실측 |
| E3 | 엣지의 97.6% (248,537개)가 `memory_data_dependency`, 규칙 `byte-reaching-store-v1` | 엣지 kind 집계 |
| E4 | 순수 Python 재현 (IDA 없음, 프로파일러 없음): `build_ssa` 1.8초, `build_memory_plan` 0.1초 (215스텝), `analyze_memory` 49.7초 (1회 호출, 의존성 248,494개 생성), 의존성 구체화 28.7초, 정렬 19.5초 → 합계 약 100초 | `/tmp/flow-profile-stages.py` (스크래치, 미커밋) |
| E5 | `canonical_json` 직렬화는 artifact당 6.5초, 일반 JSON은 1.1초 | 동일 재현 + 별도 측정 |
| E6 | 모든 flow 잡의 타임아웃은 120초 고정 | `ida_mcp/flow/service.py`의 `engine.submit(…, timeout=120)` 6곳 |
| E7 | 조회 단계는 이미 페이지네이션됨 (`TraceState`/`commit_page`, `budget_exceeded`, `flow_get_graph` 외부화) | `flow_core/query.py` |

### 원인 판정 (Ranked synthesis)

| 순위 | 설명 | 확신도 | 근거 |
|---|---|---|---|
| 1 | 바이트 단위 의존성 팬아웃: 215스텝에서 248,494개 의존성 생성, `analyze_memory`만 49.7초 | 높음 | E4 + `memory_analysis.py`의 `load()` 바이트 루프·`dependency()` |
| 2 | 25만 개 구체화+정렬이 48초 추가 (Evidence/Edge 생성 시 건당 다이제스트, 대형 정렬) | 높음 | E4 + `memory_graph.py` 구체화 루프·`Graph` 조립 정렬 |
| 3 | IDA 추출 경합이 남은 시간을 먹음 | 중간 | E4 합계 100초 + E5 직렬화 + SQLite + 추출 = 120초 초과. 추출 단독은 미측정 |

### 추론 (Inference)

- 120초 초과는 **확정적(deterministic)** 이다. IDA 없이 순수 Python만으로
  약 100초 + 직렬화 수십 초가 걸리므로, 이 함수에서는 재시도해도 항상
  터진다. 일시적 경합이 아니다.
- 폭발 지점은 "분석 깊이"가 아니라 **"의존성 전량 구체화"** 다. 노드
  2,853개는 평범한데 의존성만 25만 개다.
- 조회 페이지네이션(E7)은 이미 있으므로, 고칠 곳은 그 앞단(분석·구체화)이다.

### 미확인 (Unknowns)

- `_extract` (IDA 단계) 단독 소요 시간. 이번 재현은 분석 단계만 쟀다.
- 경계 상태(셀·버전·definitions 집합)의 실제 메모리 크기. 윈도우 설계의
  입력값이므로 Phase 0에서 측정한다.

## Approach

사용자 제안(윈도우 분할)을 채택한다. ByteRay식 에이전트 주도 스텝 탐색은
**채택하지 않는다** — 깊이(완전성)가 에이전트 성실도에 달려서, "문제 없음"
주장의 근거가 약해지기 때문이다. 배울 점은 "전부 그리지 마라"지 "얕게
분석해라"가 아니다.

핵심 설계:

1. **윈도우 분할 분석**: `plan.steps`를 고정 크기(예: 64스텝) 윈도우로
   나눠 처리한다. 앞 윈도우의 명령은 버리고, **경계 상태**(추상 저장소:
   셀·기본값·definitions)만 다음 윈도우로 넘긴다. 순방향 데이터흐름
   분석이므로 경계 상태만 완전하면 결과는 일괄 실행과 동일하다.
2. **윈도우별 예산**: 시간·의존성 개수 상한을 윈도우마다 건다. 초과 시
   해당 윈도우를 `widened`로 넓히고 전체 상태를 `partial`로 표시한다.
   기존 축(`load_range_widened`, `budget_exceeded`, `partial`)을 재사용한다.
3. **체인 다이제스트**: 윈도우별 artifact + 연결 해시로 전체 무결성을
   유지한다. 기존 단일-graph 검증(`path_bindings`, refine의 artifact 일치
   검사)과 공존하도록, 체인도 동등한 바인딩 검증을 제공한다.
4. **angr 병행**: refine은 경로 단위로 현행 유지한다. 체인 그래프에서
   경로 검증이 바로 안 되면, 경로 서브그래프만 작은 artifact로
   구체화(materialize)해서 기존 검증을 통과시킨다.

## Steps

### Phase 0 — 프로파일링 확정 + 재현 테스트

- `_extract` (IDA 단계) 단독 시간을 잰다. `runtime.py`의 `phase`
  (`extract`/`analyze`/`commit`)에 타임스팬을 기록한다.
- `analyze_memory` 내부 핫루프를 cProfile으로 한 번 더 쪼갠다
  (`load`/`dependency`/셀 읽기).
- 경계 상태 크기를 잰다 (윈도우 크기 결정의 입력).
- 116블록급 재현 픽스처 또는 합성 확대 테스트를 만든다. 실제 타깃
  바이너리는 실행하지 않는다 (AGENTS.md).
- 검증: `PYTHONPATH=src:. uv run pytest -q tests/flow_core tests/test_upstream_sync.py`

### Phase 1 — 윈도우 실행기

- 표면: `flow_core/memory_graph.py` (`_analyze_plan`, `build_memory_graph_from_program`),
  `flow_core/memory_analysis.py` (`analyze_memory`)에 윈도우 경계
  (시작 상태 주입·중단 후 상태 반환)를 둔다.
- 윈도우 크기 설정값 추가 (기본 64스텝, 조정 가능).
- **동등성 테스트**: 동일 스냅샷에 대해 윈도우 결과 == 일괄 결과
  (의존성 집합·정밀도·버전 일치).
- 검증: 동등성 테스트 + `uvx ruff@0.15.7 check src/ida_pro_mcp/flow_core tests/flow_core`

### Phase 2 — 윈도우별 예산 + 정직한 상태

- 표면: `flow_core/memory.py` (`MemoryPolicy`에 윈도우 예산),
  `flow_core/runtime.py` (잡 예산과 연동).
- 예산 초과 시 해당 윈도우 `widened`, 전체 `partial`로 기록하고 계속
  진행한다. 잘린 것을 숨기지 않는다.
- 검증: 예산을 일부러 낮춘 테스트에서 `partial` 상태 어서션.

### Phase 3 — 체인 다이제스트 + artifact 저장

- 표면: `flow_core/persistence.py` (윈도우별 `put_artifact`),
  `ida_mcp/flow/service.py` (`_analyze`의 저장 부분).
- 각 윈도우 artifact + 이전 윈도우 해시를 포함한 체인 검증 함수.
- 기존 단일-graph 경로와 공존 (호출자가 선택).
- 검증: 체인 변조 테스트 (중간 윈도우를 바꾸면 검증 실패).

### Phase 4 — 조회·경로 호환

- 표면: `flow_core/query.py` (체인 그래프 위 페이지네이션),
  `path_bindings`·`ConstraintQuery` 검증이 체인에서도 동작.
- 검증: 기존 query 테스트 + 체인 그래프 페이지네이션 테스트.

### Phase 5 — angr 연동 확인

- 표면: `ida_mcp/flow/service.py` (`create_path_refinement`,
  `refine_path_proof_v1`), `flow_core/angr_client.py` (변경 불필요 예상).
- 핀 `629a89d`의 echo(블록별 angr 가능 여부)와 호환 확인.
- 필요시 경로 서브그래프 구체화(materialize) 추가.
- 검증: 기존 refine 테스트 + 체인 그래프 refine 테스트.

### Phase 6 — live e2e 증명

- AASystem에서 `AASYSTEM_ANALYSIS_E2E_TARGET=rdbss.sys node scripts/analysis-cycle-e2e.mjs --force`.
- `lease_expired` 해소 + 스냅샷 완료 + (LLM이 원하면) refine까지 확인.
- angr 실행 자체를 강제하지 않는다. LLM이 필요성을 느껴 호출할 때
  고장 없이 도는 것이 성공 기준이다.

## Validation Plan

| 단계 | 명령·확인 | 기대 증거 |
|---|---|---|
| SDK-free 회귀 | `PYTHONPATH=src:. uv run pytest -q tests/flow_core tests/test_upstream_sync.py` (ida-pro-mcp 루트) | 전량 통과 |
| 린트 | AGENTS.md의 `uvx ruff@0.15.7 check …` 행 | 통과 |
| 지원 감사 | `uv run python scripts/audit_flow_support.py --root . --check tests/flow_fixtures/manifests/support_receipts.json` | 통과 |
| IDA 스모크 | 일회용 복사본에 `uv run ida-mcp-test "$work/…" -q` (IDA 9.3) | 통과, 원본 미변경 |
| 성능 게이트 | 기록된 함수 스냅샷 잡 < 120초 | 잡 `complete` |
| live e2e | AASystem에서 rdbss.sys 분석 사이클 | `lease_expired` 없음 |

## Risks / Open Questions

- **경계 상태 크기**: 셀·버전이 크면 윈도우 효과가 반감된다. Phase 0
  측정 후 윈도우 크기를 정한다. 필요시 경계 요약 압축을 추가한다.
- **체인 다이제스트는 계약 변경**이다. AASystem 측
  (`flow-graph-observation.js`, `path_bindings` 소비자)과 합의를 먼저 한다.
- **IDA 추출 미측정**: 분석이 주범으로 확정됐지만, 추출 단계도 느리면
  별도 처방(추출 예산·재시도)이 필요하다. Phase 0에서 같이 잰다.
- **Non-goals**: 에이전트 주도 스텝 탐색으로의 전환, 자동 취약점 판정
  (AGENTS.md 금지 유지), angr 실행 강제.

## Sources

- ByteRay `trace_ssa_step` 설계 (5스텝 단위 증분 추적, `has_more`/`next_index`
  페이지네이션) — https://byteray.ai/skills/SKILL.md ,
  https://byteray.ai/skills/tool-reference.md (2026-09-27 열람)
