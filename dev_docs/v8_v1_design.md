# pcode_slicegraph_v8_new_v1_codex_integrated

# P-code SliceGraph Engine V8 / New V1 통합 설계서

**용도:** Codex 전달용 최종 통합 문서

**대상 코드:** `pcode_ssa_report_v5.py`, `pcode_ssa_report_v6.py`, `pcode_ssa_report_v7.py`

**핵심 목표:** Low P-code 기반, target-independent, convention-free, architecture-independent, summary-backed interprocedural backward slice engine 구축

---

## 0. 이 문서의 목적

현재 v5/v6/v7 prototype은 Low P-code JSON을 기반으로 함수 내부 SSA-like dependency graph를 만들고, source/sink boundary와 일부 call summary, memory transfer summary를 실험적으로 붙인 상태다.

V8 / New V1은 기존 파일을 계속 상속 확장하지 않는다. 새 패키지 구조로 분리하고, 기존 prototype에서 검증된 로직만 가져와 재배치한다.

최종 목표는 다음이다.

```
1. Low P-code를 source of truth로 사용한다.
2. High P-code / decompiler output은 hint로만 사용한다.
3. Backward Slice를 위해 Value Dependency Graph / SliceGraph를 만든다.
4. Core graph에서 argument / return / calling convention 개념을 사용하지 않는다.
5. 함수 호출은 caller/callee 사이의 observed storage transition으로 모델링한다.
6. 32-bit / 64-bit / ARM64를 지원할 수 있는 architecture-independent storage model을 사용한다.
7. 특정 target을 미리 가정하지 않고, 관찰 가능한 모든 output storage를 graph/index에 남긴다.
8. interprocedural backward slice는 summary를 기본 연결 경로로 사용한다.
9. inline expansion depth는 precision 제어 장치로만 사용한다.
10. global memory는 source boundary가 될 수 있는 program-wide storage로 관리한다.
11. heap memory는 기본적으로 source가 아니라 source value를 전달하는 allocation-site based storage로 관리한다.
12. DataFlowBench expected validation을 계속 지원한다.
```

---

## 1. 최종 설계 원칙

```
Forward build는 지도 제작이다.
Backward query는 경로 설명이다.

Graph build 단계에서는 target을 가정하지 않는다.
Backward slice 단계에서만 target을 선택한다.

Core graph는 calling convention을 믿지 않는다.
Core graph는 argument, return, param, ABI 개념을 사용하지 않는다.

함수 호출은 convention이 아니라,
caller/callee 사이의 observed storage transition으로 모델링한다.

Ghidra Low P-code는 CALL 이후 register output을 explicit하게 제공하지 않는다.
따라서 CALL_POST_* node는 SliceGraphBuilder 또는 CallBoundaryMapper가 직접 삽입한다.

FunctionGraph는 특정 target을 기준으로 축소하지 않는다.
함수 entry/exit에서 관찰 가능한 모든 storage input/output을 보존한다.

Interprocedural call chain이 끊기는 원인은 depth limit이 아니다.
진짜 원인은 summary coverage 부재다.

max_call_depth는 inline precision을 제한한다.
FunctionSummary는 call connectivity를 책임진다.

분석 가능한 내부 함수는 bottom-up AutoFunctionSummary로 연결성을 유지한다.
외부 함수, unresolved indirect call, recursive SCC summary unavailable만 unresolved boundary로 남긴다.

Global memory는 program-wide versioned storage이며 source boundary가 될 수 있다.
Heap memory는 allocation-site based storage이며 기본적으로 source가 아니라 transfer storage다.

Loop/fixed-point limit 초과는 widened unknown으로 표현하고 source로 확정하지 않는다.

node는 값이고,
edge는 그 값이 전달된 이유와 통과한 경계다.

argument / return / calling convention은 필요할 경우 외부 interpretation layer에서만 붙인다.

불확실한 것(추정된 ABI/convention)은 믿지 않는다. 확실한 것(PDB/심볼의 정적 사실)은 신뢰한다.
PDB/심볼은 core graph를 덮어쓰지 않는 optional overlay이며, core는 PDB 유무와 무관하게 동일하다.
PDB가 주장하는 물리 storage 매핑(param/return 위치 등)은 관찰된 dataflow와 일치할 때만 채택한다.
```

---

## 2. 기존 prototype에서 유지할 것과 제거할 것

### 2.1 유지할 것

```
- Low P-code 기반 graph build
- networkx.DiGraph 기반 value dependency graph
- data / memory / address edge kind 분리
- stack store/load matching
- PHI-like merge node
- SOURCE_RET synthetic node
- SINK_ANCHOR 기록
- expected_sources / forbidden_sources 검증
- recursive stack address recovery
- memcpy / memmove / strcpy / memset transfer summary
- 기존 DataFlowBench 회귀 테스트 자산
```

### 2.2 제거할 core 표현

다음 표현은 core package, analysis core class, edge kind, node kind에서 사용하지 않는다.

```
arg
argument
param
parameter
return
ret
cdecl
stdcall
fastcall
thiscall
Win64
SysV
ABI
CALL_RET
CALL_RESET
CALL_CLOBBER
pending_stack_args
arg0_to_ret_summary
```

예외적으로 DataFlowBench adapter의 expected label, 외부 interpretation layer, report의 optional interpretation 섹션에서는 사람이 이해하기 위한 label로만 사용할 수 있다.

---

## 3. 새 패키지 구조

기존 v5/v6/v7 파일을 직접 크게 수정하지 말고, 새 구조를 만든 뒤 필요한 로직을 이식한다.

```
core/
  value_id.py
  storage.py
  architecture.py
  graph.py
  state.py
  edge.py
  memory_object.py

frontend/
  low_pcode_loader.py
  metadata_loader.py
  ghidra_architecture_loader.py
  ghidra_metadata_loader.py

analysis/
  cfg_builder.py
  slice_graph_builder.py
  memory_model.py
  call_model.py
  call_resolver.py
  call_boundary_mapper.py
  summary_provider.py
  summary_applier.py
  const_propagator.py

query/
  backward_slice.py
  source_collector.py

report/
  text_report.py
  expected_validator.py
  graph_exporter.py
```

책임 분리:

```
core:
  ValueId, Storage, EdgeKind, ArchitectureSpec, MemoryObject 같은 순수 모델

frontend:
  Low P-code JSON과 Ghidra metadata를 core 모델로 변환

analysis:
  CFG, SliceGraph, MemoryModel, CallBoundary, Summary 생성/적용

query:
  이미 만들어진 ProgramSliceGraph에서 backward traversal 수행

report:
  결과 출력, expected validation, graph export
```

---

## 4. Architecture-independent Storage Model

V8 / New V1은 32-bit x86 전용 엔진이 아니다. 32-bit x86, x86-64, AArch64를 모두 지원할 수 있어야 한다.

Core graph는 특정 architecture register name, pointer size, frame pointer, stack pointer convention에 종속되지 않는다. Architecture-specific 정보는 `ArchitectureSpec`으로 분리한다.

### 4.1 ArchitectureSpec / RegisterAlias / RegisterStorage

`core/architecture.py`에 다음 타입을 추가한다.

```python
@dataclass(frozen=True)
class RegisterAlias:
    display: str
    canonical: str
    offset_bits: int
    size_bits: int

@dataclass(frozen=True)
class RegisterStorage:
    arch: str
    canonical: str
    offset_bits: int
    size_bits: int
    display: str

@dataclass(frozen=True)
class ArchitectureSpec:
    name: str
    pointer_size: int
    endian: str

    stack_pointer_regs: set[str]
    frame_pointer_regs: set[str]
    link_registers: set[str]

    general_registers: set[str]
    register_aliases: dict[tuple[int, int], RegisterAlias]

    def canonicalize_register(
        self,
        offset: int,
        size_bytes: int,
        display_hint: str | None = None,
    ) -> RegisterStorage:
        ...
```

규칙:

```
- frontend/low_pcode_loader.py는 register varnode를 직접 문자열 register로 변환하지 않는다.
- register varnode는 반드시 ArchitectureSpec.canonicalize_register(offset, size_bytes)를 통해 RegisterStorage로 변환한다.
- ValueId.key는 display name이 아니라 canonical register 기준으로 만든다.
- display name은 node attribute로만 둔다.
```

예시:

```json
{
  "space": "reg",
  "arch": "x86_64",
  "canonical": "RAX",
  "offset_bits": 0,
  "size_bits": 32,
  "display": "EAX"
}
```

### 4.2 Phase 1 Architecture 범위

Phase 1에서는 full alias precision을 구현하지 않는다.

```
Phase 1 최소 구현:
- ArchitectureSpec.from_preset("x86") 제공
- x86 32-bit register offset -> canonical name 변환
- DFB001 / DFB002를 통과할 정도의 minimal RegisterStorage 생성
```

Phase 4 이후 확장:

```
- Ghidra Language API 기반 자동 register alias 구축
- x86-64 sub-register alias 처리
- AArch64 X/W register alias 처리
- pointer_size 기반 memory size 정규화
```

### 4.3 Ghidra Language API 활용

Ghidra Language API는 calling convention 추론이 아니다. Low P-code를 생성하는 동일 레이어의 architecture metadata이므로 core 설계 원칙과 충돌하지 않는다.

```python
class GhidraArchitectureLoader:
    def from_program(self, program) -> ArchitectureSpec:
        lang = program.getLanguage()
        ...
```

활용 목적:

```
- register offset/size -> RegisterStorage 변환
- canonical register name 추출
- sub-register alias table 생성
- pointer_size 결정
- endian 결정
- stack pointer / frame pointer / link register 후보 등록
```

주의:

```
이 정보는 architecture metadata로만 사용한다.
argument / return / convention 판단에 사용하지 않는다.
```

### 4.4 StackStorage

```python
@dataclass(frozen=True)
class StackStorage:
    function: str
    context: str
    base: str
    offset: int
    size: int | None
    relation: str
```

예시:

```
x86-32:
  foo:root:stack:EBP:-4
  foo:root:stack:ESP:+8

x86-64:
  foo:root:stack:RBP:-8
  foo:root:stack:RSP:+32

AArch64:
  foo:root:stack:SP:+16
  foo:root:stack:X29:-8
```

### 4.5 Call continuation storage

```
x86 / x86-64:
  call continuation이 stack return-address storage로 관찰될 수 있다.

AArch64:
  call continuation이 X30 / LR 같은 link register storage로 관찰될 수 있다.
```

Core data slice에는 call continuation storage를 기본 포함하지 않는다.

```
call continuation storage는 control boundary 정보다.
data-only backward slice에서는 기본 제외한다.
data+control slice 또는 exploit-oriented mode에서만 포함할 수 있다.
```

---

## 5. ValueId와 node identity

### 5.1 ValueId

```python
@dataclass(frozen=True)
class ValueId:
    function: str
    context: str
    space: str
    key: str
    version: int | None = None
```

예시:

```
case_DFB010:root:reg:EAX:3
case_DFB010:root:stack:EBP:-4:2
dfb_source_A:call_4014a3:reg:EAX:1
dfb_source_A:call_4014a3:stack:EBP:-4:1
program:global:g_dfb_value:2
foo:root:heap:malloc_401000:offset0:1
```

사람이 보는 이름은 별도 display attribute로 둔다.

```python
node_id = ValueId(...)
slice_graph.add_node(
    node_id,
    display="EAX#3",
    kind="value",
    space="reg",
    addr=addr,
    opcode=opcode,
)
```

---

## 6. Graph 구조

### 6.1 slice_graph와 cfg 분리

기존 `self.G`는 실제로 CFG가 아니라 value dependency graph였다. 다음처럼 명확히 분리한다.

```python
self.slice_graph = nx.DiGraph()
self.cfg = nx.DiGraph()
```

의미:

```
cfg:
  BasicBlock -> BasicBlock

slice_graph:
  ValueNode -> ValueNode
```

### 6.2 CFGBuilder

```python
class CFGBuilder:
    def build(self, instructions) -> nx.DiGraph:
        ...
```

Ghidra 사용 가능 환경에서는 `BasicBlockModel` adapter를 사용할 수 있다.

```python
class GhidraBasicBlockCFGBuilder:
    def build(self, program, function) -> nx.DiGraph:
        ...
```

원칙:

```
- BasicBlockModel은 decompiler가 아니다.
- CFG boundary hint로 사용할 수 있다.
- Low P-code def-use는 여전히 source of truth다.
- Ghidra BasicBlockModel을 사용할 수 없으면 기존 _build_basic_blocks 로직을 fallback으로 사용한다.
```

CFG edge attribute:

```json
{
  "kind": "fallthrough | conditional_true | conditional_false | jump | call_fallthrough",
  "condition": "optional condition value id"
}
```

---

## 7. Edge kind와 traversal policy

### 7.1 필수 edge kind

```
data
memory
address
control

summary_data
summary_memory

call_control

call_in_stack
call_in_reg
call_in_mem

call_out_reg
call_out_mem
call_out_global
```

### 7.2 data-only slice 기본 edge set

```python
DATA_SLICE_EDGES = {
    "data",
    "memory",
    "summary_data",
    "summary_memory",
    "call_in_stack",
    "call_in_reg",
    "call_in_mem",
    "call_out_reg",
    "call_out_mem",
    "call_out_global",
}
```

### 7.3 data + control slice edge set

```python
DATA_CONTROL_SLICE_EDGES = DATA_SLICE_EDGES | {
    "control",
    "call_control",
}
```

---

## 8. Target-independent output 보존 원칙

기존 backward slice 방식은 target을 먼저 정한 뒤 추적하기 때문에, target과 직접 관련 없는 output은 분석 과정에서 버려지기 쉽다.

V8 / New V1에서는 이 방식을 사용하지 않는다.

```
FunctionGraph는 target-specific graph가 아니다.
FunctionGraph는 함수 내부의 모든 value definition과 dependency edge를 가능한 범위에서 보존한다.

함수 entry에서 관찰 가능한 storage input을 callee_entry_observed_index에 기록한다.
함수 exit에서 관찰 가능한 모든 storage output을 exit_output_index에 기록한다.
특정 register 또는 특정 convention-like role에 한정해서 output을 저장하지 않는다.

Caller callsite에서도 특정 register에 한정하지 않고, pre/post-call에 관찰 가능한 storage별 CALL_PRE / CALL_POST node를 생성할 수 있어야 한다.

Backward slice target은 graph build 이후 query 단계에서 선택한다.
```

필수 index:

```
def_index:
  ValueId -> defining node

callee_entry_observed_index:
  function/context/storage -> ValueId

exit_output_index:
  function/context/storage -> ValueId

call_pre_storage_index:
  callsite/storage -> ValueId

call_post_storage_index:
  callsite/storage -> ValueId

sink_index:
  sink callsite/observed storage index -> ValueId

source_index:
  source boundary -> ValueId

storage_current_index:
  block/function/context/storage -> current ValueId

global_object_index:
  address/symbol -> GlobalObjectId

global_version_index:
  GlobalObjectId -> latest ValueId per program point

global_source_index:
  GlobalObjectId -> SourceBoundary metadata

summary_cache:
  SummaryCacheKey -> FunctionSummary
```

---

## 9. Convention-free Call Boundary Model

### 9.1 핵심 원칙

```
함수 호출은 convention이 아니라, caller/callee 사이의 observed storage transition으로 모델링한다.
```

Core graph는 다음만 표현한다.

```
caller callsite 이전에 관찰된 storage state
callee entry에서 관찰된 storage state
callee exit에서 관찰된 storage state
caller callsite 이후에 관찰된 storage state
```

### 9.2 Call boundary node

```
foo:root:callsite:0x401000:pre:reg:<REG>
foo:root:callsite:0x401000:pre:stack:<BASE>:<OFFSET>

bar:call_foo_0x401000:entry:reg:<REG>
bar:call_foo_0x401000:entry:stack:<BASE>:<OFFSET>

bar:call_foo_0x401000:exit:reg:<REG>
bar:call_foo_0x401000:exit:stack:<BASE>:<OFFSET>

foo:root:callsite:0x401000:post:reg:<REG>
foo:root:callsite:0x401000:post:stack:<BASE>:<OFFSET>
```

이 이름은 `arg`, `param`, `return`을 포함하지 않는다.

### 9.3 Call boundary edge

```
call_in_stack:
  caller pre-call stack storage -> callee entry stack storage

call_in_reg:
  caller pre-call register storage -> callee entry register storage

call_in_mem:
  caller pre-call memory object -> callee entry memory object

call_out_reg:
  callee exit register storage -> caller post-call register storage

call_out_mem:
  callee exit memory object -> caller post-call memory object

call_out_global:
  callee global write -> caller after-call global storage
```

### 9.4 Ghidra Low P-code CALL 출력 주의사항

Ghidra Low P-code는 CALL instruction 이후의 register output을 explicit하게 표현하지 않는다.

따라서 `CALL_POST_REG`, `CALL_POST_MEM`, `CALL_POST_GLOBAL` node는 Low P-code에서 자동으로 나오는 값이 아니다. SliceGraphBuilder 또는 CallBoundaryMapper가 직접 synthetic node로 생성해야 한다.

```
CALL_POST_* node는 Low P-code output이 아니다.
CALL_POST_* node는 분석기가 call boundary 이후 관찰 가능한 storage state를 표현하기 위해 삽입하는 synthetic node이다.
```

CALL 이후 storage state를 명시적으로 새 version으로 만들지 않으면 stale register dependency가 발생할 수 있다.

---

## 10. Call Model / CallBoundaryMapper

### 10.1 기존 call naming 제거

다음 이름은 제거한다.

```
CALL_RET
CALL_RESET
CALL_CLOBBER
```

Core node 이름은 다음으로 변경한다.

```
CALLSITE
CALL_PRE_REG
CALL_PRE_STACK
CALL_PRE_MEM

CALL_POST_REG
CALL_POST_MEM
CALL_POST_GLOBAL
```

`CALL_PRE_*` / `CALL_POST_*`는 Low P-code opcode가 아니다. SliceGraph의 synthetic node kind 또는 ValueId space이다.

### 10.2 CallContext

```python
@dataclass
class CallContext:
    callsite_id: str
    caller_function: str
    callee_function: str | None
    caller_context: str
    callee_context: str | None
    continuation_storage: ObservedStorage | None
    target_confidence: str

    pre_call_observed_storages: list[ObservedStorage]
    post_call_observed_storages: list[ObservedStorage]
    callee_entry_observed_storages: list[ObservedStorage]
    callee_exit_observed_storages: list[ObservedStorage]
```

### 10.3 CallBoundaryMapper interface

```python
class CallBoundaryMapper:
    def collect_pre_call_observed_storages(self, caller_state, callsite) -> list[ObservedStorage]:
        ...

    def collect_post_call_observed_storages(self, caller_state, callsite) -> list[ObservedStorage]:
        ...

    def collect_callee_entry_observed_storages(self, callee_graph) -> list[ObservedStorage]:
        ...

    def collect_callee_exit_observed_storages(self, callee_graph) -> list[ObservedStorage]:
        ...

    def create_boundary_edges(self, call_context) -> list[BoundaryEdge]:
        ...
```

하위 collector는 convention 이름이 아니라 observation 기준으로 둔다.

```
PreCallStackWriteCollector
PreCallRegisterStateCollector
PreCallMemoryStateCollector

CalleeEntryStackReadCollector
CalleeEntryRegisterReadCollector
CalleeEntryMemoryReadCollector

CalleeExitStorageCollector
PostCallStorageCollector
```

### 10.4 call_in_stack candidate 범위 제한

`PreCallStackWriteCollector`는 callsite 직전의 모든 stack write를 무작정 수집하면 안 된다.

수집 범위:

```
1. 동일 basic block 또는 callsite 직전 backward scan window 내부의 stack write만 수집한다.
2. 마지막 call-boundary reset 이후의 stack write만 수집한다.
3. stack pointer/frame pointer를 재설정하는 instruction 이후의 stack write만 수집한다.
4. callee-save spill, local allocation, frame setup으로 보이는 write는 confidence를 낮추거나 제외한다.
5. callee entry에서 실제 stack/frame read가 관찰될 때만 verified로 승격한다.
```

MVP 정책:

```
- stack write는 candidate로만 수집한다.
- candidate edge의 confidence는 "candidate"로 둔다.
- callee entry read와 storage relation이 맞으면 "callee_entry_read_verified"로 승격한다.
- 검증되지 않은 candidate는 data slice 기본 결과에는 포함하지 않고, explain/debug mode에서만 표시할 수 있다.
```

### 10.5 stack mapping basis

stack mapping은 calling convention이 아니라 다음 관찰을 기반으로 만든다.

```
call instruction의 stack pointer effect
call continuation storage 위치
callee prologue에서 관찰되는 frame base setup
callee stack/frame read offset
caller pre-call stack write offset
```

### 10.6 call_in_reg verification

`call_in_reg` edge는 무조건 verified로 만들지 않는다.

```
Phase 2:
  call_in_reg edge는 모두 confidence="candidate"로 생성한다.

Phase 5:
  callee FunctionGraph가 생성된 뒤 callee entry에서 해당 register의 use-before-def를 확인한다.
  확인되면 confidence="callee_use_before_def_verified"로 승격한다.
  callee가 해당 register를 read하기 전에 define하면 해당 call_in_reg edge는 data slice 기본 traversal에서 제외한다.
```

### 10.7 CALL_POST_REG materialization

MVP에서는 safe-lazy materialization 방식을 사용한다.

```
MVP policy:
- CALL instruction을 만나면 ArchitectureSpec.general_registers에 대해 CALL_POST_REG candidate node를 생성할 수 있다.
- query/report에서 실제 도달하거나 사용된 storage만 의미 있게 표시한다.
- CALL_POST_REG candidate는 source로 확정하지 않는다.
- callee graph 또는 summary가 있으면 해당 storage에 대해 call_out_reg edge를 연결한다.
- callee graph/summary가 없으면 unresolved_call_boundary warning으로 남긴다.
```

mode 구분:

```
default mode:
  used-after-call register + configured important register 중심으로 CALL_POST_REG 생성

safe-lazy mode:
  all general registers에 CALL_POST_REG candidate 생성

debug mode:
  all general registers + memory/global candidate까지 출력
```

Phase 1~2 기본값:

```
safe-lazy mode
```

Phase 4 이후 최적화:

```
1-pass:
  callsite 이후 redefinition 전 read되는 register set 수집

2-pass:
  해당 register에 대해서만 CALL_POST_REG materialize
```

---

## 11. CallResolver와 Ghidra metadata 활용

### 11.1 CallResolver

`analysis/call_resolver.py`는 call target resolution만 담당한다.

```python
class CallResolver:
    def resolve(self, instr, program_metadata) -> ResolvedCallTarget:
        ...
```

```python
@dataclass(frozen=True)
class ResolvedCallTarget:
    address: str | None
    name: str | None
    is_thunk: bool
    thunk_target_name: str | None
    confidence: str
```

confidence 값:

```
ghidra_symbol_verified
ghidra_thunk_resolved
low_pcode_direct_target
unresolved_indirect_call
```

### 11.2 Ghidra Symbol Table / Thunk 활용

Ghidra Symbol Table과 FunctionManager를 사용해 symbol과 thunk를 해석할 수 있다.

```python
symbol = program.getSymbolTable().getPrimarySymbol(call_target_addr)

func = program.getFunctionManager().getFunctionAt(call_target_addr)
if func and func.isThunk():
    real_func = func.getThunkedFunction(False)
```

용도:

```
- LibcSummaryProvider routing
- DataFlowBenchBoundaryBinder target matching
- unresolved call warning 품질 향상
```

주의:

```
Symbol/Thunk 정보는 call target resolution에만 사용한다.
argument / return / convention 판단에는 사용하지 않는다.
```

---

## 12. Summary 기반 interprocedural connectivity

### 12.1 핵심 구분: connectivity vs precision

```
Interprocedural connectivity와 precision은 분리한다.

inline expansion depth는 precision 제어 장치다.
function summary coverage는 connectivity 제어 장치다.

max_call_depth가 작아도 summary가 있으면 call chain은 끊기지 않는다.
summary가 없을 때만 unresolved_call_boundary에서 멈춘다.
```

### 12.2 call expansion mode

```
none:
  CALL_POST_*에서 멈춘다.

summary:
  FunctionSummary edge만 사용한다.
  call depth를 소비하지 않는다.
  interprocedural connectivity를 유지하는 기본 방식이다.

inline:
  callee FunctionGraph를 caller context로 확장한다.
  call depth를 소비한다.
  precision 향상을 위한 선택적 방식이다.

hybrid:
  summary를 기본으로 사용한다.
  debug/explain 또는 configured target에 대해서만 inline expansion을 수행한다.
```

기본 모드:

```
default interprocedural mode:
  hybrid

default behavior:
  summary 우선
  inline은 max_call_depth 범위 안에서만 선택적으로 수행
```

### 12.3 Summary edge는 depth를 소비하지 않는다

BackwardSliceQuery에 다음 정책을 추가한다.

```
summary edge traversal은 max_call_depth를 소비하지 않는다.
inline expansion만 max_call_depth를 소비한다.
```

예:

```
A target
← B summary
← C summary
← D summary
```

이 traversal은 `max_call_depth = 1`이어도 끊기지 않아야 한다.

멈추는 경우:

```
1. callee code가 없음
2. external library인데 summary가 없음
3. indirect call target을 모름
4. recursive/SCC summary를 만들 수 없음
5. analysis limit으로 function summary가 widened_unknown만 제공됨
```

---

## 13. Bottom-up AutoFunctionSummaryProvider

### 13.1 Phase 5로 이동

기존 계획에서 `AutoFunctionSummaryProvider`를 Phase 6 이후 확장으로 두면 긴 call chain에서 임의 사용자 정의 함수가 unresolved로 끊길 수 있다.

따라서 minimal `AutoFunctionSummaryProvider`를 Phase 5로 이동한다.

```
Before:
  Phase 6:
    AutoFunctionSummaryProvider는 MVP 이후 확장

After:
  Phase 5:
    Minimal AutoFunctionSummaryProvider를 구현한다.
```

### 13.2 bottom-up build 순서

ProgramSliceGraph는 call_graph를 가진다.

```python
class ProgramSliceGraph:
    functions: dict[str, FunctionGraph]
    callsites: dict[str, CallContext]
    boundary_edges: list[BoundaryEdge]

    call_graph: nx.DiGraph
    scc_map: dict[str, int]
```

Phase 5 시작 시 다음 순서로 분석한다.

```
1. CallResolver로 direct call target을 수집한다.
2. ProgramSliceGraph.call_graph를 구성한다.
3. SCC를 계산한다.
4. SCC condensation graph를 만든다.
5. reverse topological order로 leaf callee부터 FunctionGraph를 빌드한다.
6. 각 FunctionGraph 빌드 직후 AutoFunctionSummary를 생성한다.
7. caller 분석 시 callee summary를 summary edge로 적용한다.
```

Pseudo-code:

```python
def build_program_summaries(program):
    call_graph = build_call_graph(program)
    scc_graph = condense_scc(call_graph)

    for scc in reverse_topological_order(scc_graph):
        if is_recursive_scc(scc):
            build_recursive_scc_summary_or_fallback(scc)
            continue

        for function in scc.functions:
            function_graph = build_function_graph(function)
            summary = auto_summary_provider.summarize(function_graph)
            summary_cache.put(function, summary)
```

### 13.3 Minimal AutoFunctionSummaryProvider

Phase 5의 AutoFunctionSummaryProvider는 완성형 alias analysis가 아니다. MVP에서는 storage transition만 요약한다.

```python
class AutoFunctionSummaryProvider(SummaryProvider):
    def summarize(self, function_graph: FunctionGraph) -> FunctionSummary:
        ...
```

Minimal summary는 다음을 기록한다.

```
1. callee entry observed storage
2. callee exit observed storage
3. exit storage가 의존하는 entry storage
4. global read/write effect
5. memory write effect
6. callee 내부 call에 적용된 summary edge
```

금지:

```
- arg
- return
- param
- ABI
- cdecl
- Win64
- SysV
```

Auto summary도 convention-free storage transition만 표현한다.

### 13.4 recursive/SCC summary 정책

SCC가 있는 경우 MVP에서는 recursive fixed-point summary를 완전 구현하지 않는다.

```
1. SCC 크기가 1이고 self-loop가 없으면 일반 bottom-up summary를 만든다.
2. SCC 크기가 2 이상이거나 self-loop가 있으면 recursive_scc로 표시한다.
3. recursive_scc에 수동/기존 summary가 있으면 사용한다.
4. 없으면 unresolved_call_boundary 또는 recursive_summary_unavailable warning으로 멈춘다.
5. source로 확정하지 않는다.
```

Future work:

```
- SCC 내부 fixed-point summary
- widening 기반 recursive summary
- summary refinement iteration
```

---

## 14. Function Summary schema

기존 summary는 argument / return 용어를 사용하기 쉽다. V8에서는 storage transition summary로 표현한다.

### 14.1 Core summary 예시

```json
{
  "function": "identity_like",
  "entry_observed_storages": [
    {
      "id": "entry_stack_read_0",
      "storage": {
        "space": "stack",
        "base": "FRAME_BASE",
        "offset": 8,
        "size": 4
      }
    }
  ],
  "exit_observed_storages": [
    {
      "id": "exit_reg_0",
      "storage": {
        "space": "reg",
        "reg": "REG_A",
        "size": 4
      },
      "depends_on": ["entry_stack_read_0"]
    }
  ],
  "memory_effects": [],
  "warnings": []
}
```

### 14.2 여러 output storage를 보존하는 summary 예시

```json
{
  "function": "swap_like",
  "entry_observed_storages": [
    {
      "id": "entry_reg_a",
      "storage": {
        "space": "reg",
        "reg": "REG_A",
        "size": 8
      }
    },
    {
      "id": "entry_reg_b",
      "storage": {
        "space": "reg",
        "reg": "REG_B",
        "size": 8
      }
    }
  ],
  "exit_observed_storages": [
    {
      "id": "exit_reg_a",
      "storage": {
        "space": "reg",
        "reg": "REG_A",
        "size": 8
      },
      "depends_on": ["entry_reg_b"]
    },
    {
      "id": "exit_reg_b",
      "storage": {
        "space": "reg",
        "reg": "REG_B",
        "size": 8
      },
      "depends_on": ["entry_reg_a"]
    }
  ],
  "memory_effects": []
}
```

### 14.3 Optional interpretation annotation

외부 annotation은 core summary와 분리한다.

```json
{
  "interpretation_annotations": [
    {
      "value": "entry_stack_read_0",
      "label": "possible_call_input_0",
      "confidence": "external_interpretation"
    },
    {
      "value": "exit_reg_0",
      "label": "possible_return_like_storage",
      "confidence": "external_interpretation"
    }
  ]
}
```

MVP에서는 optional interpretation layer를 구현하지 않아도 된다. 단, schema에는 `role: null`, `annotations: []` 같은 확장 필드를 둘 수 있다.

---

## 15. SummaryProvider / SummaryCache

### 15.1 SummaryProvider interface

```python
class SummaryProvider:
    def get_summary(
        self,
        callee_name: str,
        call_context: CallContext,
    ) -> FunctionSummary | None:
        return None
```

구현체:

```
AutoFunctionSummaryProvider
DataFlowBenchSummaryProvider
LibcSummaryProvider
JsonSummaryProvider
CompositeSummaryProvider
```

### 15.2 SummaryCache

```python
@dataclass(frozen=True)
class SummaryCacheKey:
    function_name: str
    architecture: str
    summary_mode: str
    analysis_version: str

class SummaryCache:
    def get(self, key: SummaryCacheKey) -> FunctionSummary | None:
        ...

    def put(self, key: SummaryCacheKey, summary: FunctionSummary) -> None:
        ...
```

`CompositeSummaryProvider`는 내부적으로 SummaryCache를 사용한다.

---

## 16. Memory Object Model

V8 / New V1은 memory를 단일 `mem`으로만 추적하지 않는다.

```
MemoryObject
 ├── StackObject(function/context scoped)
 ├── GlobalObject(program scoped, source 가능)
 ├── HeapObject(allocation-site scoped, 기본적으로 transfer storage)
 ├── CallBoundaryMemoryObject(call-boundary mapped)
 └── UnknownExternalObject(alias fallback)
```

### 16.1 StackObject

StackObject는 function/context namespace를 반드시 포함한다.

금지:

```
EBP_0xfffffffc
RBP_0xfffffff8
```

허용:

```
case_DFB010:root:stack:EBP:-4
dfb_source_A:call_case_DFB010_4014a3:stack:RBP:-8
foo:root:stack:RSP:+32
bar:root:stack:X29:-16
```

### 16.2 GlobalObject

GlobalObject는 function/context namespace에 속하지 않는 program-wide storage이다.

```
global:0x404020
global:symbol:g_dfb_value
global:module.exe:.data:0x404020
```

GlobalObject metadata:

```python
@dataclass(frozen=True)
class GlobalObject:
    module: str | None
    address: str
    symbol: str | None
    section: str | None
    size: int | None
```

### 16.3 global_as_source 판정 기준

```
1. 해당 global에 write event가 존재하면 global_as_storage로 우선 처리한다.
   source는 write upstream에서 찾는다.

2. 해당 global에 write event가 없고 read만 존재하면 global_as_source 후보가 될 수 있다.

3. global_as_source 확정은 configured source boundary 또는 external source rule이 있을 때만 수행한다.

4. write event가 존재하는 global을 source로도 설정한 경우:
   - write 이전 read는 global_as_source 후보
   - write 이후 read는 global_as_storage 우선
```

### 16.4 Ghidra Data Reference / Symbol 기반 GlobalObject 심볼화

Ghidra symbol 정보는 report/display 품질 향상과 configured source 매칭에 사용한다.

```
global:0x404020
→ global:symbol:g_secret
```

주의:

```
symbol이 없어도 address 기반 GlobalObject는 반드시 생성 가능해야 한다.
symbol 정보는 source 판정을 자동 확정하지 않는다.
```

### 16.5 HeapObject

HeapObject는 기본적으로 source가 아니라, source value를 전달하는 memory object이다.

```
heap:allocsite:0x401000
heap:allocsite:0x401000:offset:0
```

Allocator summary는 post-call observed storage에 heap object candidate를 붙인다.

```
foo:root:callsite:0x401000:post:reg:<REG>
  has points_to annotation:
    heap:malloc:foo:0x401000
```

Core graph에서 특정 register를 malloc return이라고 확정하지 않는다.

### 16.6 heap source 여부

기본 정책:

```
heap object 자체는 source가 아니다.
heap은 source value를 저장/전달하는 memory object다.
```

예외:

```
- read / recv / fread 같은 외부 입력 API가 heap buffer를 채우는 경우
- tainted allocator wrapper가 특정 heap object를 source로 지정하는 경우
- 분석 설정에서 특정 heap object를 source boundary로 지정한 경우
```

---

## 17. MemoryModel

```python
class MemoryModel:
    def classify_address(self, addr_expr, state) -> MemoryObject:
        ...

    def store(self, mem_object, value, state) -> ValueId:
        ...

    def load(self, mem_object, state) -> ValueId:
        ...
```

Memory object 종류:

```
local_stack
caller_stack_or_observed_storage
stack_pointer_relative
global
heap_object
call_boundary_memory_object
unknown_external
```

MVP:

```
local_stack
caller_stack_or_observed_storage
global
unknown_external
```

다음 단계:

```
heap_object
allocation-site points-to
call_boundary_memory_object
```

future work:

```
byte_range
field_sensitive_object
precise alias_group
```

---

## 18. ProgramSliceGraph / FunctionGraph

### 18.1 ProgramSliceGraph

```python
class ProgramSliceGraph:
    def __init__(self):
        self.functions: dict[str, FunctionGraph] = {}
        self.callsites: dict[str, CallContext] = {}
        self.boundary_edges: list[BoundaryEdge] = []

        self.call_graph: nx.DiGraph = nx.DiGraph()
        self.scc_map: dict[str, int] = {}
```

### 18.2 FunctionGraph

```python
class FunctionGraph:
    function_name: str
    context_id: str
    architecture: ArchitectureSpec

    cfg: nx.DiGraph
    slice_graph: nx.DiGraph

    entry_state: State
    exit_states: list[State]

    callee_entry_observed_index: dict[StorageKey, ValueId]
    exit_output_index: dict[StorageKey, ValueId]

    stack_namespace: str

    is_recursive: bool = False
    scc_id: int | None = None
```

---

## 19. Context sensitivity / SCC 정책

### 19.1 MVP 정책

```
default:
  context = "root"

interprocedural inline expansion:
  max_call_depth = 1
  max_context_sensitivity = 1-CFA
```

### 19.2 SCC 처리

```
- Phase 5 시작 전에 direct call target을 수집해 ProgramSliceGraph.call_graph를 구성한다.
- call_graph에서 SCC를 계산한다.
- SCC 크기가 2 이상이거나 self-loop가 있으면 해당 function은 is_recursive=True로 표시한다.
- is_recursive=True 함수는 inline expansion하지 않고 summary fallback을 우선 사용한다.
- summary가 없으면 unresolved_call_boundary warning으로 남긴다.
```

Ghidra function manager의 call graph 정보를 adapter로 사용할 수 있다.

```python
for func in program.getFunctionManager().getFunctions(True):
    for called in func.getCalledFunctions(monitor):
        call_graph.add_edge(func.getName(), called.getName())
```

주의:

```
이 정보는 direct call target discovery와 SCC 감지에만 사용한다.
calling convention 추론에 사용하지 않는다.
```

---

## 20. BackwardSliceQuery

```python
class BackwardSliceQuery:
    def __init__(self, program_graph, edge_policy):
        ...

    def run(self, target: ValueId) -> SliceResult:
        ...
```

기본 동작:

```
1. target value에서 시작한다.
2. slice_graph.predecessors(node)를 확인한다.
3. edge kind가 policy에 포함되면 따라간다.
4. CALL_POST_* node를 만나면 call boundary expansion 가능 여부를 확인한다.
5. summary가 있으면 summary edge를 우선 따른다.
6. summary가 없고 inline이 가능하면 callee FunctionGraph 내부로 확장한다.
7. 둘 다 불가능하면 unresolved_call_boundary로 남긴다.
```

Pseudo-code:

```python
def expand_call_boundary(node, context):
    if summary_available(node.callee):
        return follow_summary_edges(node)

    if can_inline(node.callee, context):
        return inline_expand_callee(node)

    return unresolved_call_boundary(node)
```

정책 우선순위:

```
1. summary 우선
2. inline은 선택적 precision enhancement
3. summary도 없고 inline도 불가능하면 unresolved
```

---

## 21. Control dependency

branch condition을 explicit `control` edge로 추가한다.

```python
slice_graph.add_edge(
    branch_condition_value,
    phi_node,
    kind="control",
    condition_kind="branch_condition",
    confidence="cfg_condition",
)
```

Data-only slice에서는 제외한다.
Data+control slice에서는 포함한다.

DFB010은 control edge가 있어야 올바르게 검증할 수 있다.

```
dfb_source_C:
  control source로는 허용
  data source로는 forbidden
```

따라서 control edge 구현은 interprocedural inline expansion보다 먼저 구현한다.

---

## 22. Loop / fixed-point CFG 처리

worklist fixed-point 방식으로 변경한다.

```python
worklist = [entry_block]

while worklist:
    block = worklist.pop(0)

    new_in = merge(predecessor_out_states)
    old_in = block_in_states.get(block)

    if new_in == old_in and block in block_out_states:
        continue

    block_in_states[block] = new_in
    new_out = process_block(block, new_in)

    if new_out != block_out_states.get(block):
        block_out_states[block] = new_out
        worklist.extend(cfg.successors(block))
```

제한:

```
max_iterations_per_function
max_phi_inputs
widen_unknown_after_limit
```

widening 정책:

```python
ValueId(
    function=function_name,
    context=context_id,
    space="widened",
    key="*",
    version=N,
)
```

Backward slice에서 widened node를 만나면:

```
1. source로 확정하지 않는다.
2. sound over-approx leaf로 표시한다.
3. WARN 태그를 붙이고 traversal을 멈춘다.
4. report에 "analysis widened due to loop/phi limit"를 출력한다.
```

TODO Phase 4+:

```
State에 content_hash를 추가한다.
worklist convergence 비교는 dict equality 대신 content_hash 우선 비교를 사용한다.
```

---

## 23. Source/Sink binder

Core engine은 `dfb_source_*`, `dfb_sink_*` 이름을 몰라야 한다.

```python
class BoundaryBinder:
    def bind_call(self, callsite, state) -> BoundaryBinding | None:
        ...

class DataFlowBenchBoundaryBinder(BoundaryBinder):
    ...
```

DataFlowBench adapter가 다음 synthetic node를 만든다.

```
SOURCE_RET
SINK_OBSERVED_STORAGE
GLOBAL_SOURCE
EXTERNAL_INPUT_SOURCE
```

기존 `SINK_ANCHOR(args=...)`는 다음처럼 변경한다.

```
SINK_ANCHOR(observed_storages=...)
```

---

## 24. Expected validation

V8에서는 data/control/global source 구분을 지원해야 한다.

```json
{
  "expected_data_sources": [],
  "expected_control_sources": [],
  "expected_global_sources": [],
  "forbidden_data_sources": [],
  "forbidden_control_sources": [],
  "expected_features": [],
  "allowed_warnings": []
}
```

호환 규칙:

```
expected_sources가 있으면 expected_data_sources로 간주한다.
forbidden_sources가 있으면 forbidden_data_sources로 간주한다.
```

---

## 25. Report / Graph export

### 25.1 Report edge kind 표시

```
SINK_OBSERVED_STORAGE0
└── [data] caller:REG#5
    └── [call_out_reg callsite=0x4014a3 reg=<REG>] callee:exit:<REG>#2
        └── [data] callee:stack:<BASE>:+8#0
            └── [call_in_stack callsite=0x4014a3] caller:pre_call_stack_storage0
```

### 25.2 optional interpretation 분리

```
Core:
  caller post-call observed storage depends on callee exit observed storage.

Optional interpretation:
  caller post-call observed storage may behave like return-like storage.
  confidence: external_interpretation
```

### 25.3 unresolved / widened 표시

```
[unresolved_call_boundary]
callee target unknown
storage: reg <REG>
action: stopped at call boundary

[recursive_summary_unavailable]
function: foo
scc_id: 3
action: stopped at recursive call boundary
source_status: not_source

[widened_unknown]
reason: loop_or_phi_limit
source_status: not_source
```

### 25.4 GraphExporter

```python
class GraphExporter:
    def export_json(self, graph, path): ...
    def export_graphml(self, graph, path): ...
    def export_dot(self, graph, path): ...
```

필수 output:

```
slice_graph.json
slice_graph.graphml
slice_graph.dot
cfg.graphml
```

GraphML / DOT에서 다음 metadata가 보여야 한다.

```
node kind
edge kind
function
context
architecture
storage
callsite
confidence
source role
warning
```

---

## 26. 기존 이름 변경 목록

```
self.G
→ self.slice_graph

pending_stack_args
→ pre_call_observed_stack_writes

args
→ observed_storages

anchor_arg0
→ sink_observed_storage0

CALL_RET
→ CALL_POST_REG

CALL_RESET
→ CALLSITE_OPAQUE_BOUNDARY

CALL_CLOBBER
→ CALL_POST_REG 또는 CALL_POST_MEM

arg0_to_ret_summary
→ observed_storage_to_exit_storage_summary

out_arg
→ destination_observed_storage_index

value_arg
→ source_observed_storage_index

source/sink callsite binder
→ BoundaryBinder

CallInputBinder
→ CallBoundaryMapper

interproc_arg
→ call_in_stack / call_in_reg / call_in_mem

interproc_reg_effect
→ call_out_reg

interproc_global_effect
→ call_out_global
```

---

## 27. Phase별 구현 순서

### Phase 1: Walking Skeleton

목표:

```
DFB001 / DFB002 PASS
```

작업:

```
1. 새 패키지 구조 생성
2. Low P-code JSON loader 생성
3. ArchitectureSpec.from_preset("x86") shell 생성
4. minimal canonicalize_register() 구현
5. ValueId 도입
6. slice_graph와 cfg 분리
7. CFGBuilder fallback 구현
8. BackwardSliceQuery 구현
9. ExpectedValidator 이식
10. GraphExporter 최소 구현
```

완료 조건:

```
- DFB001 direct value PASS
- DFB002 arithmetic value PASS
- graph export가 최소 동작
- report가 edge kind를 출력
```

### Phase 2: Convention-free Call Boundary Skeleton

목표:

```
CALL_POST_* synthetic node 생성 정책 확정
단일 함수 내 call boundary가 stale dependency를 만들지 않도록 함
```

작업:

```
1. CALL_RET / CALL_RESET / CALL_CLOBBER 용어 제거
2. CALLSITE / CALL_PRE_* / CALL_POST_* node 도입
3. safe-lazy mode로 CALL_POST_REG candidate 생성
4. CallResolver 분리
5. CallBoundaryMapper 도입
6. call_in_reg / call_in_stack은 candidate confidence로만 생성
7. Ghidra Low P-code CALL 이후 output은 synthetic node로 직접 삽입
```

### Phase 3: Control Dependency

목표:

```
DFB010 PASS
```

작업:

```
1. control edge 추가
2. PHI node에 branch condition control edge 연결
3. data-only slice와 data+control slice edge policy 분리
4. expected_data_sources / expected_control_sources 지원
```

### Phase 4: Memory + Architecture Expansion

목표:

```
global / heap skeleton
architecture storage 확장
```

작업:

```
1. RegisterStorage / StackStorage 정밀화
2. Ghidra Language API 기반 ArchitectureSpec 생성
3. MemoryObject / MemoryModel 도입
4. MemoryRegionClassifier 로직 흡수
5. GlobalObject 및 global_source_index 구현
6. Ghidra Data Reference / Symbol 기반 global 심볼화
7. HeapObject allocation-site skeleton 구현
8. unknown_heap_alias_group fallback 구현
```

### Phase 5: Interprocedural Skeleton + Bottom-up Auto Summary

목표:

```
direct call 기반 interprocedural backward slice skeleton
분석 가능한 내부 함수에 대해 summary coverage 확보
```

작업:

```
1. ProgramSliceGraph.call_graph 추가
2. CallResolver로 direct call target 수집
3. Ghidra call graph adapter 추가 가능
4. SCC 계산 및 FunctionGraph.is_recursive 설정
5. SCC condensation graph 생성
6. reverse-topological order로 FunctionGraph build
7. callee_entry_observed_index / exit_output_index 기록
8. Minimal AutoFunctionSummaryProvider 구현
9. FunctionGraph 빌드 직후 FunctionSummary 생성
10. SummaryCache에 자동 summary 저장
11. caller 분석 시 callee summary를 summary edge로 적용
12. call_in_reg candidate를 use-before-def 기반으로 verified 승격
13. call_out_reg / call_out_mem / call_out_global edge 생성
14. max_call_depth = 1은 inline expansion에만 적용
15. summary traversal은 depth를 소비하지 않음
16. recursion/SCC는 summary fallback 또는 unresolved boundary 처리
```

### Phase 6: Summary Refinement / Libc / Cache 고도화

목표:

```
summary 품질 개선 및 반복 분석 비용 감소
```

작업:

```
1. CompositeSummaryProvider 구현
2. SummaryCache 고도화
3. DataFlowBenchSummaryProvider 분리
4. LibcSummaryProvider로 memcpy/memmove/strcpy/memset 이동
5. summary_data / summary_memory edge 적용
6. JSON SummaryProvider 구현
7. AutoFunctionSummaryProvider refinement
8. recursive SCC summary는 future work로 유지
9. byte-range / field-sensitive memory는 future work로 유지
```

### Phase 7: Symbol / PDB Overlay (post-core, optional)

진입 조건:

```
core가 심볼 없이 DataFlowBench recall 100% 달성(DoD) 이후에 착수
```

목표:

```
PDB/심볼을 optional overlay로 얹어 라벨/타입/검증을 정밀화 (core graph 불변)
```

작업:

```
1. frontend/pdb_loader.py 추가 (PDB/심볼/타입/라인 적재)
2. frontend/symbol_type_service.py 추가 ((module, address|storage) -> name/type/field)
3. StackObject/GlobalObject에 symbol/type/field annotation (attribute-only, edge topology 불변)
4. report에 symbolized 라벨 + 타입 provenance 표시
5. PDB 물리 매핑은 candidate로 생성 -> 관찰 dataflow 일치 시 verified 승격
6. SummaryCacheKey에 symbol source(pdb_hash) 추가
7. 기본값 off (opt-in), graceful degradation
```

완료 조건:

```
- PDB on/off에서 core slice 결과(node/edge)가 동일
- PDB on에서 라벨/타입 provenance가 report에 표시
```

### Phase 8: 동적 연계 & 에이전트 오버레이 (post-core, optional)

진입 조건:

```
core(±PDB)가 정적으로 DataFlowBench recall 100% 달성 이후에 착수
```

목표:

```
정적 slice 위에 디버거 backtrace 경로 필터 + 에이전트 Frida 후킹/모니터링/변조를 optional overlay로 얹는다 (core graph 불변)
```

작업:

```
1. dynamic/trace_loader.py: backtrace/trace -> slice 경로 필터
2. dynamic/chokepoint_analyzer.py: dominator/cut 기반 must-pass 구간 식별 (read-only)
3. dynamic/frida_bridge.py: 후킹 monitor / value modify
4. interface/slice_mcp_server.py: API/MCP 구멍 (query_chokepoints / get_hook_targets / ingest_runtime_observation / write_value)
5. 기본값 off (opt-in), core/analysis/query 불변
```

완료 조건:

```
- 동적 overlay on/off에서 core slice 결과(node/edge)가 동일
- backtrace 입력 시 실행 경로만 필터링되어 표시
- agent가 chokepoint를 조회하고 후킹을 통해 monitor/modify 가능
```

---

## 28. V8 MVP 목표 케이스

```
DFB001 direct value
DFB002 arithmetic value
DFB010 branch phi
DFB024~026 global
DFB030~031 heap
DFB050 identity call
DFB056 storage-to-exit-storage summary
DFB058 storage-to-memory-effect summary
DFB120 memcpy

x86-64 register storage case
x86-64 stack storage case
AArch64 register storage smoke test
```

DFB010 기대:

```
data source:
  dfb_source_A.ret
  dfb_source_B.ret

control source:
  dfb_source_C.ret

forbidden data source:
  dfb_source_C.ret
```

DataFlowBench label에서는 `ret` 표현이 남아도 된다. 단, core graph 내부 node/edge에서는 return으로 취급하지 않는다.

---

## 29. Non-goals for V8 MVP

```
- Full heap object recovery
- Full byte-range memory precision
- Precise indirect call resolution
- Recursive interprocedural expansion without depth limit
- Full calling convention inference
- High P-code dependency
- Decompiler variable name dependency
- Full field-sensitive struct tracking
- Full ARM64 production-quality support
- Full register alias precision
- SCC 내부 fixed-point summary
- Symbol/PDB overlay (Phase 7, post-core optional layer)
- 동적 실행 연계 / 에이전트 후킹 overlay (§34, Phase 8, post-core optional layer)
```

단, ArchitectureSpec과 Storage model은 처음부터 64-bit / ARM64 확장을 막지 않는 형태로 설계한다.

---

## 30. v5~v7 코드에서 재사용 가능한 로직

```
_stack_expr_from_node
→ MemoryModel.classify_address
→ 거의 그대로 재사용

_const_from_node
→ analysis/const_propagator.py
→ 그대로 재사용

_build_basic_blocks
→ CFGBuilder.build()
→ nx.DiGraph 래핑 추가

_merge_block_states / PHI
→ SliceGraphBuilder
→ worklist 방식으로 재작성

_collect_data_sources
→ BackwardSliceQuery.run()
→ edge_policy 파라미터화

_validate_expected_sources
→ ExpectedValidator
→ 거의 그대로 재사용

_apply_libc_transfer_summary
→ LibcSummaryProvider
→ summary_memory edge로 변경

dfb_source_*/dfb_sink_* 처리
→ DataFlowBenchBoundaryBinder
→ core 분리

pending_stack_args 로직
→ PreCallStackWriteCollector
→ 범위 한정 로직 재설계 필요

_resolved_call_targets / _primary_target_name
→ CallResolver
→ 별도 모듈로 이동

MemoryRegionClassifier
→ MemoryModel.classify_address()
→ EBP/ESP hardcoding을 ArchitectureSpec 기반으로 변경
```

---

## 31. Codex 작업 지시 요약

Codex는 다음 순서로 수정한다.

```
1. 새 패키지 구조를 만든다.
2. 기존 v5/v6/v7 코드를 직접 수정하기보다, 필요한 로직을 새 모듈로 이동한다.
3. Low P-code JSON loader를 만든다.
4. ArchitectureSpec / RegisterStorage / StackStorage를 만든다.
5. Low P-code register varnode는 반드시 canonicalize_register() 경유하도록 한다.
6. CFGBuilder를 만든다.
7. FunctionGraph와 ProgramSliceGraph를 만든다.
8. ValueId를 도입한다.
9. slice_graph와 cfg를 분리한다.
10. exit_output_index, callee_entry_observed_index, call_pre_storage_index, call_post_storage_index를 도입한다.
11. core에서 arg / return / convention / ABI 명명 제거 여부를 점검한다.
12. CallResolver를 만든다.
13. CallBoundaryMapper를 만든다.
14. CALL_PRE_* / CALL_POST_* node와 call_in_* / call_out_* edge를 만든다.
15. Ghidra Low P-code CALL 이후 output을 synthetic node로 삽입한다.
16. CALL_POST_REG는 MVP에서 safe-lazy mode로 생성한다.
17. call_in_stack candidate 범위 제한 정책을 구현한다.
18. call_in_reg는 Phase 2 candidate, Phase 5 verified로 2단계 처리한다.
19. MemoryObject와 MemoryModel을 도입한다.
20. StackObject / GlobalObject / HeapObject / UnknownExternalObject를 구현한다.
21. global source와 global storage propagation을 분리한다.
22. heap은 allocation-site based transfer storage로 구현한다.
23. ProgramSliceGraph.call_graph / scc_map을 추가한다.
24. FunctionGraph.is_recursive / scc_id를 추가한다.
25. Phase 5에서 Minimal AutoFunctionSummaryProvider를 구현한다.
26. bottom-up reverse-topological order로 summary를 생성한다.
27. summary traversal은 max_call_depth를 소비하지 않게 한다.
28. hardcoded summary를 SummaryProvider로 이동한다.
29. SummaryCache를 만든다.
30. Summary schema를 storage transition 기반으로 변경한다.
31. BackwardSliceQuery를 만든다.
32. control edge를 Phase 3에서 구현한다.
33. ExpectedValidator를 기존 expected JSON과 호환되게 만든다.
34. report에 edge kind와 call boundary를 출력한다.
35. report에 core fact와 optional interpretation을 분리해서 출력한다.
36. report에 global / heap / widened unknown / unresolved boundary를 명확히 출력한다.
37. DFB001, DFB002, DFB010, DFB024~026, DFB030~031, DFB050, DFB056, DFB058, DFB120, x86-64 smoke case 기준으로 회귀 테스트한다.
```

---

## 32. Codex 첫 실행 프롬프트 권장안

전체 문서를 한 번에 구현하려고 하지 말고 Phase 1만 수행한다.

```
V8 / New V1 통합 설계서 기준으로 Phase 1 Walking Skeleton만 구현해줘.

목표:
- 기존 v5/v6/v7 파일은 직접 수정하지 말고 새 패키지 구조를 만든다.
- DFB001 / DFB002를 통과하는 것을 첫 gate로 삼는다.
- interprocedural, heap, full global, full 64-bit alias, ARM64 production support는 아직 구현하지 않는다.

필수 구현:
1. core/value_id.py
2. core/architecture.py
3. core/storage.py
4. core/graph.py
5. frontend/low_pcode_loader.py
6. analysis/cfg_builder.py
7. analysis/slice_graph_builder.py
8. query/backward_slice.py
9. report/expected_validator.py
10. report/graph_exporter.py

기존 코드에서 재사용:
- _build_basic_blocks
- _const_from_node
- _collect_data_sources
- _validate_expected_sources

금지:
- arg / return / cdecl / ABI 용어를 core에 넣지 말 것
- CALL_RET / CALL_RESET / CALL_CLOBBER를 새 코드에 만들지 말 것

완료 조건:
- DFB001 PASS
- DFB002 PASS
- slice_graph와 cfg가 분리되어 export됨
- report에 edge kind가 출력됨
```

---

## 33. 심볼/PDB 오버레이 (post-core, optional layer)

<aside>
🧩

convention-free core가 완성된 뒤(심볼 없이 DataFlowBench recall 100% 달성 후) 얹는 **가산적 overlay**. core graph(node/edge/storage)는 PDB 유무와 무관하게 동일하며, PDB는 convention-free 정책을 대체하지 않는다.

</aside>

### 33.1 원칙

```
PDB/심볼은 core가 아니라 core 위에 얹는 optional overlay다.
core graph는 PDB 유무와 무관하게 동일하다.
PDB는 convention-free 정책을 대체하지 않고, 그 위에 라벨/타입/검증을 더한다.
이 레이어는 core가 DataFlowBench recall 100%(심볼 없이)를 달성한 뒤에 착수한다.
기본값은 off. opt-in.
```

### 33.2 신뢰 등급 (무엇을 믿고 무엇을 검증하나)

```
신뢰 (정적 사실, 그대로 채택):
- 함수 이름 / 함수 경계
- 타입, 구조체 레이아웃, 필드 이름/오프셋
- 전역 변수 주소/타입
- 소스 라인 매핑

힌트+검증 (관찰 dataflow와 일치할 때만 채택):
- 특정 callsite에서 값이 실린 물리 register/stack 위치
- 지역 변수 storage 위치와 live range (최적화 빌드에서 불완전)
- 물리 출력 위치(return-like storage)

금지:
- PDB signature(param/return)를 core의 arg/return으로 강제 주입
- PDB를 근거로 calling convention을 core에 도입
```

confidence 등급 통합:

```
pdb_static_verified > observed > heuristic > widened_unknown
pdb_location_candidate: PDB가 주장하나 dataflow 미검증 -> 검증 전엨 candidate
```

### 33.3 컴포넌트 배치 (frontend overlay only)

```
frontend/
  pdb_loader.py            # PDB/심볼/타입/라인 적재 (신규)
  symbol_type_service.py   # (module, address|storage) -> name/type/field (신규)
report/
  text_report.py           # symbolized 라벨 + 타입 provenance (확장)
```

```
- core/ analysis/ query/ 의 node/edge/storage 생성 로직은 수정하지 않는다.
- symbol_type_service는 ValueId/StorageKey를 받아 display label/type만 정밀화한다.
```

### 33.4 타입 provenance

```
mem[RBP-0x30]      -> player.hp
global:0x404020    -> g_secret : int
```

```
- MemoryObject(§16)의 StackObject/GlobalObject에 symbol/type/field annotation을 붙인다(별도 attribute, edge topology 불변).
- struct 필드 오프셋이 있으면 field-named sub-object로 display (분석 정밀도가 아니라 표시/매칭 용도).
```

### 33.5 캐시 / 멀티모듈

```
- SummaryCacheKey(§15.2)에 symbol source(pdb_hash) 추가 -> 심볼 보강 summary를 convention-free summary와 별도 캐싱.
- 멀티 바이너리 프로젝트와 결합 시 module + build/pdb hash로 캐시 무효화.
```

### 33.6 graceful degradation

```
- PDB 없음: 전부 convention-free (floor).
- PDB 일부만: 함수별로 신뢰 등급이 섞임 (partial overlay).
- PDB 있으나 dataflow와 불일치: 해당 매핑은 candidate로 강등, core 결과 우선.
```

### 33.7 [AGENTS.md](http://AGENTS.md) 불변식과의 관계

```
이 overlay는 core AGENTS.md invariant(arg/return/convention 금지)에 포함하지 않는다.
coding agent가 PDB를 core에 엮지 않도록, PDB 작업은 별도 post-core 작업으로만 지시한다.
```

---
 