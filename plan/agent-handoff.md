# FBVBS agent handoff

This file is the repo-local continuation note for the next AI agent. Treat it as the in-repository equivalent of the Copilot session `plan.md`.

## Non-negotiable architecture decisions

- **Ada/SPARK is the authoritative implementation path** for hypervisor orchestration, lifecycle, policy, ABI validation, audit logic, and trusted-service semantics.
- **Python is tooling only** in this repository. `fbvbs_spec/` parses `plan/fbvbs-design.md` and regenerates checked-in artifacts under `generated/`; it is not runtime hypervisor code.
- **C is allowed only as a tiny high-assurance hardware leaf boundary** such as VMX/SVM instruction wrappers or similarly narrow CPU/MSR/CPUID helpers.
- Any retained C must remain leaf-only and non-policy, with the repo direction still requiring **MISRA C compliance, static analysis, and formal-verification evidence** before it can be trusted.

## Current repository state

### 1. Executable-spec toolchain

- Normative source: `plan/fbvbs-design.md`
- Parser/generator: `fbvbs_spec/`
- Checked-in outputs: `generated/`
- Spec/tool tests: `tests/test_spec_parser.py`

### 2. Hypervisor workspace

- Main workspace: `hypervisor/`
- Ada/SPARK code: `hypervisor/ada/src/`
- Retained C migration/leaf code: `hypervisor/src/`
- C assurance gate: `make -C hypervisor analyze`

### 3. Ada/SPARK implementation already modeled

The current Ada/SPARK path already covers a large frozen-ABI subset, including:

- command sequencing and host callsite validation
- partition create/destroy/measure/load/start/recover/status/quiesce/resume/fault-info
- memory allocate/map/unmap/set-permission/register-shared/unregister-shared/release
- VM run, inject-interrupt, vCPU status, register set/get, and selected map-memory behavior
- selected KCI control calls
- selected KSI / IKS / SKS service calls
- audit mirror-info / boot-id
- selected diagnostic queries

The executable assertion harness is `hypervisor/ada/src/fbvbs_hypervisor_main.adb`.

## Verified commands

These commands were the validated acceptance path in the last working session:

```bash
python3 -m unittest discover -s tests -v
make -C hypervisor analyze
make -C hypervisor clean all test
gprbuild -P hypervisor/ada/fbvbs_hypervisor.gpr
(
  cd hypervisor/ada
  alr build
  ./fbvbs_hypervisor_main
)
```

## Most important files to read first

- `README.md`
- `plan/about-a-hypervisor.md`
- `plan/implementation-plan.json`
- `plan/implementation-todo.json`
- `generated/roadmap.json`
- `hypervisor/ada/src/fbvbs-abi.ads`
- `hypervisor/ada/src/fbvbs-hypercall_dispatcher.ads`
- `hypervisor/ada/src/fbvbs-hypercall_dispatcher.adb`
- `hypervisor/ada/src/fbvbs-partitions.ads`
- `hypervisor/ada/src/fbvbs-partitions.adb`
- `hypervisor/ada/src/fbvbs-memory.ads`
- `hypervisor/ada/src/fbvbs-memory.adb`
- `hypervisor/ada/src/fbvbs-ksi.ads`
- `hypervisor/ada/src/fbvbs-ksi.adb`
- `hypervisor/ada/src/fbvbs-sks.ads`
- `hypervisor/ada/src/fbvbs-sks.adb`
- `hypervisor/ada/src/fbvbs_hypervisor_main.adb`
- `tests/test_hypervisor_implementation.py`

## Important status note

`plan/implementation-todo.json` currently shows the tracked Ada dispatcher migration slices as done. That does **not** mean the repository is a finished production hypervisor; it means the currently tracked repo-local migration slices were completed.

The roadmap in `generated/roadmap.json` still describes a broader end state than what this repository currently implements concretely. If continuing implementation, treat the current code as an **Ada/SPARK executable model / migration path**, not as the final bare-metal microhypervisor promised by the full roadmap.

## Best next concrete code slices

If the next agent is asked to keep implementing meaningful code in this repository, the best surgical next slices are:

### Slice A: tighten `VM_MAP_MEMORY`

Relevant files:

- `hypervisor/ada/src/fbvbs-hypercall_dispatcher.adb`
- `hypervisor/ada/src/fbvbs-memory.ads`
- `hypervisor/ada/src/fbvbs-memory.adb`
- `hypervisor/ada/src/fbvbs_hypervisor_main.adb`

Why:

- `VM_MAP_MEMORY` is currently dispatched through the same path as generic `MEMORY_MAP`.
- The design document gives it VM-specific semantics (`vmm.ko` caller, valid in `Created`/`Measured`/`Loaded`/`Runnable`/`Quiesced`, invalid in `Running`/`Faulted`, and hypervisor-retained frame-choice authority).
- The next improvement is to split the `Call_VM_Map_Memory` branch and enforce VM-specific checks explicitly instead of aliasing it to generic memory mapping.

### Slice B: tighten `KSI_REGISTER_TIER_B`

Relevant files:

- `hypervisor/ada/src/fbvbs-abi.ads`
- `hypervisor/ada/src/fbvbs-ksi.ads`
- `hypervisor/ada/src/fbvbs-ksi.adb`
- `hypervisor/ada/src/fbvbs-hypercall_dispatcher.adb`
- `hypervisor/ada/src/fbvbs_hypervisor_main.adb`

Why:

- `KSI_REGISTER_TIER_B` is currently handled together with `KSI_REGISTER_TIER_A`.
- The design gives Tier B extra semantics (`protection_class`, shadow-management intent, extra resource/error surface).
- The next improvement is to model Tier-B-specific validation separately instead of treating it as identical to Tier A.

## Working tree caution

This repository may contain user changes and extra untracked files that were not part of the core implementation path. In particular, preserve unrelated modifications unless the user explicitly asks to clean them up.

If you see files such as:

- `ANALYSIS_INDEX.md`
- `IMPLEMENTATION_SUMMARY.md`
- `IMPLEMENTATION_STATUS_REPORT.txt`
- `IMPLEMENTATION_QUICK_REFERENCE.txt`

verify with the user before deleting or rewriting them.

## Short continuation rule-set

1. Do not expand C beyond tiny hardware-boundary leaves.
2. Prefer extending Ada/SPARK models and dispatcher coverage over adding new legacy-C logic.
3. Keep repo-local planning artifacts inside `plan/`.
4. After each substantive change, rerun the verified commands above.
5. If a new roadmap slice is too large for one edit, land the smallest Ada/SPARK-authoritative slice that still leaves the repo in a validated state.
