# About-a-Hypervisor Execution Plan

## Goal

Drive the repository toward the end state described in `plan/about-a-hypervisor.md`:

- Ada/SPARK as the authoritative implementation
- retained C reduced to tiny hardware-boundary leaves
- architecture converging toward capability-based, dynamic, deprivileged-host hypervisor structure

## Current iteration

### Completed in this iteration

- default C acceptance path reduced to `hypervisor/src/vmx.c`
- leaf-only public VMX interface split into `hypervisor/include/fbvbs_leaf_vmx.h`
- retained-C subset gate added for the leaf path
- bounded proof-style VMX leaf contract artifact added for the retained-C leaf
- leaf C build/test now validates only VMX probe and synthetic leaf-exit behavior
- Ada/SPARK side tightened `VM_MAP_MEMORY` and KSI Tier B target-set coupling
- repository docs updated to reflect the new retained-C boundary

### Achieved status

- Ada/SPARK authoritative path: partially achieved, active
- retained C leaf-only acceptance path: achieved for the default repository build/test path
- retained C leaf-only header boundary: achieved for the default repository build/test path
- retained C MISRA-oriented subset gate: achieved for the default repository build/test path
- retained C bounded proof artifact: achieved for the default repository build/test path
- legacy C policy/orchestration removed from default acceptance: achieved

### Remaining work

- delete or replace the legacy C policy/orchestration sources and their large migration header still present on disk
- replace the current bounded proof artifact with external Frama-C / CBMC / TrustInSoft evidence when those tools are available
- implement bare-metal Ada/SPARK kernel/runtime path instead of executable-model-only harness
- implement deprivileged FreeBSD host boot path
- implement NOVA-style kernel object model beyond the current partition-centric ABI model
- implement portal-style IPC / capability delegation model
- implement AMD SVM/GMET/NPT translation-integrity path
- produce SPARK proof artifacts and audited non-SPARK leaf boundary evidence

## Immediate next milestones

1. Remove the remaining non-leaf legacy entry points from the migration header or split it further by subsystem.
2. Replace the current proof script with external static-proof tooling outputs as soon as Frama-C / CBMC class tools are available in CI.
3. Replace any residual C-owned runtime state transitions with Ada/SPARK-owned harnesses or leaf stubs.
4. Start the bare-metal runtime skeleton needed for the deprivileged-host architecture.

## Long-range phased plan

### Phase 0. Retained-C emergency containment

Status: active, mostly achieved in the default path.

- shrink the default retained-C path to a hardware leaf only
- split the leaf public interface away from the legacy orchestration header
- add fixed-ABI assertions, subset rules, and proof-style contract evidence
- keep all new policy and orchestration on the Ada/SPARK side

Exit criteria:

- default `make -C hypervisor analyze`
- default `make -C hypervisor proof`
- default `make -C hypervisor test`
- no default path dependency on `command.c`, `partition.c`, `security.c`, `vm_policy.c`

Primary requirement alignment:

- `FBVBS-REQ-0201`
- `FBVBS-REQ-1000`

### Phase 1. Legacy C retirement

Status: not achieved.

- remove or replace `command.c`, `partition.c`, `security.c`, `memory.c`, `log.c`, `vm_policy.c`, and `kernel.c`
- split the giant migration header by subsystem until no policy-orchestration declarations remain in the default trusted interface surface
- port any residual state-transition logic into Ada/SPARK packages with executable checks
- keep only the minimum assembly or non-SPARK leaf needed for hardware entry and exit

Exit criteria:

- no policy/orchestration C left in active build paths
- Ada/SPARK executable checks cover all behavior previously modeled in retired C
- retained C reduced to instruction wrappers and similarly tiny hardware leaves only

Primary requirement alignment:

- `FBVBS-REQ-0200`
- `FBVBS-REQ-0201`
- `FBVBS-REQ-0204`

### Phase 2. Capability-object kernel model

Status: not achieved.

- introduce NOVA-style kernel object categories for protection domains, execution contexts, scheduling contexts, memory spaces, DMA spaces, and portals
- move from the current partition-centric modeling surface toward capability delegation and revocation
- define object-lifecycle invariants in Ada/SPARK contracts
- add object-level negative tests and state-machine checks

Exit criteria:

- capability delegation is explicit and owned only by the microhypervisor
- object creation, destruction, delegation, and revocation have Ada/SPARK-owned checks
- the ABI no longer depends on partition-centric shortcuts where object semantics are required

Primary requirement alignment:

- `FBVBS-REQ-0204`
- `FBVBS-REQ-0205`
- `FBVBS-REQ-0207`

### Phase 3. Bare-metal Ada/SPARK runtime skeleton

Status: not achieved.

- replace the executable-model-only harness with a bare-metal boot path
- add early page-table setup, interrupt/trap entry points, bootstrap-page handling, and leaf VMX wrappers
- keep assembly and non-SPARK code minimized and documented as audited leaves
- establish the GNAT bare-metal runtime profile and proof boundaries

Exit criteria:

- the repository can build a bare-metal kernel artifact
- the retained assembly/C boundary is explicitly documented and small
- SPARK and non-SPARK boundaries are visible in package structure and evidence

Primary requirement alignment:

- `FBVBS-REQ-0200`
- `FBVBS-REQ-0201`
- `FBVBS-REQ-1002`

### Phase 4. Deprivileged FreeBSD host bring-up

Status: not achieved.

- define the FreeBSD host partition bootstrap path
- model and implement host command transport and mirror-log plumbing
- prove that the host runs deprivileged and does not own virtualization hardware state
- enumerate and test FreeBSD boot-time intervention points

Exit criteria:

- FreeBSD host boot path is operational under the Ada/SPARK-owned microhypervisor
- host-visible logs remain secondary while the primary audit path stays independent
- integration evidence exists for the chosen intervention points

Primary requirement alignment:

- `FBVBS-REQ-0200`
- `FBVBS-REQ-1101`
- `FBVBS-REQ-1103`

### Phase 5. Portal IPC and service partition convergence

Status: not achieved.

- implement portal-style IPC and capability-mediated service invocation
- converge KCI, KSI, IKS, SKS, and UVS onto narrow object-capability interfaces
- eliminate any remaining ad hoc cross-partition request patterns
- add audit hooks and denial-path tests for every service boundary

Exit criteria:

- service partitions communicate only through explicit portal/capability channels
- privilege transfer is narrow, audited, and reversible
- denial and spoofing paths are exercised by regression tests

Primary requirement alignment:

- `FBVBS-REQ-0502`
- `FBVBS-REQ-0506`
- `FBVBS-REQ-0600`
- `FBVBS-REQ-0701`

### Phase 6. Intel translation integrity and DMA ownership

Status: partially modeled, not production-ready.

- harden Intel VMX, EPT, HLAT, MBEC, CET, and IOMMU ownership paths
- replace synthetic-only checks with real second-level translation ownership logic
- tie DMA-space ownership and device assignment to capability objects
- add adversarial tests for code-page translation integrity and DMA remapping

Exit criteria:

- Intel path enforces the design's translation-integrity assumptions
- device passthrough is owned by microhypervisor capability state
- code integrity claims have test evidence beyond synthetic harness checks

Primary requirement alignment:

- `FBVBS-REQ-0300`
- `FBVBS-REQ-0301`
- `FBVBS-REQ-0402`

### Phase 7. AMD translation-integrity path

Status: not achieved.

- implement the AMD-specific NPT, shadow-translation, and synchronization design
- document exactly what is and is not equivalent to Intel HLAT-based claims
- build multicore adversarial tests for PTE tamper, TLB race, and update ordering
- gate any AMD readiness claim on evidence, not architectural analogy

Exit criteria:

- AMD path has concrete implementation and adversarial evidence
- no documentation claims unsupported HLAT equivalence
- production-readiness gates remain closed until campaign evidence exists

Primary requirement alignment:

- `FBVBS-REQ-0302`
- `FBVBS-REQ-0303`
- `FBVBS-REQ-1100`

### Phase 8. Assurance closure and release governance

Status: not achieved.

- connect requirements, code, tests, proof artifacts, and review records bidirectionally
- add MC/DC or an explicitly justified alternative coverage regime
- add fuzzing, supply-chain evidence, reproducible builds, and signed provenance
- close the gap between repository-local proof artifacts and release-grade assurance evidence

Exit criteria:

- traceability is audit-ready
- release pipeline emits SBOM and provenance
- coverage and review records exist for TCB changes
- proof claims are scoped, reproducible, and externally reviewable

Primary requirement alignment:

- `FBVBS-REQ-1000`
- `FBVBS-REQ-1001`
- `FBVBS-REQ-1004`
- `FBVBS-REQ-1005`
- `FBVBS-REQ-1006`
