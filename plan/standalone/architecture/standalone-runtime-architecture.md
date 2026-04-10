# Standalone Runtime Architecture

- Status: Active
- Authority level: derived architecture
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 2.1, 9-20, 37, 49-50
- Depends on: `plan/shared/fbvbs-deployment-profiles.md`
- Supersedes: `plan/standalone/archive/hypervisor-standalone-production-architecture.md`
- Intended audience: runtime 実装者、設計レビュー担当、後続実装エージェント

## Role Of This Document

本書は、shared retained-C foundation を **standalone product profile** として成立させるための派生アーキテクチャである。full-stack 仕様の代替ではなく、`plan/full-stack/fbvbs-design.md` で定義されたマイクロハイパーバイザー原理、partition/state machine、capability/ownership、audit 原則を、standalone runtime に写像する。

## Profile Boundary

### Reused From The Authoritative Design

1. microhypervisor の最小責務
2. partition / vCPU / memory / command page の所有権規律
3. fail-closed hypercall ABI 原則
4. OOB audit を最優先とする監査境界
5. IOMMU / interrupt remapping / second-stage translation の強制

### Added For The Standalone Profile

1. management diagnostics surface
2. storage pool / virtual disk 管理
3. operator command plane と optional OCS/VCD
4. standalone incident / evidence / compatibility discipline

### Explicitly Excluded

1. FreeBSD 保護を目的とする KCI / KSI / IKS / SKS / UVS semantics
2. `fbvbs.ko` と FreeBSD kernel intervention points
3. `bhyve` / `vmm` との full-stack lifecycle contract
4. standalone 文書による full-stack 要求の上書き

## Runtime Layers

| Layer | Responsibility | Standalone interpretation |
|---|---|---|
| Isolation substrate | CPU, second-stage translation, IOMMU, interrupt control | shared retained-C foundation をそのまま使用 |
| Resource lifecycle | partition, vCPU, memory object, teardown, ownership | standalone でも authoritative state machine を共有 |
| Management control plane | command ABI, authorization, rate-limit, mutation preconditions | operator / host 管理操作に限定 |
| Management services | diagnostics, storage-control, optional operator-console | standalone 固有の付加価値 |
| Operations and assurance | audit, incident, compatibility, evidence | product closure の要件 |

## Authoritative Standalone Surfaces

### Control Plane

standalone の control plane は host 管理呼び出しと optional OCS を含むが、どちらも `plan/full-stack/fbvbs-design.md` の ABI 原則から逸脱してはならない。caller identity は runtime が決定し、reserved-zero、owner-bound command page、fail-closed error discipline を維持する。

### Storage Plane

storage pool / vdisk 管理は standalone の主要 subsystem だが、ownership と lifecycle は general partition/object discipline の派生形として扱う。storage を特別扱いして別の権限理論を持ち込まない。

### Operator Plane

operator plane は optional であり、OCS が無効でも runtime 本体は成立しなければならない。OCS/VCD は管理支援 surface であって、transport ownership や audit ownership をハイパーバイザーから奪ってはならない。

### Audit And Assurance Plane

standalone-ready 判定には、diagnostics ABI、compatibility matrix、validator suite、evidence pack が必要である。これらは実装補助ではなく、runtime の production claim を支える派生仕様群として扱う。

## Cross-Cutting Invariants

1. OCS は optional extension であり、本体成立条件ではない
2. management ABI でも guest-facing ABI と同じ fail-closed discipline を維持する
3. storage / diagnostics / operator 操作も audit 境界の外に出さない
4. revoke / destroy / detach 後に stale visibility を残さない
5. standalone の service partition は万能権限主体にしない
6. collector loss や evidence 欠落を fail-open の口実にしない

## Companion Documents

1. `../subsystems/service-management.md`
2. `../subsystems/storage-and-state-management.md`
3. `../operations/operator-control-plane.md`
4. `../operations/incident-audit-and-recovery.md`
5. `../assurance/management-diagnostics-abi.md`
6. `../implementation/standalone-implementation-plan.md`

## Architecture Gaps That Still Require Closure

1. authoritative IOMMU / interrupt-remapping 実機閉鎖
2. final host deprivilege / `VMLAUNCH` handoff
3. append-only OOB audit chain の production-grade closure
4. standalone release evidence の hardware campaign
5. update / artifact / secure-clock discipline の standalone 具体化
