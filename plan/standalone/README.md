# Standalone Planning Guide

- Status: Active
- Authority level: standalone profile index
- Source-of-truth: `plan/full-stack/fbvbs-design.md`, `plan/shared/fbvbs-deployment-profiles.md`
- Depends on: `plan/README.md`
- Intended audience: standalone runtime 実装者、運用設計者、検証担当

## Purpose

このディレクトリは、共有 retained-C 基盤を使う **standalone FBVBS microhypervisor profile** の現行参照系である。以前の flat な `plan/standalone/*.md` は、設計・運用・validator・補助メモが混在していたため、現役文書は以下の五層に再編した。

1. `architecture/`
   - standalone runtime の境界と責務
2. `subsystems/`
   - service 管理、storage / lifecycle / ownership 仕様
3. `operations/`
   - operator command plane、incident、audit、recovery
4. `assurance/`
   - diagnostics ABI、compatibility、validators、evidence
5. `implementation/`
   - workstream と milestone を持つ実装計画

`archive/` は歴史的断片の退避先であり、正本ではない。

## Current Authoritative Reading Order

1. `architecture/standalone-runtime-architecture.md`
2. `subsystems/service-management.md`
3. `subsystems/storage-and-state-management.md`
4. `operations/operator-control-plane.md`
5. `operations/incident-audit-and-recovery.md`
6. `assurance/management-diagnostics-abi.md`
7. `assurance/compatibility-and-versioning.md`
8. `assurance/verification-and-validator-suite.md`
9. `assurance/evidence-and-support-artifacts.md`
10. `implementation/standalone-implementation-plan.md`

## What This Profile Does Not Define

1. KCI / KSI / IKS / SKS / UVS の full-stack semantics
2. `fbvbs.ko` や FreeBSD 介入点
3. `bhyve` / `vmm` の full-stack integration contract
4. full-stack conformance claim

これらは `plan/full-stack/fbvbs-design.md` を正とする。
