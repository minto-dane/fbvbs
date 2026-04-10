# Plan Directory Guide

`plan/` は、FBVBS の設計・派生仕様・実装計画・保証資料を、権威レベルごとに分けて読むための入口である。

## Authority Model

1. **最上位設計**
   - `plan/full-stack/fbvbs-design.md`
   - FBVBS 全体の設計思想、保護境界、ABI 原則、要求・保証構造の最上位ソース。
2. **共有プロファイルと全体整理**
   - `plan/shared/fbvbs-deployment-profiles.md`
   - `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md`
3. **standalone 派生設計**
   - `plan/standalone/architecture/standalone-runtime-architecture.md`
   - `plan/standalone/subsystems/*.md`
   - `plan/standalone/operations/*.md`
   - `plan/standalone/assurance/*.md`
4. **実装計画**
   - `plan/standalone/implementation/standalone-implementation-plan.md`
5. **補助資料と履歴**
   - `plan/overview/agent-handoff-summary.md`
   - `plan/full-stack/cpu-sec.md`
   - `plan/standalone/archive/`

`plan/full-stack/fbvbs-design.md` と矛盾する standalone 文書は正本ではない。standalone 配下は、full-stack 設計を上書きする場所ではなく、共有基盤を使った別プロファイルを具体化する場所として扱う。

## Directory Map

1. `plan/full-stack/`
   - authoritative architecture / requirements / assurance specification
2. `plan/shared/`
   - cross-profile definitions and machine-readable indices
3. `plan/overview/`
   - roadmap and onboarding
4. `plan/standalone/architecture/`
   - standalone runtime の派生アーキテクチャ
5. `plan/standalone/subsystems/`
   - service、storage、ownership などの subsystem 仕様
6. `plan/standalone/operations/`
   - operator、incident、audit、recovery の運用仕様
7. `plan/standalone/assurance/`
   - diagnostics ABI、compatibility、validators、evidence
8. `plan/standalone/implementation/`
   - workstream / milestone / dependency を持つ実装計画
9. `plan/standalone/archive/`
   - superseded / fragmented / historical standalone notes

## Reading Order

### First Read

1. `plan/full-stack/fbvbs-design.md`
2. `plan/shared/fbvbs-deployment-profiles.md`
3. `plan/README.md`
4. `plan/document-catalog.md`
5. `plan/fbvbs-design-traceability.md`

### Standalone Runtime Implementation

1. `plan/standalone/README.md`
2. `plan/standalone/architecture/standalone-runtime-architecture.md`
3. `plan/standalone/subsystems/service-management.md`
4. `plan/standalone/subsystems/storage-and-state-management.md`
5. `plan/standalone/assurance/management-diagnostics-abi.md`
6. `plan/standalone/implementation/standalone-implementation-plan.md`

### Operator / Diagnostics / Audit Work

1. `plan/standalone/operations/operator-control-plane.md`
2. `plan/standalone/operations/incident-audit-and-recovery.md`
3. `plan/standalone/assurance/management-diagnostics-abi.md`
4. `plan/standalone/assurance/evidence-and-support-artifacts.md`
5. `plan/standalone/assurance/compatibility-and-versioning.md`

### Validation / Assurance Work

1. `plan/full-stack/fbvbs-design.md` sections 2.2, 17, 42-45, Appendix G, Appendix K
2. `plan/standalone/assurance/verification-and-validator-suite.md`
3. `plan/standalone/assurance/compatibility-and-versioning.md`
4. `plan/standalone/assurance/evidence-and-support-artifacts.md`
5. `plan/fbvbs-design-traceability.md`

### Historical Material

旧 standalone 断片文書は `plan/standalone/archive/README.md` から辿る。archive は履歴保全用であり、現行仕様の参照順序には入らない。
