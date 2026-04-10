# FBVBS Design Traceability

- Status: Active
- Authority level: traceability index
- Source-of-truth: `plan/full-stack/fbvbs-design.md`
- Intended audience: 設計レビュー担当、実装者、保証担当

## Purpose

本書は、`plan/full-stack/fbvbs-design.md` の主要設計根を、standalone を含む派生文書へ結び付ける。どの文書が何を具体化しているか、逆にまだ具体化が足りない領域は何かを明示する。

## Design Root To Derived Documents

| Design root in `fbvbs-design.md` | Derived / companion docs | Notes |
|---|---|---|
| 2.1 Conformance Profiles | `plan/shared/fbvbs-deployment-profiles.md`, `plan/standalone/README.md`, `plan/standalone/architecture/standalone-runtime-architecture.md` | stack と standalone の境界整理 |
| 2.2 Requirements Identification and Traceability | `plan/document-catalog.md`, `plan/fbvbs-design-traceability.md`, `plan/standalone/assurance/compatibility-and-versioning.md` | 文書分類と traceability 運用 |
| 9-10 Architectural Thesis / Logical Component Structure | `plan/standalone/architecture/standalone-runtime-architecture.md` | standalone profile への写像 |
| 13-15 OOB logging / mirror logging / panic caveats | `plan/standalone/operations/incident-audit-and-recovery.md`, `plan/standalone/assurance/evidence-and-support-artifacts.md` | audit collector と incident artifact |
| 16 Scope of the Microhypervisor | `plan/standalone/architecture/standalone-runtime-architecture.md`, `plan/standalone/implementation/standalone-implementation-plan.md` | standalone での責務境界 |
| 17 Implementation Language and Proof Boundary | `plan/standalone/assurance/verification-and-validator-suite.md` | divergence / proof readiness |
| 18 Partition Model and State Machine | `plan/standalone/subsystems/storage-and-state-management.md`, `plan/standalone/operations/operator-control-plane.md`, `plan/standalone/implementation/standalone-implementation-plan.md` | lifecycle / preconditions / teardown |
| 19 Capability and Ownership Model | `plan/standalone/subsystems/service-management.md`, `plan/standalone/subsystems/storage-and-state-management.md`, `plan/standalone/operations/operator-control-plane.md` | ownership / capability / role |
| 20 Hypercall ABI Principles | `plan/standalone/assurance/management-diagnostics-abi.md`, `plan/standalone/operations/operator-control-plane.md`, `plan/standalone/assurance/compatibility-and-versioning.md` | management ABI の固定点 |
| 37 Passthrough, DMA, and Interrupt Remapping | `plan/standalone/architecture/standalone-runtime-architecture.md`, `plan/standalone/implementation/standalone-implementation-plan.md` | 実機閉鎖は未完 |
| 42-45 Process / language / test / supply chain | `plan/standalone/assurance/verification-and-validator-suite.md`, `plan/standalone/assurance/evidence-and-support-artifacts.md`, `plan/standalone/implementation/standalone-implementation-plan.md` | CI / fuzz / evidence |
| 49 Failure Semantics | `plan/standalone/operations/operator-control-plane.md`, `plan/standalone/operations/incident-audit-and-recovery.md`, `plan/standalone/assurance/management-diagnostics-abi.md` | fail-closed / recoverability |
| Appendix G.3 / G.11 / G.12 | `plan/standalone/implementation/standalone-implementation-plan.md`, `plan/standalone/assurance/*.md` | production readiness / quality closure |
| Appendix K | `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md`, `plan/standalone/implementation/standalone-implementation-plan.md` | implementation increments and workstreams |
| Appendix L.11 | `plan/standalone/assurance/management-diagnostics-abi.md` | diagnostics call surface |

## Derived Documents Back To Design Roots

| Derived doc | Design roots |
|---|---|
| `plan/standalone/architecture/standalone-runtime-architecture.md` | 2.1, 9-10, 16, 19-20, 37, 49 |
| `plan/standalone/subsystems/service-management.md` | 10, 18-20 |
| `plan/standalone/subsystems/storage-and-state-management.md` | 18-20, 35-37, 49 |
| `plan/standalone/operations/operator-control-plane.md` | 13-15, 19-20, 49 |
| `plan/standalone/operations/incident-audit-and-recovery.md` | 13-15, 42-45, 49-50 |
| `plan/standalone/assurance/management-diagnostics-abi.md` | 19-20, 49, Appendix L.11 |
| `plan/standalone/assurance/compatibility-and-versioning.md` | 2.2, 20, 42-45, Appendix L |
| `plan/standalone/assurance/verification-and-validator-suite.md` | 17, 42-45, Appendix G |
| `plan/standalone/assurance/evidence-and-support-artifacts.md` | 13-15, 42-45 |
| `plan/standalone/implementation/standalone-implementation-plan.md` | 16-20, 37, 42-45, Appendix K |

## Orphan Or Weak-Root Historical Documents

以下は有用な断片を含んでいたが、full-stack design root への結び付きが弱いか、単独文書としては粒度が細かすぎたため archive へ移した。

1. `plan/standalone/archive/operator-console-mainframe-ui.md`
   - presentation profile であり architecture / ABI の source-of-truth にはならない
2. `plan/standalone/archive/degraded-health-scoring-model.md`
   - operator prioritization heuristic であり要求根が弱い
3. `plan/standalone/archive/command-audit-mapping.md`
   - useful tooling output だが単独の仕様書としては狭すぎる
4. `plan/standalone/archive/page-leak-detector.md`
   - validator 定義のみで subsystem spec と分離しすぎていた
5. `plan/standalone/archive/quota-drift-detector.md`
   - capacity policy 本体ではなく assurance hook だった

## Uncovered Design Areas

`fbvbs-design.md` にはあるが、standalone 側の具体化がまだ不足している領域。

1. standalone 向け update / artifact freshness / secure clock policy
   - sections 39-40, Appendix G.8 に対応する standalone 正本が未整備
2. authoritative IOMMU / interrupt-remapping hardware validation
   - section 37, Appendix G.10 の standalone-specific evidence plan が薄い
3. host deprivilege / final launch handoff
   - sections 11-12, 16 の standalone closure 文書が未成熟
4. append-only OOB audit chain の production closure
   - sections 13-15 に対して policy はあるが implementation closure doc が不足
5. performance discipline and scale closure
   - section 48 に対応する standalone-specific performance / capacity design が不足

## Going-Forward Rule

新しい standalone 文書を active set に入れるときは、少なくとも次を明記する。

1. authority level
2. source design roots in `fbvbs-design.md`
3. depends on
4. supersedes / superseded by when applicable
