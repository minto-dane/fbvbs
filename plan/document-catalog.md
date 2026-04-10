# Plan Document Catalog

- Status: Active
- Authority level: catalog / governance index
- Source-of-truth: `plan/full-stack/fbvbs-design.md`, `plan/shared/fbvbs-deployment-profiles.md`
- Intended audience: 文書管理者、実装者、レビュー担当

## Classification Legend

1. `authoritative design`
   - system-wide architecture / requirements の正本
2. `derived specification`
   - authoritative design を特定 profile / subsystem / interface に具体化した文書
3. `implementation plan`
   - workstream / dependency / milestone を定義する文書
4. `validation / assurance`
   - compatibility, validators, evidence, verification discipline
5. `operational policy`
   - operator, incident, support, recovery, production governance
6. `supplementary memo`
   - onboarding, survey, machine-readable summary, archive index
7. `obsolete / superseded`
   - historical snapshot。現行仕様の正本ではない

## Active Documents

| Path | Classification | Authority | Notes |
|---|---|---|---|
| `plan/README.md` | supplementary memo | active index | `/plan` 全体の入口 |
| `plan/document-catalog.md` | supplementary memo | active catalog | 本文書 |
| `plan/fbvbs-design-traceability.md` | supplementary memo | active traceability | design roots と gaps を整理 |
| `plan/full-stack/fbvbs-design.md` | authoritative design | normative | FBVBS 全体の最上位ソース |
| `plan/full-stack/cpu-sec.md` | supplementary memo | non-normative | CPU security 調査メモ |
| `plan/shared/fbvbs-deployment-profiles.md` | derived specification | active | shared / stack / standalone のプロファイル定義 |
| `plan/shared/c-leaf-boundary.json` | supplementary memo | machine-readable index | shared retained-C boundary の要約 |
| `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md` | implementation plan | active roadmap | program-level roadmap |
| `plan/overview/agent-handoff-summary.md` | supplementary memo | onboarding | 読み順と現状把握 |
| `plan/standalone/README.md` | supplementary memo | active index | standalone 現役参照系の入口 |
| `plan/standalone/architecture/standalone-runtime-architecture.md` | derived specification | active | standalone runtime の派生アーキテクチャ |
| `plan/standalone/subsystems/service-management.md` | derived specification | active | service plane の最小権限化 |
| `plan/standalone/subsystems/storage-and-state-management.md` | derived specification | active | storage / lifecycle / ownership |
| `plan/standalone/operations/operator-control-plane.md` | operational policy | active | operator command plane / OCS/VCD |
| `plan/standalone/operations/incident-audit-and-recovery.md` | operational policy | active | audit / incident / recovery workflow |
| `plan/standalone/assurance/management-diagnostics-abi.md` | derived specification | active | management diagnostics ABI |
| `plan/standalone/assurance/compatibility-and-versioning.md` | validation / assurance | active | ABI / artifact compatibility discipline |
| `plan/standalone/assurance/verification-and-validator-suite.md` | validation / assurance | active | validators / fuzz / semantic drift |
| `plan/standalone/assurance/evidence-and-support-artifacts.md` | validation / assurance | active | evidence pack / support dump / retention |
| `plan/standalone/assurance/baselines/operator-tooling-compatibility-baseline.json` | validation / assurance | machine-readable baseline | tooling compatibility 固定点 |
| `plan/standalone/implementation/standalone-implementation-plan.md` | implementation plan | active | standalone workstream / milestone / dependency |
| `plan/standalone/archive/README.md` | supplementary memo | archive index | superseded docs の案内 |

## Superseded Standalone Fragments

### Superseded By `plan/standalone/operations/operator-control-plane.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/operator-console-requirements.md`
2. `plan/standalone/archive/operator-console-mainframe-ui.md`
3. `plan/standalone/archive/operator-console-severity-model.md`
4. `plan/standalone/archive/operator-privilege-separation.md`
5. `plan/standalone/archive/command-origin-attestation.md`
6. `plan/standalone/archive/command-idempotency-rules.md`
7. `plan/standalone/archive/management-command-rate-limiting.md`

### Superseded By `plan/standalone/operations/incident-audit-and-recovery.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/admin-session-correlation-id.md`
2. `plan/standalone/archive/audit-collector-loss-policy.md`
3. `plan/standalone/archive/break-glass-command-audit.md`
4. `plan/standalone/archive/command-audit-mapping.md`
5. `plan/standalone/archive/fault-escalation-matrix.md`
6. `plan/standalone/archive/immutable-incident-timeline.md`
7. `plan/standalone/archive/incident-timeline-utility.md`
8. `plan/standalone/archive/operator-acknowledgment-workflow.md`

### Superseded By `plan/standalone/subsystems/service-management.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/service-plane-policy.md`
2. `plan/standalone/archive/service-identity-attestation.md`
3. `plan/standalone/archive/service-lifecycle-audit.md`
4. `plan/standalone/archive/service-privilege-review-tooling.md`
5. `plan/standalone/archive/unused-service-capability-detector.md`
6. `plan/standalone/archive/service-api-surface-minimization.md`

### Superseded By `plan/standalone/subsystems/storage-and-state-management.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/storage-authorization-model.md`
2. `plan/standalone/archive/vdisk-lifecycle-state-machine.md`
3. `plan/standalone/archive/attach-detach-audit-consistency.md`
4. `plan/standalone/archive/destructive-storage-confirmation.md`
5. `plan/standalone/archive/storage-evidence-trail.md`

### Superseded By `plan/standalone/assurance/compatibility-and-versioning.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/diagnostic-abi-compatibility-baseline.md`
2. `plan/standalone/archive/downgrade-compatibility-policy.md`
3. `plan/standalone/archive/migration-compatibility-checker.md`
4. `plan/standalone/archive/operator-tooling-compatibility-matrix.md`
5. `plan/standalone/archive/deprecated-field-policy.md`
6. `plan/standalone/archive/reserved-field-enforcement.md`

### Superseded By `plan/standalone/assurance/verification-and-validator-suite.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/framac-divergence-classification.md`
2. `plan/standalone/archive/malformed-input-fuzz-coverage.md`
3. `plan/standalone/archive/production-model-semantic-diff-review.md`
4. `plan/standalone/archive/page-leak-detector.md`
5. `plan/standalone/archive/quota-drift-detector.md`
6. `plan/standalone/archive/stale-mapping-detector.md`
7. `plan/standalone/archive/state-transition-precondition-validator.md`
8. `plan/standalone/archive/storage-invariant-checker.md`
9. `plan/standalone/archive/teardown-postcondition-validator.md`
10. `plan/standalone/archive/degraded-health-scoring-model.md`

### Superseded By `plan/standalone/assurance/evidence-and-support-artifacts.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/standalone-evidence-pack-format.md`
2. `plan/standalone/archive/support-dump-scrubbing-policy.md`

### Superseded By `plan/standalone/architecture/standalone-runtime-architecture.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/hypervisor-standalone-production-architecture.md`

### Superseded By `plan/standalone/implementation/standalone-implementation-plan.md`

Classification: `obsolete / superseded`

1. `plan/standalone/archive/goal-quality-implementation-plan.md`
