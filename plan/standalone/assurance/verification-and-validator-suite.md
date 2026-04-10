# Standalone Verification And Validator Suite

- Status: Active
- Authority level: validation / assurance doc
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 17, 42-45, Appendix G
- Depends on: `plan/standalone/subsystems/*`, `plan/standalone/operations/*`
- Supersedes: `plan/standalone/archive/framac-divergence-classification.md`, `plan/standalone/archive/malformed-input-fuzz-coverage.md`, `plan/standalone/archive/production-model-semantic-diff-review.md`, `plan/standalone/archive/page-leak-detector.md`, `plan/standalone/archive/quota-drift-detector.md`, `plan/standalone/archive/stale-mapping-detector.md`, `plan/standalone/archive/state-transition-precondition-validator.md`, `plan/standalone/archive/storage-invariant-checker.md`, `plan/standalone/archive/teardown-postcondition-validator.md`, `plan/standalone/archive/degraded-health-scoring-model.md`
- Intended audience: validation 担当、CI 設計者、proof readiness reviewer

## Purpose

standalone 向け validator、detector、fuzz、semantic-drift check を、実装補助メモではなく assurance suite として整理する。

## Assurance Families

### Semantic Drift And Proof Readiness

1. Frama-C divergence inventory
2. divergence classification: `hardware-dependent-only`, `acceptable-stub`, `forbidden-divergence`
3. `semantic-drift-check`

禁止事項:

1. policy / state transition / audit observability を `__FRAMAC__` 分岐で変えること
2. report の部分走査

### ABI Robustness

1. malformed input fuzz corpus
2. reserved-zero regression
3. negotiation path coverage

### Runtime State And Lifecycle Validators

1. state transition precondition validator
2. teardown postcondition validator
3. stale mapping detector
4. quota drift detector

### Storage And Ownership Validators

1. storage invariant checker
2. page leak detector
3. attach/detach audit consistency checker
4. destructive confirmation verifier

### Operational Health And Incident Validators

1. degraded health scoring
2. fault escalation matrix generation
3. audit gap detection
4. time source integrity validation

## Gate Levels

### Always-On

1. unit / integration tests
2. reserved field / compatibility checks
3. validator regression tests
4. malformed-input fuzz smoke

### Heavy Gates

1. semantic drift review
2. longer fuzz campaign
3. fault injection and soak
4. hardware-backed teardown / IOMMU checks

## Evidence Rule

validator は単に pass/fail を返すだけでなく、どの設計 root を検証しているかを traceable にしなければならない。詳細な design root mapping は `../../fbvbs-design-traceability.md` を参照する。
