# Standalone Service Management

- Status: Active
- Authority level: derived specification
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 10, 18-20
- Depends on: `plan/standalone/architecture/standalone-runtime-architecture.md`
- Supersedes: `plan/standalone/archive/service-plane-policy.md`, `plan/standalone/archive/service-identity-attestation.md`, `plan/standalone/archive/service-lifecycle-audit.md`, `plan/standalone/archive/service-privilege-review-tooling.md`, `plan/standalone/archive/unused-service-capability-detector.md`, `plan/standalone/archive/service-api-surface-minimization.md`
- Intended audience: runtime 実装者、service plane レビュー担当、検証担当

## Scope

本書は、standalone runtime における **service-like management partitions** の権限境界を定義する。full-stack の KCI / KSI / IKS / SKS / UVS requirements をここで再定義しない。standalone で扱うのは、management plane を支える service profile と、その最小権限化ルールである。

## Service Profiles

standalone profile で現行参照系に含める管理 profile は次のとおり。

1. `operator-console`
   - optional OCS / VCD を担う
2. `diagnostics`
   - health / inventory / fault / guidance の集約を担う
3. `audit-collection`
   - OOB collector 連携と retention 補助を担う
4. `storage-control`
   - storage governance を担う

full-stack 系 `SERVICE_KIND_KCI` などの meaning は `plan/full-stack/fbvbs-design.md` を正とし、本書では standalone-ready 条件に含めない。

## Mandatory Rules

1. service partition は capability の集合でのみ存在を正当化してはならない
2. service profile ごとに allowed object access と allowed call surface を固定する
3. break-glass bypass は default deny とする
4. service identity は runtime state ではなく attestation artifact でも固定する
5. service lifecycle event は append-only 監査経路に流す

## Identity And Capability Discipline

service identity attestation には少なくとも以下を含める。

1. `service_profile`
2. `service_kind`
3. `partition_id`
4. required capability baseline
5. access policy hash
6. peer policy hash
7. image digest / signer identity
8. `session_correlation_id` when operator-mediated

Identity drift は次の場合に fail-close とする。

1. profile baseline と capability mask が不一致
2. profile の allowlist に無い `service_kind`
3. access / peer policy hash mismatch

## Lifecycle And Audit

service lifecycle では少なくとも次を監査対象にする。

1. boot / measure / start
2. quiesce / resume
3. fault / recover
4. revoke / destroy
5. credential or policy rotation

lifecycle 監査は sequence と previous-hash を持つ append-only ledger か、同等の一方向連鎖を要求する。

## Review And Detection Hooks

次の review / detector は、本書の派生 assurance hook として扱う。

1. privilege review baseline
2. unused capability detector
3. API surface minimization report
4. lifecycle audit verification

これらの具体的な gate は `../assurance/verification-and-validator-suite.md` を正とする。

## Non-Goals

1. full-stack trusted services の機能仕様
2. service 間の高度な policy orchestration
3. standalone-ready を超える将来 service plane segmentation の確定
