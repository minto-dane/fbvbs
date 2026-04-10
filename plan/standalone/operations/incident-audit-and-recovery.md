# Standalone Incident, Audit, And Recovery

- Status: Active
- Authority level: derived specification
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 13-15, 42-45, 49-50
- Depends on: `plan/standalone/operations/operator-control-plane.md`, `plan/standalone/assurance/evidence-and-support-artifacts.md`
- Supersedes: `plan/standalone/archive/audit-collector-loss-policy.md`, `plan/standalone/archive/break-glass-command-audit.md`, `plan/standalone/archive/command-audit-mapping.md`, `plan/standalone/archive/admin-session-correlation-id.md`, `plan/standalone/archive/fault-escalation-matrix.md`, `plan/standalone/archive/immutable-incident-timeline.md`, `plan/standalone/archive/incident-timeline-utility.md`, `plan/standalone/archive/operator-acknowledgment-workflow.md`
- Intended audience: audit 実装者、incident response 設計者、operator tooling 実装者

## Scope

本書は、standalone profile における incident handling の一本道を定義する。対象は collector loss policy、audit event mapping、timeline reconstruction、operator acknowledgment、recovery approval、break-glass separation である。

## Audit Priority Rules

1. OOB collector が一次監査経路である
2. collector loss を fail-open の理由に使わない
3. mutation 可能性は collector mode に従って制御する
4. command と audit event の対応は deterministic でなければならない

## Collector Modes

### `NORMAL`

collector present、heartbeat healthy、spool usage が高水位未満。

### `DEGRADED_BACKPRESSURE`

spool 高水位、dropped bytes、framing error 継続。新規変更系操作を絞り、drain を優先する。

### `HALT_NEW_MUTATIONS`

collector absent、heartbeat lost、または halt watermark 到達。読み取り診断と evidence export のみを許可する。

## Incident Workflow

1. raw audit lines を timeline へ再構成する
2. reconstructed timeline を hash-chain で seal する
3. severity summary と fault / guidance を結び付ける
4. operator acknowledgment ledger を append-only で更新する
5. recovery approval artifact を issue / verify する
6. evidence pack に相関 summary を含める

## Session And Break-Glass Rules

1. acknowledgment、origin attestation、recovery approval、break-glass ledger、evidence pack は同じ `session_correlation_id` を参照できなければならない
2. break-glass command は通常 audit channel と別 ledger に記録する
3. timeline root mismatch や session drift があれば append を拒否する
4. justification を持たない break-glass は拒否する

## Escalation And Recovery

fault / health / severity から少なくとも以下を導けなければならない。

1. escalation level
2. containment policy
3. operator action
4. recovery requirement

`recover` は source state と approval artifact の両方を要求する。operator judgment だけで state machine を飛ばしてはならない。

## Cross-References

1. diagnostics shape と runbook code は `../assurance/management-diagnostics-abi.md`
2. evidence pack への格納は `../assurance/evidence-and-support-artifacts.md`
3. validator と gap detection は `../assurance/verification-and-validator-suite.md`
