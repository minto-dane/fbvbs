# Standalone Operator Control Plane

- Status: Active
- Authority level: derived specification
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 13-15, 19-20, 49
- Depends on: `plan/standalone/architecture/standalone-runtime-architecture.md`, `plan/standalone/assurance/management-diagnostics-abi.md`
- Supersedes: `plan/standalone/archive/operator-console-requirements.md`, `plan/standalone/archive/operator-console-mainframe-ui.md`, `plan/standalone/archive/operator-console-severity-model.md`, `plan/standalone/archive/operator-privilege-separation.md`, `plan/standalone/archive/command-origin-attestation.md`, `plan/standalone/archive/command-idempotency-rules.md`, `plan/standalone/archive/management-command-rate-limiting.md`
- Intended audience: operator plane 実装者、ABI 実装者、運用設計者

## Scope

本書は、standalone runtime の operator-facing control plane を定義する。対象は host 管理 command、optional OCS/VCD、operator privilege model、command safety rules である。runtime 本体を OCS 依存にしてはならない。

## Control-Plane Boundaries

1. OCS は optional extension である
2. VCD は transport substrate であり command interpreter そのものではない
3. authoritative mutation boundary は structured command set であり、UI profile はその上位 presentation に過ぎない
4. transport ownership と audit ownership はハイパーバイザーに残す

## Command Classes

### Read-Only

inventory、partition list、fault record、schema registry、compatibility disclosure など。原則として deterministic read とし、state mutation を起こさない。

### Convergent Mutation

`PARTITION_QUIESCE`、`PARTITION_RESUME` など、重複要求時の結果を説明できる mutation。idempotency class を文書と tooling で固定する。

### Guarded Mutation

`PARTITION_RECOVER`、destructive storage operation、maintenance mode など。origin attestation、session correlation、artifact precondition を要求する。

### Break-Glass

通常経路と混同せず、separate audit と justification を必須にする。

## Authorization Model

capability だけでなく、少なくとも以下を判定入力に含める。

1. operator role
2. authorization domain
3. action
4. host callsite / transport context
5. break-glass flag
6. required precondition artifact

代表 role は次のとおり。

1. `observer`
2. `incident-responder`
3. `capacity-admin`
4. `storage-admin`
5. `ocs-operator`

## Command Safety Rules

1. origin attestation 必須 command は artifact なしで実行しない
2. session correlation ID は ack / recovery / break-glass / evidence まで通す
3. reserved-zero / version negotiation / rate limiting を迂回する privileged path を作らない
4. mutation 前提は validator で再確認できるようにする

## Rate Limiting And Replay

management abuse guard は runtime 強制事項である。operator tooling は `lockout_windows` と `policy_deny_count` を可視化し、`RETRY_LATER` を generic busy と abuse-guard lockout で混同してはならない。

## OCS / VCD Rules

1. `SERVICE_KIND_OCS` と `FBVBS_CAP_OCS_ACCESS` の両方を要求する
2. owner mismatch は `active=false` への fail-closed 遷移とする
3. VCD status は authoritative owner に対してのみ開示する
4. OCS は standalone 管理面を越える権限を持たない

## Presentation Profile

presentation は ABI の source of truth ではない。reference UI profile として以下を維持する。

1. primary option menu
2. partition list panel
3. partition detail panel
4. command reference

locale は少なくとも `ja` と `en` を持ってよいが、machine-readable JSON schema を変えてはならない。

## Companion Assurance Hooks

1. `../assurance/management-diagnostics-abi.md`
2. `../assurance/compatibility-and-versioning.md`
3. `../assurance/verification-and-validator-suite.md`

operator plane 固有の historical notes は `../archive/` に退避した。
