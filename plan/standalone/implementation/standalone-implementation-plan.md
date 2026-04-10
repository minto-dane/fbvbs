# Standalone Implementation Plan

- Status: Active
- Authority level: implementation plan
- Source-of-truth: `plan/full-stack/fbvbs-design.md`, `plan/standalone/architecture/standalone-runtime-architecture.md`
- Depends on: `plan/standalone/subsystems/*`, `plan/standalone/operations/*`, `plan/standalone/assurance/*`
- Supersedes: `plan/standalone/archive/goal-quality-implementation-plan.md`
- Intended audience: 実装者、レビュー担当、作業分解を行う自動実装エージェント

## Scope

本書は **実装順序と依存関係** を定義する。要求や設計そのものをここで新規定義してはならない。設計判断は architecture / subsystems / operations / assurance 文書を正とし、本書はそれらを workstream と milestone に正規化する。

## Inputs

1. `../architecture/standalone-runtime-architecture.md`
2. `../subsystems/service-management.md`
3. `../subsystems/storage-and-state-management.md`
4. `../operations/operator-control-plane.md`
5. `../operations/incident-audit-and-recovery.md`
6. `../assurance/management-diagnostics-abi.md`
7. `../assurance/compatibility-and-versioning.md`
8. `../assurance/verification-and-validator-suite.md`
9. `../assurance/evidence-and-support-artifacts.md`

## Exit Target

`standalone-ready` を主張するには、少なくとも以下を満たす。

1. authoritative second-stage translation、IOMMU、teardown が production-grade に閉じている
2. management ABI と operator flow が文書・実装・validator で一致している
3. diagnostics / compatibility / evidence が release gate に統合されている
4. OCS enabled / disabled の両運用形態で挙動が説明可能である
5. hardware validation と residual risk が証跡化されている

## Workstreams

| Workstream | Focus | Primary dependencies | Primary outputs |
|---|---|---|---|
| WS-1 Foundation closure | IOMMU, interrupt remapping, host deprivilege, teardown | authoritative architecture | runtime closure evidence |
| WS-2 Command and management safety | authorization, rate-limit, origin, preconditions | operator control plane, diagnostics ABI | stable management plane |
| WS-3 Storage and lifecycle closure | storage auth, lifecycle, invariants, destructive safeguards | storage subsystem spec | production storage plane |
| WS-4 Incident, audit, and recovery | collector-loss, timeline, acknowledgment, break-glass | incident/audit spec | operational closure |
| WS-5 Compatibility and assurance | versioning, baselines, validators, semantic drift, fuzz | assurance docs | CI-enforced stability |
| WS-6 Evidence and release | evidence pack, support dump scrubbing, signing, retention | evidence spec | release-ready artifacts |

## Workstream Details

### WS-1 Foundation Closure

Required work:

1. IOMMU / interrupt-remapping 実機 bring-up を authoritative 化する
2. host deprivilege / final launch path を閉じる
3. revoke / destroy / detach 後条件を runtime と validator の両方で固定する
4. stale DMA / stale mapping / teardown drift を実測付きで閉じる

Exit:

1. hardware evidence がある
2. teardown と revoke の fail-closed semantics が実測で再現できる
3. management plane 以前の基盤 blocker が消えている

### WS-2 Command And Management Safety

Required work:

1. command origin attestation、session correlation、privilege separation を runtime 契約に合わせる
2. command idempotency / replay / mutation precondition を tool と doc で一致させる
3. OCS/VCD を optional extension として固定し、非 OCS 構成でも管理面が成立するようにする
4. diagnostics ABI を operator tooling と同じ row set で保守する

Exit:

1. mutation command の required artifact が明確
2. break-glass と通常経路が監査上分離される
3. command safety drift を CI で検出できる

### WS-3 Storage And Lifecycle Closure

Required work:

1. host / service / tenant の authorization を runtime と文書で一致させる
2. vdisk lifecycle、destroy confirmation、attach/detach audit consistency を production rule に昇格する
3. pool / vdisk / page ownership / allocated-bytes の invariant suite を gate 化する
4. snapshot / clone / zeroization を導入する場合は state machine から先に定義する

Exit:

1. storage mutation の意味差が消える
2. destroy / detach / quarantine の証跡が追える
3. invariant violation が silent corruption にならない

### WS-4 Incident, Audit, And Recovery

Required work:

1. collector-loss mode を runtime policy と operator 表示へ接続する
2. timeline reconstruction -> seal -> acknowledgment -> recovery approval を一本道にする
3. fault escalation matrix と severity summary を runbook に結び付ける
4. append-only audit chain と gap detection を evidence pack へ接続する

Exit:

1. incident を session 単位で追跡できる
2. recovery 前提が artifact で検証される
3. collector 不全時の mutation policy が固定される

### WS-5 Compatibility And Assurance

Required work:

1. schema registry / command negotiation / guest feature negotiation を baseline と同期する
2. deprecated field / reserved field / version window を compatibility gate に統合する
3. Frama-C divergence、semantic drift、fuzz corpus、validator suite を一本化する
4. management ABI / operator tooling / support artifact の row set drift を防ぐ

Exit:

1. non-compatible change が CI で落ちる
2. validator coverage が subsystem と traceability で説明できる
3. semantic drift が禁止領域に入らない

### WS-6 Evidence And Release

Required work:

1. diagnostic bundle、sealed timeline、severity summary、ack ledger、compatibility matrix を evidence pack に束ねる
2. support dump scrubbing と forensic preservation mode を release runbook に載せる
3. retention integrity / remote export retry / signing を production artifact として扱う
4. hardware campaign と residual risk を evidence pack に接続する

Exit:

1. standalone-ready 判断に必要な artifact 一式が機械生成できる
2. forensic / support / operator artifact の境界が明確
3. release claim が retained-C foundation release と混線しない

## Milestones

1. **M1 Foundation Ready**
   - WS-1 が基盤 blocker を除去し、WS-2/3 の前提を満たす
2. **M2 Management Plane Stable**
   - WS-2 と WS-3 の external semantics が固定される
3. **M3 Operational Closure**
   - WS-4 と WS-5 の gate が CI / tooling に入る
4. **M4 Standalone Release Candidate**
   - WS-6 を含む evidence と hardware validation が揃う

## Active Completion Matrix (2026-04-08)

本セクションは active plan に対する **現時点の実装分類** を示す。分類は runtime + tests + compatibility/validator 実行結果に基づく。

### Completed

1. partition / trusted service 基本 lifecycle（create/measure/load/start/quiesce/resume/fault/recover/destroy）
2. memory / page の基本 lifecycle（allocate/map/unmap/register/unregister/release）
3. storage pool / vdisk 基本 lifecycle（create/attach/detach/status/qos/corruption/destroy）
4. command page safety（reserved-zero / replay tracker / dispatch validation）
5. diagnostics / compatibility / tooling gate の CI 統合（`make compatibility-check`）

### Partially Implemented

1. incident / recovery artifact enforcement（session+nonce+digest+expiry+ledger digest は runtime 強制済み、ack/origin/break-glass/evidence の完全 end-to-end 連鎖は未完）
2. tenant / service / host boundary closure（主要 mutation 経路は強化済み、全 call surface での完全同等 enforcement は未完）
3. service-plane extensibility 基盤（version negotiation と schema 管理は稼働、将来サービス追加用 ABI フックは一部のみ）

### Unimplemented

1. live migration / checkpoint / replication / HA orchestration の runtime 実装
2. cluster / fleet control-plane primitives
3. backup/restore integration と guest integration services 本体

### Fail-Closed Only

1. host deprivilege handoff の hosted path（fail-closed で停止し成功 handoff は未提供）
2. 一部 IOMMU/device lifecycle の未実装経路（未対応操作は fail-closed）

### Hard Blockers

1. authoritative IOMMU / DMA remap / interrupt remap の production-grade closure（実機証跡含む）
2. host deprivilege final launch path の authoritative closure
3. append-only OOB audit chain と incident evidence の完全 runtime 連鎖閉塞

### Recent Delta (Current Batch)

1. PARTITION_RECOVER に approval expiry + approval ledger digest を追加し runtime で検証
2. recovery approval digest を session/nonce/boot/expiry/ledger digest に束縛
3. host deprivilege で IOMMU runtime-ready を必須 precondition 化

## Deferred Backlog

以下は重要だが、standalone-ready の直前 blocker と混線させない。

1. confidential guest と secret injection
2. migration 本体と dirty tracking
3. large-fleet scale redesign
4. full service-plane segmentation beyond standalone needs

## Planning Rules

1. 設計変更を implementation plan に書き足して正本化しない
2. 新規 work は必ず design root と assurance hook を持つ
3. 実装メモは issue / task tracker に置き、本書へ時系列ログを蓄積しない
4. 完了条件は code merged ではなく evidence available で判定する
