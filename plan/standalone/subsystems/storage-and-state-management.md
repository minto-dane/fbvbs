# Standalone Storage And State Management

- Status: Active
- Authority level: derived specification
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 18-20, 35-37, 49
- Depends on: `plan/standalone/architecture/standalone-runtime-architecture.md`
- Supersedes: `plan/standalone/archive/storage-authorization-model.md`, `plan/standalone/archive/vdisk-lifecycle-state-machine.md`, `plan/standalone/archive/attach-detach-audit-consistency.md`, `plan/standalone/archive/destructive-storage-confirmation.md`, `plan/standalone/archive/storage-evidence-trail.md`
- Intended audience: storage/runtime 実装者、operator tooling 実装者、validation 担当

## Scope

本書は、standalone profile における storage pool / virtual disk / related state artifact の設計を定義する。storage は独立 subsystem だが、ownership・capability・audit の原則は general runtime state machine の派生として扱う。

## Actor Model

### Host

host 管理主体は pool 作成・破棄、QoS 変更、global inventory 参照を行える。

### Service Admin

必要な capability を持つ standalone 管理 service は、host と同等の storage-control 権限を持ちうる。ただし profile と identity attestation が前提である。

### Tenant Owner

tenant owner は `owned-only` scope に限定される。attach / detach / status は自身の ownership 範囲に限り許可し、pool-level mutation や foreign object mutation を許可しない。

## Ownership Rules

1. `owner_partition_id` を authoritative とする
2. delegation は attached partition に対する限定委譲のみ
3. owner change は新規 vdisk 発行または明示 migration 手順でのみ許可する
4. pool granularity invariant を破ってはならない

## Lifecycle Rules

vdisk lifecycle は少なくとも次の状態を持つ。

1. `PROVISIONED`
2. `ATTACHED`
3. `DETACH_PENDING`
4. `RELEASE_PENDING`
5. `QUARANTINED`
6. `DESTROYED`

destroy 系操作は bare ID だけで通してはならない。inventory digest と session correlation を持つ confirmation artifact を要求する。

## Audit And Evidence Rules

1. attach には対応する successful audit event が必要
2. detach 後に未閉鎖 attach relation を残してはならない
3. destructive operation は confirmation artifact に束縛する
4. storage evidence trail は inventory digest と audit consistency report digest を保持する

## Invariants

最低限、以下を常時チェック可能でなければならない。

1. `allocated_bytes <= capacity_bytes`
2. `sum(vdisk.size_bytes) == pool.allocated_bytes`
3. attached count と inventory 状態が一致する
4. granularity alignment が崩れない
5. released object に stale attachment が残らない

## Assurance Hooks

本書の派生 validator / detector は次のとおり。

1. storage invariant checker
2. attach/detach audit consistency checker
3. page leak detector
4. teardown postcondition validator
5. storage evidence trail generator

これらの実施方法と CI gate は `../assurance/verification-and-validator-suite.md` を正とする。
