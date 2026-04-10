# State Transition Precondition Validator

## 目的

partition の `quiesce / resume / recover` を operator tooling が投げる前に、現在状態と必要 artifact を fail-close に確認できるようにする。

## 実装

`hypervisor/tools/partition/validate_partition_transition_preconditions.py` は `partition list` JSON を読み、次を判定する。

1. source state が command の許可状態に入っているか
2. `recover` の場合に recovery approval artifact が存在し、partition id と expiration が整合しているか
3. current health / fault / quarantine 情報
4. required artifacts

## 判定対象

1. `quiesce`: `RUNNABLE` / `RUNNING`
2. `resume`: `QUIESCED`
3. `recover`: `FAULTED` かつ valid recovery approval

## 出力物

- `partition-transition-<action>-<partition-id>.json`
- `partition-transition-<action>-<partition-id>.md`

## 完了条件

1. operator tooling が mutation 前に source state を機械検証できる
2. `recover` は approval なしで green にならない
3. validator の結果が CI で回帰される
