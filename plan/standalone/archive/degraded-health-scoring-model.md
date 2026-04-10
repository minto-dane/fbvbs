# Degraded Health Scoring Model

## 目的

partition health を診断上の離散ラベルだけでなく score でも扱い、
degraded / at-risk の優先順位付けを可能にする。

## 実装

`hypervisor/tools/partition/score_partition_health.py` は partition list または
severity summary から次を使って score を算出する。

1. `health_state`
2. `severity`
3. `policy_deny_count`
4. `lockout_windows`
5. `fault_code`
6. `quarantine_reason`

出力 band は `HEALTHY` / `DEGRADED` / `AT_RISK`。

## 検証

`hypervisor/tests/python/partition/test_boundary_and_capacity_tools.py` は
warning + deny/lockout を持つ degraded partition が `AT_RISK` になることを固定する。
