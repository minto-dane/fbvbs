# Standalone Audit Collector Loss Policy

## 目的

OOB collector 欠落や audit backpressure 発生時の standalone 運用モードを固定する。

## 実装

`hypervisor/tools/audit/evaluate_audit_collector_mode.py` は collector status JSON から
運用モードを判定する。

入力例:

1. `collector_present`
2. `heartbeat_ok`
3. `spool_usage_pct`
4. `framing_error_count`
5. `dropped_bytes`

## モード

### NORMAL

collector が存在し、heartbeat が健全で、spool usage が高水位未満。

### DEGRADED_BACKPRESSURE

1. spool usage が高水位に到達した
2. dropped bytes が観測された
3. framing error が継続している

このモードでは、新規変更系操作を絞り、drain を優先する。

### HALT_NEW_MUTATIONS

1. collector absent
2. collector heartbeat lost
3. spool usage が halt watermark に到達

このモードでは新規 mutation を止め、読み取り診断と証跡 export のみを許可する。

## 原則

1. collector 不在で standalone-ready を主張しない
2. collector loss は fail-open の理由に使わない
3. backpressure は operator に可視でなければならない
4. mode 遷移は監査対象であるべき

## 検証

`hypervisor/tests/python/audit/test_audit_collector_mode_tool.py` は次を固定する。

1. collector 不在で `HALT_NEW_MUTATIONS`
2. spool 高水位で `DEGRADED_BACKPRESSURE`
