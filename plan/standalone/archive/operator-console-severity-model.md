# Standalone Operator Console Severity Model

## 目的

operator console が `health / fault / guidance / inventory` を 1 画面に集約するときの
severity 優先順位と表示ルールを固定する。

## 実装

`hypervisor/tools/operator/generate_operator_console_severity_summary.py` は次の入力から
`operator-console-severity-summary.json`、`operator-console-severity-summary.md`、
`operator-console-ispf.txt` と ISPF 風 panel set を生成する。

1. `inventory.json`
2. `partition-list.json`
3. `fault-record-*.json`
4. `guidance-*.json`

presentation locale は少なくとも `en` と `ja` をサポートし、
JSON の canonical code/name は互換性のため維持する。

## 優先順位

severity は次の順で比較する。

1. `ALERT`
2. `CRITICAL`
3. `ERROR`
4. `WARNING`
5. `NOTICE`
6. `INFO`
7. `DEBUG`

partition ごとの severity source は次の優先順位で決める。

1. `fault-record`
2. `guidance`
3. `health-state` 推定

health-state 推定は現在の管理 ABI guidance と整合させる。

1. `HEALTHY` -> `INFO`
2. `DEGRADED` -> `WARNING`
3. `QUARANTINED` -> `ERROR`
4. `RECOVERY` -> `NOTICE`

## 表示ルール

1. `ALERT` は sticky incident banner と即時 security escalation を要求する
2. `CRITICAL` は sticky incident banner と即時 platform recovery を要求する
3. `ERROR` は persistent action banner と recovery-required を要求する
4. `WARNING` は warning banner と triage を要求する
5. `NOTICE` は notice banner と monitor を要求する
6. `INFO` / `DEBUG` は informational banner と observe を返す

## 出力契約

JSON summary は最低限次を含む。

1. `overall_severity`
2. `severity_counts`
3. `display_rules`
4. `inventory`
5. `partitions`

Markdown summary は operator 向けの one-screen view であり、
上位 partition を severity 順で表示する。

ISPF panel set は standalone OCS の reference presentation であり、
少なくとも次を返す。

1. primary option menu
2. partition list panel
3. partition detail panel

各 panel は `Option ===>` または `Command ===>`、必要に応じて `Scroll ===>`、
PF key footer、line command を含む。

より mainframe に寄せた multi-panel workflow は
`hypervisor/tools/operator/render_operator_console_mainframe.py` と
`plan/standalone/operator-console-mainframe-ui.md` で定義する。

## 検証

`hypervisor/tests/python/operator/test_operator_console_severity_summary.py` は次を固定する。

1. `fault-record` が `guidance` と `health-state` より優先される
2. overall severity が最大 partition severity に一致する
3. `ALERT` で sticky incident banner が返る
4. JSON / Markdown / ISPF panel set が生成される
5. `--locale ja` で日本語 presentation が生成される
