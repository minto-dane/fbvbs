# Break-Glass Command Audit

## 目的

emergency break-glass command path を通常の acknowledgment / recovery 監査と
混同せず、専用 ledger に分離する。

## 実装

`hypervisor/tools/audit/record_break_glass_audit.py` は break-glass origin attestation と
timeline / severity / acknowledgment ledger を束ねて、
`audit_channel=operator-break-glass` の append-only ledger を生成する。

各 event は少なくとも次を持つ。

1. `break_glass_sequence`
2. `ticket_id`
3. `operator_id`
4. `operator_role`
5. `session_correlation_id`
6. `timeline_root_chain_sha384`
7. `origin_attestation_sha384`
8. `audit_event=FBVBS_EVENT_OPERATOR_BREAK_GLASS`
9. `previous_break_glass_sha384`
10. `break_glass_sha384`

`hypervisor/tools/audit/verify_break_glass_audit.py` は chain / session / timeline root を
検証する。

## fail-close rules

1. origin attestation が break-glass 指定でなければ ledger へ追加しない
2. acknowledgment ledger の session と attestation session がずれたら拒否する
3. timeline root が不一致なら拒否する
4. chain hash が不一致なら拒否する
5. audit channel は `operator-break-glass` 以外を許可しない

## evidence pack

`hypervisor/tools/diagnostics/correlate_standalone_incident_artifacts.py` と
`hypervisor/tools/diagnostics/generate_standalone_evidence_pack.py` は
`origin-attestation.json` と `break-glass-ledger.json` を取り込み、
session drift と missing separate-audit を warning に反映する。

## 検証

`hypervisor/tests/python/audit/test_break_glass_audit_tools.py` は次を固定する。

1. break-glass ledger を生成できる
2. `FBVBS_EVENT_OPERATOR_BREAK_GLASS` が記録される
3. verify tool が chain / session / timeline root を検証できる
