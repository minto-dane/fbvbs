# Standalone Operator Acknowledgment Workflow

## 目的

operator が incident を確認し、timeline seal と severity summary に対して
誰が何を承認したかを append-only ledger として残す。

## 実装

`hypervisor/tools/incident/record_operator_acknowledgment.py` は次を受け取る。

1. sealed incident timeline JSON
2. operator console severity summary JSON
3. operator identity
4. action code
5. optional note
6. previous acknowledgment ledger
7. session correlation ID

出力は `acknowledgment ledger JSON` であり、`acknowledgments[]` の末尾へ
新しい entry を追加する。

## ledger 契約

1. 各 entry は `previous_ack_sha384` を保持する
2. 各 entry は canonical JSON over self の `ack_sha384` を持つ
3. ledger は `timeline_root_chain_sha384` を固定し、別 timeline へ跨って append しない
4. operator action は free-form string だが、tool は machine-readable field として保持する
5. ledger と各 entry は同じ `session_correlation_id` を保持し、append 時に drift しない

## 完了条件

1. operator acknowledgment workflow が test で固定される
2. timeline seal と severity summary に紐づく append-only ledger が生成できる
3. recovery 承認や triage 完了を JSON として再利用できる

## recovery approval

`hypervisor/tools/incident/issue_recovery_approval.py` は次を fail-close で要求する。

1. sealed incident timeline
2. operator console severity summary
3. acknowledgment ledger
4. target partition ID
5. operator identity
6. recovery rationale
7. session correlation ID

検査:

1. ledger の `timeline_root_chain_sha384` は timeline root と一致しなければならない
2. ledger には少なくとも 1 件の acknowledgment がなければならない
3. target partition は severity summary に存在しなければならない
4. target partition は `HEALTHY` ではあってはならない
5. approval は ledger の `session_correlation_id` を継承しなければならない

`hypervisor/tools/incident/verify_recovery_approval.py` は hash / expiration / `session_correlation_id` を検証する。
