# Admin Session Correlation ID

## 目的

operator acknowledgment、recovery approval、origin attestation、break-glass ledger、correlation summary、evidence pack を同一の administrative session で束ね、incident 対応の判断系列を追跡可能にする。

## 実装

1. `acknowledge_incident_timeline.py` は `session_correlation_id` を単発 acknowledgment artifact に記録する
2. `record_operator_acknowledgment.py` は ledger の top-level と各 entry に `session_correlation_id` を持たせ、append 時に不一致を fail-close にする
3. `issue_recovery_approval.py` は ack ledger の `session_correlation_id` を必須化し、approval artifact に継承する
4. `issue_command_origin_attestation.py` は origin attestation に `session_correlation_id` を記録する
5. `record_break_glass_audit.py` は dedicated break-glass ledger の top-level と各 entry に `session_correlation_id` を持たせる
6. `correlate_standalone_incident_artifacts.py` は session correlation の summary を evidence correlation に含める
7. `generate_standalone_evidence_pack.py` は manifest に `session_correlation_id` を載せる

## 完了条件

1. ack / ledger / approval / origin / break-glass / correlation / evidence pack が同じ session ID を参照できる
2. ledger append 時の session mismatch が fail-close になる
3. evidence pack だけ見ても operator session を追える
