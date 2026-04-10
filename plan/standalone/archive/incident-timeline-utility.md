# Standalone Incident Timeline Utility

## 目的

primary collector や mirror dump から採取した `AUDIT seq=...` 行を、
boot/session ごとに並べ替えた incident timeline へ正規化する初版 utility を定義する。

## 実装済み土台

`hypervisor/tools/incident/reconstruct_incident_timeline.py` を追加し、次を実装した。

1. `AUDIT seq=...` 形式の text log を読み、JSON timeline に正規化する
2. `boot_hi/boot_lo` がある行は boot-scoped session として束ねる
3. `ts=` / `event=` 形式の collector line も受理する
4. boot/session ごとの `sequence` gap を検出する
5. source file / line number を記録して chain-of-custody を補助する
6. sealed timeline は `seal_incident_timeline.py` が record ごとの
   `previous_chain_sha384` / `record_sha384` / `chain_sha384` と top-level `root_chain_sha384` を付与する
7. `verify_incident_timeline.py` は sealed timeline の chain を再計算して改ざんを検証する

## 出力

timeline JSON は少なくとも以下を含む。

1. `input_files`
2. `record_count`
3. `boot_sessions`
4. `records`
5. sealed 後は `record_chain`
6. sealed 後は `root_chain_sha384`
7. `audit_schema_version`

`boot_sessions` では `first_sequence`, `last_sequence`, `gap_count`, `gaps` を返す。

## 現在の境界

1. payload decode や event-specific rendering は今後の拡張
2. `generate_standalone_evidence_pack.py` により diagnostic bundle / severity summary /
   acknowledgment ledger と evidence pack で統合できる
3. `detect_audit_gaps.py` により timeline の gap summary を operator-facing JSON / Markdown として抽出できる
4. `validate_time_source_integrity.py` により monotonicity / future skew を検証できる
