# Standalone Immutable Incident Timeline

## 目的

reconstructed incident timeline を hash-chain で seal し、後続の operator acknowledgment が
同じ immutable root を参照できるようにする。

## 実装

1. `hypervisor/tools/incident/seal_incident_timeline.py`
2. `hypervisor/tools/incident/acknowledge_incident_timeline.py`

`seal_incident_timeline.py` は `reconstruct_incident_timeline.py` の JSON を入力に取り、
record ごとの `previous_record_sha384` / `record_sha384` と
`timeline_root_sha384` を付与した sealed timeline を出力する。

`acknowledge_incident_timeline.py` は sealed timeline の chain を再検証し、
検証が通った場合だけ operator acknowledgment artifact を生成する。

## 完了条件

1. timeline root が deterministic に再計算できる
2. tampered timeline では acknowledgment を生成できない
3. operator acknowledgment が immutable timeline root を参照する
