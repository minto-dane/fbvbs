# Frama-C Divergence Classification

## 目的

`__FRAMAC__` 分岐を inventory 化し、production path との意味乖離を
`hardware-dependent-only` / `acceptable-stub` / `forbidden-divergence`
へ分類する。

## 実装

`hypervisor/tools/verification/generate_framac_divergence_report.py` は
`hypervisor/tools/verification/check_framac_stubs.py` の scan 結果を集約し、
JSON / Markdown report を生成する。

分類規則は初版では次を使う。

1. `HW_STUB` は `hardware-dependent-only`
2. high-risk かつ `SYNC` 欠落は `forbidden-divergence`
3. `STRUCT_ZERO` かつ size guard 欠落は `forbidden-divergence`
4. それ以外は `acceptable-stub`

## 検証

`hypervisor/tests/python/verification/test_framac_divergence_report_tool.py` は次を固定する。

1. report schema version が固定される
2. total block count が出る
3. divergence class count が JSON で読める
