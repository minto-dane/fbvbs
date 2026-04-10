# Page Leak Detector

## 目的

memory object と page inventory の食い違いから page leak を検出する。

## 実装

`hypervisor/tools/storage/detect_page_leaks.py` は次を検査する。

1. `len(backing_pages) == backing_page_count`
2. backing page に対応する page record が存在する
3. page record の `owner_object_id` が object と一致する
4. `allocated=true` なのに object から参照されない page が存在しない

## 検証

`hypervisor/tests/python/storage/test_storage_and_memory_integrity_tools.py` は
owner mismatch と unreferenced allocated page を leak として検出する。
