# Malformed Input Fuzz Coverage

## 目的

standalone 管理 ABI の malformed input を、seed corpus と軽量回帰の両方で固定する。

## 実装

`hypervisor/fuzz/corpus/command_page/` に以下の seed を揃えた。

1. `diag_get_schema_registry_valid.hex`
2. `diag_get_schema_registry_page_reserved0.hex`
3. `diag_get_schema_registry_reserved_flag.hex`
4. `diag_negotiate_command_version_reserved_field.hex`
5. `diag_negotiate_command_version_short_output.hex`
6. `diag_negotiate_guest_features_exact.hex`
7. `diag_negotiate_guest_features_reserved_field.hex`
8. `diag_negotiate_guest_features_tail_nonzero.hex`
9. `diag_negotiate_guest_features_unsupported_profile.hex`
10. `diag_negotiate_guest_features_unsupported_version.hex`

`hypervisor/tests/python/verification/test_command_page_fuzz_corpus.py` は corpus drift を確認し、`make -C hypervisor fuzz-smoke` は各 seed を harness で replay する。

## 期待する coverage

1. valid management negotiation baseline
2. reserved-zero violation
3. reserved flag violation
4. short input length
5. too-small output buffer
6. unsupported ABI version
7. unsupported guest profile

## 完了条件

1. corpus が決定論的に replay できる
2. standalone 管理 ABI の主要 negotiation path に malformed seed が存在する
3. seed 名と coverage が回帰で固定される
