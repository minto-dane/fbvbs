# Reserved Field Enforcement

## 目的

standalone 管理 ABI の reserved field を、文書規律だけでなく runtime enforcement と CI で固定する。

## 実装

1. `hypervisor/tools/compatibility/check_standalone_reserved_fields.py` が compatibility matrix と `fbvbs_abi.h` を読み、reserved field を持つ request ABI を抽出する
2. request ABI ごとに runtime の enforcement evidence を source pattern で確認する
3. compatibility matrix 上でも `FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO` を必須にする
4. `make -C hypervisor compatibility-check` で report 生成と回帰を回す

## 対象

1. `fbvbs_command_page_v1`
2. `fbvbs_diag_command_version_request`
3. `fbvbs_diag_guest_feature_request`
4. `fbvbs_diag_set_scaling_limits_request`
5. `fbvbs_storage_pool_create_request`
6. `fbvbs_storage_vdisk_create_request`

## 出力物

- `standalone-reserved-field-report.json`
- `standalone-reserved-field-report.md`

## 完了条件

1. reserved field 付き standalone ABI が機械可読に列挙される
2. compatibility flag と runtime enforcement の両方が fail-close に確認される
3. 新規 ABI 追加時の drift を CI で検出できる
