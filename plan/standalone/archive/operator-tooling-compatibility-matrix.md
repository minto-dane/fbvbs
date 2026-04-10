# Standalone Operator Tooling Compatibility Matrix

- 文書バージョン: 1.0
- 最終更新: 2026-04-05
- 適用対象: standalone トラック

---

## 1. 目的

operator tooling が参照する管理 ABI の互換性固定点を、機械可読 JSON と Markdown の両方で生成する。

この文書は、`hypervisor/tools/compatibility/generate_operator_tooling_compatibility_matrix.py` の正本説明である。

## 2. 入力

生成器は次を source of truth として読む。

1. `hypervisor/include/fbvbs_abi.h`
2. `plan/standalone/management-diagnostics-abi.md`
3. `plan/standalone/diagnostic-abi-compatibility-baseline.md`
4. `plan/standalone/operator-console-requirements.md`

## 3. 出力

生成器は output directory に次を出力する。

1. `operator-tooling-compatibility-matrix.json`
2. `operator-tooling-compatibility-matrix.md`
3. baseline 固定点 `plan/standalone/operator-tooling-compatibility-baseline.json` と比較可能な row set

## 4. 固定点

1. `schema_registry` の ABI / schema version
2. `DIAG_NEGOTIATE_COMMAND_VERSION` の class / capability / feature 前提
3. `DIAG_NEGOTIATE_GUEST_FEATURES` の guest profile / runtime feature bitmap
4. `partition status` / `partition list` の health layout
5. `partition fault info` / `fault record` の structured layout
6. `DIAG_SET_SCALING_LIMITS` の runtime scaling ABI
7. `STORAGE_CREATE_POOL` / `STORAGE_CREATE_VDISK` / status call の host-only 管理 ABI
8. `OCS VCD attach/status` の optional transport 境界
9. deprecated field policy と lifecycle metadata

## 5. 完了条件

1. JSON と Markdown が同じ row set から生成される
2. operator tooling が supported / unsupported call を事前判定できる
3. plan/standalone の compatibility matrix 項目が文書・テストと整合する
4. baseline との差分から非互換変更を CI で検出できる
5. reserved-zero discipline の report と row set が矛盾しない
