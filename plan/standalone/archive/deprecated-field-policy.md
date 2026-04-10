# Standalone Deprecated Field Policy

- 文書バージョン: 1.0
- 最終更新: 2026-04-05
- 適用対象: standalone 管理 ABI / operator tooling

---

## 1. 目的

standalone の管理 ABI で、reserved field と deprecated field を minor upgrade で壊さない運用規律を固定する。

## 2. 規則

1. 現行 major ABI の間は field layout を append-only とする
2. reserved field は schema-versioned 拡張で昇格するまで `0` を維持する
3. deprecated field は minor upgrade で削除しない
4. deprecated field は別意味に再利用しない
5. deprecated field は current response で `0` または旧意味のまま返してよいが、未宣言の repurpose は不可とする
6. deprecated field の宣言は compatibility matrix JSON の `lifecycle.deprecated_fields` に機械可読で残す

## 3. 検出

次を非互換変更として扱う。

1. baseline に存在した call の削除
2. call id / request type / response type / capability / command class / service kind の変更
3. minimum ABI version の引き上げ
4. schema version の後退
5. compatibility flag の削除
6. `lifecycle.deprecated_fields` に載っていた field の消失

## 4. CI

`hypervisor/tools/compatibility/check_standalone_compatibility_changes.py` は baseline と current matrix を比較し、非互換があれば fail する。

CI と local gate の正本コマンドは次のとおり。

```bash
make -C hypervisor compatibility-check
```
