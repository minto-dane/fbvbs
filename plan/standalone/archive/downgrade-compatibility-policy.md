# Standalone Downgrade Compatibility Policy

- 文書バージョン: 1.0
- 最終更新: 2026-04-05
- 適用対象: standalone 管理 ABI / evidence/state artifact

---

## 1. 目的

standalone の state artifact を older target に戻すとき、silent misbehavior ではなく fail-closed で可否判定する。

## 2. 正本

`hypervisor/tools/compatibility/generate_standalone_state_manifest.py` が state format 固定点を生成し、
`hypervisor/tools/compatibility/check_standalone_downgrade_compatibility.py` が source / target を比較する。

## 3. 判定規則

target は少なくとも次を満たさなければならない。

1. source の management ABI / schema version / bundle format version が target の accepted window に入る
2. source locale が target の supported locale に含まれる
3. target に version window が存在しない場合は fail する

## 4. 非互換

次は非互換とする。

1. source version が target `minimum_accepted..maximum_accepted` 外
2. target 側 version window の欠落
3. target が source operator locale を扱えない

## 5. 実行

```bash
python3 hypervisor/tools/compatibility/check_standalone_downgrade_compatibility.py \
  --source-manifest source-state.json \
  --target-manifest target-state.json
```
