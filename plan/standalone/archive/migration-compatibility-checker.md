# Standalone Migration Compatibility Checker

- 文書バージョン: 1.0
- 最終更新: 2026-04-05
- 適用対象: standalone migration preflight

---

## 1. 目的

standalone 間の migration preflight を、state manifest と operator-facing policy から fail-closed で判定する。

## 2. 正本

`hypervisor/tools/compatibility/check_standalone_migration_compatibility.py`

この tool は downgrade compatibility の version-window 判定に加えて、運用前提を確認する。

## 3. 追加判定

1. timeline root が存在すること
2. sequence gap が target の許容 budget を超えないこと
3. source panel style が target の supported style に含まれること
4. target が compatibility matrix を要求する場合、source に matrix が存在すること

## 4. 備考

この checker は live migration 本体ではなく preflight policy である。
実機 confidential migration や dirty tracking は別 WS で扱う。
