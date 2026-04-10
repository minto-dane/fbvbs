# Standalone Command To Audit Mapping

- 文書バージョン: 1.0
- 最終更新: 2026-04-05
- 適用対象: standalone command plane / operator tooling

---

## 1. 目的

command call から audit event を deterministic に引ける固定点を提供し、
tooling が「どの command がどの event を出し得るか」を機械照会できるようにする。

## 2. 正本

`hypervisor/tools/audit/generate_command_audit_mapping.py`

## 3. 出力

1. `command-audit-mapping.json`
2. `command-audit-mapping.md`

## 4. 含める内容

1. call id
2. emit し得る event code
3. payload struct type
4. trigger 種別
5. source file

## 5. 完了条件

1. policy deny の監査 shape が call ごとに silent drift しない
2. storage / device / OCS の監査 event が operator tooling から追跡できる
