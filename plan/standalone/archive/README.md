# Standalone Archive Guide

- Status: Active
- Authority level: archive index
- Source-of-truth: `plan/standalone/README.md`
- Intended audience: 過去メモの参照が必要な設計者、差分確認者

## Purpose

`archive/` には、旧 `plan/standalone` の flat 構造で管理されていた断片文書を退避した。これらは削除対象ではなく、**履歴保全用の superseded material** として扱う。

## Rules

1. archive 内の文書は現行設計の正本ではない
2. 新規仕様判断は archive 文書に追加しない
3. 現行参照先は必ず active docs へ引き戻す

## Superseded Clusters

1. command / operator 断片
   - 現行参照先: `../operations/operator-control-plane.md`
2. incident / audit / recovery 断片
   - 現行参照先: `../operations/incident-audit-and-recovery.md`
3. service-plane 断片
   - 現行参照先: `../subsystems/service-management.md`
4. storage / lifecycle 断片
   - 現行参照先: `../subsystems/storage-and-state-management.md`
5. compatibility / evidence / validator 断片
   - 現行参照先: `../assurance/*.md`
6. 旧 standalone architecture / implementation plan / OCS requirements
   - 現行参照先: `../architecture/standalone-runtime-architecture.md`
   - 現行参照先: `../implementation/standalone-implementation-plan.md`
   - 現行参照先: `../operations/operator-control-plane.md`
