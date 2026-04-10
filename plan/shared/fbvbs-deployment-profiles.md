# FBVBS デプロイメントプロファイル定義

- 文書バージョン: 2.0
- 最終更新: 2026-04-08
- 目的: 共有基盤、フル FBVBS スタック、スタンドアロン・マイクロハイパーバイザーを明確に分離する

---

## 1. 本文書の役割

本書は、同じ retained-C マイクロハイパーバイザー基盤を使う 2 つの異なる製品トラックを区別するための定義文書である。

1. **FBVBS スタック**
   - FreeBSD を保護対象 OS とする本来の FBVBS 構成。
   - KCI/KSI/IKS/SKS/UVS、`fbvbs.ko`、FreeBSD 介入点、`bhyve`/`vmm` 統合を含む。
2. **スタンドアロン FBVBS マイクロハイパーバイザー**
   - 同じハイパーバイザー基盤を、FreeBSD 保護スタックとは独立した仮想化基盤として扱う構成。
   - スケーリング、ストレージ仮想化、診断 ABI、VCD/OCS などの管理面を主対象とする。

重要なのは、**両者は共有基盤を持つが、同じ計画書で同じ完成条件を持つわけではない**という点である。

---

## 2. 共有基盤

両プロファイルは、少なくとも以下の retained-C 基盤を共有する。

1. 最小権限マイクロハイパーバイザー
2. partition / vCPU / memory / VM の基本状態機械
3. EPT/NPT、IOMMU、割り込み仮想化、CPU 制御
4. fail-closed、capability + policy、一次監査ログの設計原則
5. 形式検証・静的解析・テストに耐える C11 + ACSL 基盤

この共有基盤は `hypervisor/` に実装されている。

---

## 3. プロファイル A: FBVBS スタック

### 3.1 定義

FBVBS スタックは、**FreeBSD を保護するための機能群**としての FBVBS である。

ハイパーバイザーはその基盤だが、製品として成立するには次の要素が必要になる。

1. Kernel Code Integrity Service (KCI)
2. Kernel State Integrity Service (KSI)
3. Identity Key Service (IKS)
4. Storage Key Service (SKS)
5. Update Verification Service (UVS)
6. FreeBSD front-end (`fbvbs.ko`)
7. FreeBSD 介入点と `bhyve`/`vmm` 統合

### 3.2 目標

1. FreeBSD カーネル侵害後でも中核不変条件を維持する
2. FreeBSD を deprivileged host として扱う
3. 保護対象 OS と信頼サービスを明確に分離する

### 3.3 現在の位置づけ

2026-04-03 時点で、リポジトリに存在するのは主として **共有基盤** であり、フル FBVBS スタックは未完成である。

未完の主要項目:

1. Ada/SPARK trusted services
2. FreeBSD front-end
3. `bhyve`/`vmm` 統合
4. full-stack としての production readiness evidence

---

## 4. プロファイル B: スタンドアロン FBVBS マイクロハイパーバイザー

### 4.1 定義

スタンドアロン FBVBS マイクロハイパーバイザーは、共有 retained-C 基盤を**独立した仮想化基盤**として成立させるトラックである。

このトラックでは、FreeBSD は「保護対象 OS」ではなく、必要であれば管理環境または一般 guest の一形態にすぎない。

### 4.2 目標

1. FreeBSD 保護スタック抜きでも成立する管理面を整備する
2. スケーリング、ストレージ、診断、監査、運用回復を製品レベルへ引き上げる
3. OCS を含む場合でも、ハイパーバイザー本体が OCS 非依存で成立するようにする

### 4.3 スコープに入るもの

1. scaling runtime limits
2. storage pool / virtual disk
3. diagnostics / health / evidence
4. VCD とその fail-closed 境界
5. OCS を含むスタンドアロン運用面

### 4.4 スコープに入らないもの

1. KCI/KSI/IKS/SKS/UVS の実装完了
2. FreeBSD を保護対象とする stack semantics
3. `fbvbs.ko` と FreeBSD 介入点
4. full-stack conformance claim

### 4.5 現在の位置づけ

2026-04-03 時点では、standalone 向けに次が部分的に実装済みである。

1. scaling ABI と runtime limit 状態
2. storage virtualization ABI と基本状態機械
3. VCD attach/status ABI と owner mismatch fail-closed

ただし、**スタンドアロン製品としての完成**にはまだ至っていない。

主な残課題:

1. standalone control plane の固定
2. OCS ランタイム本体
3. 運用 runbook / health / evidence pack
4. 実機 IOMMU 閉鎖と release evidence

---

## 5. readiness レベル

本リポジトリでは、プロファイルと readiness を混同しない。

1. **shared-foundation ready**
   - retained-C 基盤の build / test / proof / smoke 境界が成立している状態
2. **stack-ready**
   - FBVBS スタックとして必要な trusted services / FreeBSD integration が閉じている状態
3. **standalone-ready**
   - standalone 管理面、運用面、ストレージ/診断/OCS 境界が閉じている状態
4. **high-assurance ready**
   - 上記に加えて、実機検証、運用証跡、署名付き evidence、残余リスク管理が閉じている状態

現在の repository-local release 境界は **shared-foundation ready に近い retained-C foundation release** であり、stack-ready でも standalone-ready でもない。

---

## 6. 文書の正本

| 文書 | 主対象 | 役割 |
|---|---|---|
| `plan/full-stack/fbvbs-design.md` | FBVBS スタック | フルスタックの規範仕様 |
| `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md` | 全体 | 共有基盤 + stack + standalone のマスターロードマップ |
| `plan/standalone/architecture/standalone-runtime-architecture.md` | standalone | スタンドアロン runtime アーキテクチャ |
| `plan/standalone/implementation/standalone-implementation-plan.md` | standalone | スタンドアロン実装計画 |
| `plan/standalone/operations/operator-control-plane.md` | standalone | OCS/VCD を含む operator control plane |
| `plan/full-stack/cpu-sec.md` | FBVBS スタック | CPU セキュリティ調査メモ（非規範） |
| `plan/overview/agent-handoff-summary.md` | 全体 | オンボーディング索引 |
| `plan/shared/c-leaf-boundary.json` | 全体 | 機械可読な境界インデックス |

---

## 7. 設計上の拘束

1. standalone 文書は、フル FBVBS スタック仕様を暗黙に上書きしてはならない。
2. フルスタック仕様は、standalone 管理面の未実装をもって自動的に変更されたと解釈してはならない。
3. 共有 retained-C 基盤に関する変更は、両プロファイルへの影響を同時に評価しなければならない。
4. 同一機能がどちらのトラックに属するか曖昧な場合は、まず「FreeBSD を保護するための機能か」「独立仮想化基盤として必要な機能か」で分類する。
