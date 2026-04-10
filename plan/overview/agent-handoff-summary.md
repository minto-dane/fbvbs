# FBVBS エージェント引き継ぎサマリー

- 最終更新: 2026-04-08
- 目的: 新しいセッションが `plan/` と `hypervisor/` の役割分担を短時間で把握するための索引

---

## 1. まず最初に理解すべきこと

このリポジトリには、**同じ retained-C マイクロハイパーバイザー基盤を使う 2 本の設計トラック**が存在する。

1. **FBVBS スタック**
   - FreeBSD を保護対象 OS とする本来の FBVBS。
   - KCI/KSI/IKS/SKS/UVS、`fbvbs.ko`、FreeBSD 介入点、`bhyve`/`vmm` 統合を含む。
2. **スタンドアロン FBVBS マイクロハイパーバイザー**
   - 同じ基盤を独立した仮想化基盤として成立させるトラック。
   - scaling、storage、diagnostics、VCD/OCS、運用面を重視する。

`plan/standalone/README.md` から辿る standalone 文書群は **standalone トラック用** であり、フル FBVBS スタック仕様そのものではない。

---

## 2. `plan/` の見方

1. `plan/full-stack/`
   - FreeBSD 保護を目的とする FBVBS スタックの正本
2. `plan/standalone/`
   - スタンドアロン FBVBS マイクロハイパーバイザーの現行参照系
3. `plan/shared/`
   - 両トラック共通のプロファイル定義と機械可読インデックス
4. `plan/overview/`
   - 全体ロードマップとオンボーディング索引

---

## 3. どの文書を正本として読むか

### FBVBS スタックを扱う場合

1. `plan/full-stack/fbvbs-design.md`
2. `plan/shared/fbvbs-deployment-profiles.md`
3. `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md`
4. `plan/full-stack/cpu-sec.md`

### スタンドアロン・マイクロハイパーバイザーを扱う場合

1. `plan/shared/fbvbs-deployment-profiles.md`
2. `plan/standalone/README.md`
3. `plan/standalone/architecture/standalone-runtime-architecture.md`
4. `plan/standalone/implementation/standalone-implementation-plan.md`
5. `plan/standalone/operations/operator-control-plane.md`
6. `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md`

### retained-C 実装境界と release evidence を扱う場合

1. `hypervisor/README.md`
2. `hypervisor/compliance/retained_c_leaf_boundary.md`
3. `hypervisor/compliance/wp_verification_boundary.md`
4. `hypervisor/compliance/deployment_profile.md`
5. `hypervisor/compliance/security_target_outline.md`

---

## 4. リポジトリの現在地

### 現在の実装境界

repository-local で実際に build / test / proof / smoke の対象になっているのは `hypervisor/` である。

2026-04-08 時点の概数:

1. `hypervisor/src`: 30 ファイル
2. `hypervisor/tests`: 10 テストスイート
3. `hypervisor/compliance`: 15 文書

### すでに存在する主な実装

1. partition / memory / command / security / log の retained-C 基盤
2. CPU security、VMX/SVM path、HLAT/NPT、boot / APIC / IDT / MP
3. scaling runtime limits
4. storage virtualization ABI と状態機械
5. VCD attach/status と owner mismatch fail-closed

### まだ存在しない、または未完の主なもの

1. authoritative IOMMU 実機 bring-up の閉鎖
2. final host deprivilege / `VMLAUNCH` handoff
3. Ada/SPARK trusted services
4. `fbvbs.ko` と FreeBSD 介入点
5. standalone OCS ランタイム本体

---

## 5. 現在の release 境界

現在の repository-local release 境界は、**retained-C foundation release** である。

これは次を意味する。

1. `make -C hypervisor release-hypervisor` で収集される証拠は retained-C 基盤のもの
2. フル FBVBS スタック完成の証拠ではない
3. standalone 製品完成の証拠でもない

過大主張を避けること。

---

## 6. よく使うコマンド

すべてリポジトリルートから実行する。

```bash
make -C hypervisor analyze
make -C hypervisor test
make -C hypervisor proof-shards
make -C hypervisor release-hypervisor
```

`release-hypervisor` は少なくとも次を束ねる。

1. analyze
2. test
3. cppcheck
4. fuzz-build / fuzz-smoke
5. coverage
6. traceability
7. reproducible / sbom / provenance
8. proof-smoke / proof-shards
9. bare-metal ISO と QEMU smoke / matrix

---

## 7. 作業時の判断基準

1. **FreeBSD を守るための機能か**
   - そうなら FBVBS スタック文書を正本にする。
2. **独立した仮想化基盤として必要な機能か**
   - そうなら standalone 文書を正本にする。
3. **両方が使う retained-C 基盤か**
   - 共有基盤として両トラックへの影響を評価する。

---

## 8. 典型的な誤読

1. `plan/standalone/implementation/standalone-implementation-plan.md` を full-stack 実装計画と誤読しない。
2. `plan/standalone/operations/operator-control-plane.md` を KCI/KSI など full-stack service control 仕様と誤読しない。
3. retained-C release boundary を、そのまま stack-ready または standalone-ready と誤読しない。
4. `plan/full-stack/cpu-sec.md` は調査メモであり、単独では規範仕様ではない。
