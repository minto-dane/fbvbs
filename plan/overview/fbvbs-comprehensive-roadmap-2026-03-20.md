# FBVBS 包括ロードマップ

- 文書バージョン: 2.0
- 最終更新: 2026-04-08
- 役割: shared retained-C foundation、FBVBS スタック、スタンドアロン・マイクロハイパーバイザーの全体ロードマップ

---

## 1. 本文書の位置づけ

本書は、同一リポジトリ内で並行する 3 つの対象を 1 枚で追跡するためのマスターロードマップである。

1. **共有 retained-C foundation**
2. **FreeBSD を保護する FBVBS スタック**
3. **スタンドアロン FBVBS マイクロハイパーバイザー**

文書の正本:

1. フルスタック仕様: `plan/full-stack/fbvbs-design.md`
2. プロファイル定義: `plan/shared/fbvbs-deployment-profiles.md`
3. standalone アーキテクチャ: `plan/standalone/architecture/standalone-runtime-architecture.md`
4. standalone 実装計画: `plan/standalone/implementation/standalone-implementation-plan.md`
5. standalone operator plane: `plan/standalone/operations/operator-control-plane.md`

---

## 2. 現在地の要約

### 2.1 共有 retained-C foundation

repository-local で最も進んでいるのは `hypervisor/` にある shared retained-C foundation である。

すでに存在する主な実装:

1. partition / memory / command / security / log
2. cpu security と投機実行緩和ロジック
3. VMX/SVM path、HLAT/NPT path
4. boot / APIC / IDT / MP / watchdog / page allocator

### 2.2 standalone 向けにすでに実装済みの substrate

1. `src/core/scaling.c`
2. `src/storage/storage_virtualization.c`
3. `src/io/vcd_virtualization.c`
4. 対応する `command.c` handler 群
5. `tests/c/storage/test_scaling_storage.c`
6. `tests/c/storage/test_vcd_virtualization.c`

### 2.3 現在の release 境界

現在の `make -C hypervisor release-hypervisor` が主張するのは **retained-C foundation release** である。

これは次を意味しない。

1. FBVBS スタック完成
2. standalone 製品完成
3. high-assurance operational closure

---

## 3. プログラム全体の分解

| トラック | 目的 | 現状 |
|---|---|---|
| shared foundation | 両トラックが使う hypervisor 基盤 | 最も進捗している |
| FBVBS stack | FreeBSD を保護する本来の FBVBS | 仕様先行、実装未完 |
| standalone | 独立仮想化基盤として成立させる | substrate 一部実装済み |
| assurance / release | 実機・証跡・運用閉鎖 | 未完 |

---

## 4. shared retained-C foundation ロードマップ

## F0. 実装済み基盤の維持

現在の基盤:

1. 30 source files
2. 10 test suites
3. proof-shards / smoke / QEMU matrix を含む release gate

維持すべき性質:

1. fail-closed
2. shared foundation release の再現性
3. shared basis としての文書整合

## F1. authoritative IOMMU 閉鎖

必要項目:

1. 実機 MMIO / programming evidence
2. interrupt-remapping の実証
3. safe reset / FLR / passthrough teardown
4. hardware validation campaign

## F2. host deprivilege / boot 閉鎖

必要項目:

1. final host handoff
2. `VMLAUNCH` path
3. boot / measurement / readiness state の一貫化

## F3. proof / evidence hardening

必要項目:

1. verification boundary 更新
2. proof-shards 追随
3. release evidence の説明可能性向上

---

## 5. FBVBS スタック ロードマップ

このトラックは、**FreeBSD を保護するための FBVBS スタック**の完成を目標とする。

## S1. trusted services

必要項目:

1. KCI
2. KSI
3. IKS
4. SKS
5. UVS

現状:

1. 仕様はある
2. Ada/SPARK 実装は未着手または未完

## S2. FreeBSD front-end

必要項目:

1. `fbvbs.ko`
2. FreeBSD 介入点
3. caller/callsite discipline

## S3. `bhyve` / `vmm` 統合

必要項目:

1. `vmm.ko` compatible ABI path
2. VM execution integration
3. passthrough / lifecycle integration

## S4. full-stack readiness

必要項目:

1. full-stack threat-to-evidence closure
2. intervention-point sufficiency evidence
3. update freshness and key-management closure

---

## 6. standalone マイクロハイパーバイザー ロードマップ

このトラックは、shared retained-C foundation を**独立した仮想化基盤**として成立させることを目標とする。

## H1. 管理 substrate 固定

すでにある基盤:

1. scaling runtime limits
2. storage pool / vdisk management
3. VCD attach/status

残項目:

1. ABI versioning
2. compatibility discipline
3. health / diagnostics / evidence 統合

## H2. storage / scaling の製品化

必要項目:

1. quota / headroom / operator guidance
2. attach/detach/destroy semantics の固定
3. capacity / QoS policy

## H3. standalone OCS

必要項目:

1. OCS runtime
2. command parser
3. operator session model
4. transport multiplexer

注意:

OCS は standalone 管理面のための機能であり、full-stack trusted services 制御面ではない。

## H4. standalone 運用閉鎖

必要項目:

1. health state
2. evidence pack
3. incident bundle
4. collector loss / degraded mode / runbook

## H5. standalone-ready 判定

必要項目:

1. IOMMU / teardown 実機 evidence
2. management ABI compatibility evidence
3. OCS enabled/disabled evidence
4. release profile と運用 runbook

---

## 7. assurance / release ロードマップ

## Q1. repository-local gates

現在存在する主要ゲート:

1. analyze
2. test
3. cppcheck
4. fuzz-build / fuzz-smoke
5. coverage
6. traceability
7. reproducible / sbom / provenance
8. proof-smoke / proof-shards
9. baremetal ISO / verify / QEMU matrix

## Q2. hardware evidence

まだ不足しているもの:

1. authoritative IOMMU bring-up evidence
2. deprivilege handoff evidence
3. long soak and failure-injection evidence

## Q3. operational evidence

両トラックに共通して不足しているもの:

1. runbook closure
2. residual risk tracking
3. operational assurance case

---

## 8. 直近の優先順位

1. shared foundation と standalone 文書群の境界修正
2. IOMMU 実機 bring-up と teardown correctness
3. host deprivilege / boot 閉鎖
4. standalone ABI versioning
5. storage / scaling 運用ガイド
6. VCD substrate の上に OCS runtime を設計
7. proof / verification boundary の継続更新

---

## 9. legacy フェーズとの対応

旧来の Phase 記法は完全には廃止しないが、今後の読み方は次のとおりとする。

| legacy 分類 | 新しい読み方 |
|---|---|
| 0A, 0B, 0C, 1, 2, 3, 8 | shared retained-C foundation |
| 4, 5, 6, 7 | FBVBS stack |
| scaling / storage / VCD / OCS | standalone |
| 9 | assurance / release |

旧フェーズ番号だけで standalone と stack を混同してはならない。

---

## 10. 完了判定

### shared-foundation ready

1. retained-C release gate が再現可能
2. authoritative hardware blocker を除く範囲で fail-closed が閉じている

### stack-ready

1. trusted services、FreeBSD front-end、`bhyve`/`vmm` が閉じている
2. FreeBSD protection semantics の証拠がある

### standalone-ready

1. management plane、storage、scaling、health、OCS 境界が閉じている
2. standalone 用の運用 evidence がある

### high-assurance ready

1. 実機・運用・署名付き evidence・残余リスク管理まで閉じている
