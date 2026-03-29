# FBVBS v7 包括的実装ロードマップ

**日付:** 2026-03-24
**基準文書:** plan/fbvbs-design.md (FBVBS v7 仕様書)
**現状:** retained C マイクロハイパーバイザー基盤は広く実装済みだが、production release 完了ではない。Multiboot2 bare-metal ELF/GRUB ISO/QEMU smoke は追加済みで、repository-local では Stage 1 の TCG `intel-iommu`、Stage 2 のローカル KVM `intel-iommu`、Stage 3 の q35 `intel-iommu` / `amd-iommu` emulation matrix が boot artifact materialization、boot catalog ingest、host partition seed を通過し、VMX を expose しない環境では `VMX unavailable` で fail-closed する。`KCI_SET_WX` は retained-C 内蔵 SHA-384 と approved per-page digest table により runtime binding する。さらに、initialized audit path を含む retained-C foundation readiness、measured-boot を伴う high-assurance foundation readiness、host deprivilege readiness をコード上で区別する helper/capability bit を追加した。repository-local release packet には `provenance.json`、`release-readiness.json`、`release-evidence.tar.gz`、QEMU matrix summaries/per-case logs が含まれる。bare-metal retained boot artifact catalog は host kernel artifact を immutable loaded image bytes に、残りの retained seed artifact を明示 Multiboot module に authoritative に束縛する。`PARTITION_LOAD_IMAGE` は retained-C fixed ELF64 `ET_EXEC` loader として実装済みで、manifest/profile、`entry_ip`、writable and non-executable stack 条件を満たす authoritative image object に対して `Loaded` へ遷移する。残る主 blocker は authoritative な IOMMU bring-up と実機検証、host deprivilege handoff、Missing RTE guards と timeout を中心とする proof hardening、外部署名付き provenance、Phase 4-7 の信頼サービス/フロントエンド実装である。過去の WP 件数は履歴値として保持するが、常に再現済みの release 証拠を意味しない。

---

## 現状サマリ

### 実装済み（retained C 基盤）

| コンポーネント | ファイル | 行数(概算) | WP検証 | 状態 |
|--------------|---------|-----------|--------|------|
| hypercall dispatch | command.c | ~2150 | 1636/1642 (6 TO) | TOCTOU全修正済 |
| パーティション管理 | partition.c | ~2830 | 1611/1633 (22 TO) | ライフサイクル完全 + IOMMU domain管理 |
| CPU セキュリティ | cpu_security.c | ~1175 | 652/652 (0 TO) ✅ | 81機能検出・緩和 + DR0-3ゼロ化 |
| VMX 制御 | vmx.c | ~580 | 329/330 (1 TO) | probe/setup/run |
| メモリ管理 | memory.c | ~450 | 107/117 (10 TO) | EPTマッピング + ロールバック + テーブルリクレイム + alignment検証 |
| 監査ログ | log.c | ~280 | 217/218 (1 TO) | ringbuf + CRC32C |
| VM ポリシー | vm_policy.c | ~400 | 1322/1324 (2 TO) | capability mask + DR shadow handler + invalid access→FAULTED |
| セキュリティ | security.c | ~1800 | 1641/1656 (15 TO) | manifest/hash/KCI — TO全てGPA manifest chain |
| カーネル統合 | kernel.c | ~400 | 835/836 (1 TO) | model code |
| メモリユーティリティ | memory_utils.c | ~150 | WP除外 | void*関数群 |
| ブートパーサ | boot_multiboot.c | ~250 | WP対象外 | multiboot2 parse |
| IOMMU VT-d | iommu_vtd.c | ~900 | WP対象外 | DMAR パーサ + レジスタ制御 (Phase 0B-1/0B-2) |
| IOMMU AMD-Vi | iommu_amdvi.c | ~470 | WP対象外 | IVRS パーサ + レジスタ制御 (Phase 0B-3) |
| UEFI エントリ | uefi_entry.c | ~260 | WP対象外 | UEFI アプリケーション (Phase 1-1) |
| 早期初期化 | early_init.c | ~230 | WP対象外 | Post-ExitBootServices 初期化 (Phase 1-1) |
| EFI 型定義 | fbvbs_efi.h | ~280 | N/A | UEFI 型・構造体定義 |
| VMCS セットアップ | vmcs_setup.c | ~500 | WP対象外 | VMCS フィールド定義 + deprivilege 準備 + ページアロケータ接続。end-to-end VMLAUNCH は未完 |
| Intel HLAT | hlat.c | ~1040 | WP対象外 | HLAT テーブル管理 + per-partition 状態 + KLD 接続 + クリーンアップ (Phase 2-1, 0C-3) |
| AMD NPT | amd_npt.c | ~1240 | WP対象外 | NPT write-protect + per-partition 状態 + ページアロケータ + KLD 接続 (Phase 3, 0C-3) |
| VMX 制御拡張 | vmx_controls.c | ~350 | WP対象外 | CET-SS + MSR bitmap + preemption timer + ページアロケータ (Phase 2-3/4/5, 0C-3) |
| ページアロケータ | page_alloc.c | ~200 | WP対象外 | ビットマップ PFN アロケータ + ゼロ化保証 (Phase 0C-1/2) |
| ウォッチドッグ | watchdog.c | ~270 | WP対象外 | VMX preemption + NMI watchdog (Phase 1-9) |
| APIC 仮想化 | apic.c | ~410 | WP対象外 | xAPIC/x2APIC + タイマー + EOI + 割り込み注入 (Phase 1-7) |
| IDT | idt.c | ~200 | WP対象外 | IDT エントリ構築 + IST スタック (Phase 1-1) |
| ASM バックエンド | fbvbs_asm.h | ~370 | N/A | 11カテゴリ asm + Frama-C モデルパス (Phase 1-12) |
| MP 初期化 | mp_init.c | ~750 | WP対象外 | MADT/SRAT パーサ + AP 初期化 + IPI + TLB shootdown + NUMA (Phase 8) |
| 並行性設計 | fbvbs_concurrency.h | ~125 | N/A | BHL + per-CPU ロック戦略 (Phase 1-6) |
| リンカスクリプト | fbvbs.ld | ~170 | N/A | ガードページ + IST スタック + W^X + ASSERT 検証 (Phase 1-11) |
| ファジングハーネス | fuzz/*.c | ~550 | N/A | command page + manifest + multiboot2 + iommu (Phase 9-1) |

**WP検証合計:** 履歴上は 8,330 / 8,387 (57 TO) だが、現行の release 判定ではファイル単位の再現結果と proof gap の有無を別途確認すること。

### 未実装・ブロッカー

1. ~~**物理ページアロケータ**~~ — ✅ Phase 0C 完了。ビットマップアロケータ + 全統合ポイント接続 (VMCS/HLAT/NPT/IOMMU VT-d/AMD-Vi/CET) (2026-03-22)
2. ~~**IDT + 例外ハンドラ**~~ — ✅ Phase 1-1 IDT 実装済み (idt.c)
3. ~~**並行性設計**~~ — ✅ Phase 1-6 完了。BHL + per-CPU 戦略文書化 (fbvbs_concurrency.h) (2026-03-21)
4. **IOMMU 実機有効化** — DMAR/IVRS パース済み、ページアロケータ接続済み、retained-C foundation は runtime-ready IOMMU と initialized audit path まで評価可能だが、authoritative 実機 bring-up の閉鎖は未完
5. **ブートパス** — Multiboot2 bare-metal/QEMU smoke は追加済み、UEFI handoff はなお skeleton が残る
6. **WP proof hardening** — `vmx.c` union モデル warning の解消、RTE guard 追加、header/source contract の継続整合
7. ~~**KCI byte binding**~~ — ✅ full-module SHA-384 verification + approved per-page digest table (2026-03-24)
8. **Broader executable loader profile** — retained-C fixed `ET_EXEC` loader は実装済み。残作業は `ET_DYN`/再配置/boot-time service orchestration のような release 範囲外 profile をどう扱うかの設計閉鎖
9. ~~**VM exit 緩和列の実装完了**~~ — ✅ RSB fill / PBRSB / BHB clear の実装済み。残課題は実機 placement と proof hardening
9. ~~**アセンブリバックエンド**~~ — ✅ Phase 1-12 完了。fbvbs_asm.h 集約 (2026-03-21)
10. ~~**HLAT/翻訳整合性**~~ — ✅ Intel HLAT + AMD NPT + MBEC/GMET、per-partition 状態管理 + KLD 接続 (2026-03-22)
11. ~~**xAPIC/x2APIC 仮想化**~~ — ✅ Phase 1-7 実装済み (apic.c) (2026-03-21)
12. **信頼サービスパーティション** — KCI/KSI/IKS/SKS/UVS 全て stub（Ada/SPARK 必要、Phase 4）
13. **暗号ライブラリ** — retained C には KCI 用の限定 SHA-384 測定経路のみ存在し、一般用途の SHA-256/384, Ed25519, AES ライブラリは未実装（Ada/SPARK 必要、Phase 5）
14. **FreeBSD フロントエンド** — fbvbs.ko 未実装（Rust no_std 必要、Phase 6）
15. **bhyve/vmm 統合** — vmm.ko 互換層未実装（Phase 7）
16. ~~**マルチソケット**~~ — ✅ Phase 8 完了。MADT/SRAT/AP/IPI/TLB shootdown/NUMA (mp_init.c) (2026-03-22)
17. **Phase 9 残作業** — ファジングハーネス 5 本と基本ゲートはあるが、継続 fuzzing・seed corpus・SBOM/provenance artifact・監査認証準備は未完。残: CI/CD パイプライン (9-8)、AMD翻訳実証 (9-2)、監査認証準備 (9-4)、supply-chain artifact の閉鎖

---

## フェーズ定義

フェーズは以下の5カテゴリに分類される:

| カテゴリ | 言語/ツールチェーン | フェーズ |
|---------|-----------------|---------|
| **A. マイクロハイパーバイザー** | C11 + Frama-C ACSL + asm | Phase 0A, 0B, 0C, 1, 2, 3, 8 |
| **B. 信頼サービス + 暗号** | Ada/SPARK 2014 | Phase 4, 5 |
| **C. FreeBSD フロントエンド** | Rust (no_std) | Phase 6 |
| **D. bhyve/vmm 統合** | C/Rust | Phase 7 |
| **E. 品質保証・リリース** | 全体横断 | Phase 9 |

---

## カテゴリ A: マイクロハイパーバイザー (C11 + Frama-C ACSL)

### Phase 0A: マイクロハイパーバイザー品質完結（現在地 → 完了）

**目標:** 現行 retained C コードの形式検証品質を最終化し、Phase 0 の全ブロッカーを解消する。

**対象要件:**
- REQ-0200 (マイクロハイパーバイザー責務限定)
- REQ-0201 (形式的解析証拠)
- REQ-0202–0212 (パーティション/hypercall ABI)
- REQ-0205–0210 (command page ABI)

#### 0A-1. WP タイムアウト削減

現在 ~~62~~ → **57** timeouts (2026-03-22 全9ファイル再検証)。目標: 30 以下は未達だが、構造的限界のTOが大部分。

| ファイル | TO | 証明率 | 主因 |
|---------|-----|--------|------|
| cpu_security.c | **0** ✅ | 652/652 (100%) | 関数分割完了 |
| vm_policy.c | **2** | 1322/1324 (99.85%) | run_vcpu/unclassified_fault |
| vmx.c | **1** | 329/330 (99.70%) | synthetic_ept_access_bits |
| kernel.c | **1** | 835/836 (99.88%) | model code |
| log.c | **1** | 217/218 (99.54%) | callee-requires |
| command.c | **6** | 1636/1642 (99.63%) | dispatch GPA assigns |
| memory.c | **10** | 107/117 (91.45%) | EPT map/unmap terminates + create_root requires |
| security.c | **15** | 1641/1656 (99.09%) | GPA manifest chain 全体 |
| partition.c | **22** | 1611/1633 (98.65%) | release 2D assigns + callee-requires |

**アクション:**
1. ~~cpu_security.c: 関数分割~~ → ✅完了 (33→0 TO: detect_common/amd_features, merge_worst_case_vuln, features_match_*, vuln_profiles_match, ローカルvendorキャッシュ, initialized requires削除)
2. ~~partition.c~~ → ✅完了 (10→5 TO: ヘッダ契約追加で5解消、残5はrelease_shared_registrations 2D assigns構造限界)
3. security.c: 14 TO全てGPA manifest chain → Phase 0A-4 に移動（`#ifdef __FRAMAC__` モデル必要）
4. command.c: 6 TO変化なし（dispatch_hypercall GPA assigns、構造限界、許容）
5. **ヘッダ契約追加**: fbvbs_find_manifest_profile_for_object, fbvbs_vmx_run_vcpu, fbvbs_log_append, fbvbs_primary_host_callsite に ACSL 契約追加 → partition.c 5件解消

#### 0A-2. KCI_SET_WX measurement binding ✅ (2026-03-24)

**対象要件:** REQ-0400–0402

**完了:**
1. ✅ `KCI_VERIFY_MODULE` が host partition 上の module mapping 全体を raw SHA-384 測定し、artifact catalog の `payload_hash` と一致したときだけ承認
2. ✅ successful verify 時に approved per-page SHA-384 digest table を internal state に materialize
3. ✅ `KCI_SET_WX` が `guest_physical_address == verified_module_base + file_offset` を強制し、対象全 page の digest を approved table と再照合
4. ✅ write 付与と unmap で approved module state と page bindings を失効

#### 0A-3. Device qualification 基盤 ✅

**対象要件:** REQ-0352, REQ-0904

**完了:**
1. ✅ `fbvbs_device_catalog_entry` に ACS capability, FLR support, MSI-X control, vendor/device ID, qualification flag 追加
2. ✅ `vm_assign_device` に qualification チェック追加（qualified + has_flr + has_acs 必須）
3. ✅ `hypervisor/compliance/device_qualification_matrix.md` 作成（8項目の qualification criteria）
4. 本体は引き続き fail-closed（IOMMU domain 作成は Phase 0B）

#### 0A-4. コンパイラ硬化フラグ ✅ (2026-03-22)

**対象要件:** REQ-0201 (形式的解析), Section 43 (言語固有ルール)

**完了:**
1. ✅ `-fstack-protector-strong` — スタックバッファオーバーフロー検出 (CWE-121)
2. ✅ `-fcf-protection=full` — Intel CET endbr64 + shadow stack（ハイパーバイザー自身のコード）
3. ✅ `-mno-red-zone` — ベアメタル/割り込みハンドラ必須（red zone 破壊防止）
4. ✅ `-fno-common` — 未初期化グローバルのマージ防止
5. ⬜ `-mcmodel=kernel` — 上位半メモリモデル対応（ベアメタルリンク時のみ、ホストテストビルドでは省略）
6. ✅ 既存フラグ確認: `-fno-strict-overflow`, `-fno-delete-null-pointer-checks`, `-fno-strict-aliasing`

#### 0A-5. ログレート制限・フラッド防護 ✅ (2026-03-22)

**対象要件:** REQ-0100 (一次ログ信頼性), Section 15 (過負荷欠落特性)

**完了:**
1. ✅ イベントクラス別レートリミッタ（16クラス、100件/ウィンドウ閾値、超過時 "N dropped" サマリ記録）— `fbvbs_log_append_rate_limited()`
2. ✅ 高優先イベント免除: SEVERITY_CRITICAL, SEVERITY_ALERT, RATE_LIMIT_SUMMARY 自身は無制限通過
3. ✅ リングバッファ溢れポリシー: 最古レコード上書き（ラップアラウンド、sequence monotonic）
4. ✅ VM exit ハンドラ（CR pin violation, DR access intercept）でレート制限ログ使用 — フラッド防護

---

### Phase 0B: IOMMU 実機有効化

**目標:** ACPI テーブルから DMAR/IVRS を解析し、DMA remapping と interrupt remapping を有効化する。

**対象要件:**
- REQ-0003 (IOMMU 必須)
- REQ-0350 (DMA remapping)
- REQ-0351 (interrupt remapping)
- REQ-0353 (外部 DMA ポート分離)

#### 0B-1. ACPI DMAR パーサ（Intel VT-d） ✅

**新規ファイル:** `hypervisor/src/iommu_vtd.c`

**アクション:**
1. ✅ ACPI RSDP → XSDT → DMAR テーブル検索（モデル: NULL返却 fail-closed、PRODUCTION NOTE付き）
2. ✅ DMAR テーブルヘッダ解析（DMA Remapping Reporting Structure）
3. ✅ DRHD (DMA Remapping Hardware Unit) エントリ解析
   - Base address, flags, segment number
   - Device scope parsing (PCI bus/dev/func)
4. ✅ RMRR (Reserved Memory Region Reporting) エントリ解析
5. ATSR (Root Port ATS Capability Reporting) エントリ解析 — Phase 0B-2で必要に応じて追加
6. ✅ ACSL contract 付き bounded パーサ（バッファ長検証、オーバーフロー防止、MAX_DMAR_TABLE_SIZE=4096）
7. ✅ GCC -fanalyzer + テスト通過、cpu_security.c WP 628/628 (0 TO) 維持
8. ✅ `fbvbs_iommu_detect` が Intel vendor時に `fbvbs_vtd_detect` を呼び出すよう統合
9. WP検証: iommu_vtd.c は void* キャストを使用するため WP Typed+Cast 対象外（boot_multiboot.c と同様）

#### 0B-2. Intel VT-d レジスタ制御 ✅

**アクション:**
1. ✅ Global Command Register (GCMD) / Global Status Register (GSTS) 操作 — MMIO read/write モデル + PRODUCTION NOTE
2. ✅ Root Table Address Register 設定 — `vtd_set_root_table()` (SRTP → RTPS ポーリング)
3. ✅ Context Table エントリ構築 — `vtd_build_context_entry()` (Present + TT + SLPTPTR + DID)
4. ✅ Interrupt Remapping Table Entry (IRTE) 構築 — `vtd_build_irte()` (Present + vector + dest + SID)
5. ✅ Translation Enable / Interrupt Remapping Enable — `vtd_enable_translation()`, `vtd_enable_interrupt_remapping()`
6. Context cache invalidation — `vtd_invalidate_context_global()` (IOTLB invalidation は Phase 0B-4 per-domain)
7. ✅ Fault Status Register 監視 — `vtd_check_fault()` (PPF/PFO 検出)
8. ✅ CAP/ECAP レジスタ読み取り — `vtd_probe_capabilities()` (IR, PASID, SAGAW)
9. ✅ `fbvbs_vtd_init()` エントリポイント — 全 DRHD ユニット初期化シーケンス
10. ✅ 本番ビルドは fail-closed（MMIO マッピング未実装時は全操作失敗）

#### 0B-3. ACPI IVRS パーサ（AMD-Vi） ✅

**新規ファイル:** `hypervisor/src/iommu_amdvi.c`

**アクション:**
1. ✅ ACPI IVRS テーブル検索と解析 — `fbvbs_ivrs_parse()` bounded パーサ（ACSL contract付き）
2. ✅ IVHD (I/O Virtualization Hardware Definition) エントリ解析 — type 10h/11h/40h 対応
3. ✅ IVMD (I/O Virtualization Memory Definition) エントリ解析 — type 20h/21h/22h 対応
4. ✅ Device Table エントリ構築 — `amdvi_build_dte()` (Valid + TV + Mode4 + DomainID)
5. ✅ Interrupt Remapping Table 構築 — `amdvi_build_irte()` (RemapEn + vector + dest)
6. ✅ MMIO レジスタ空間マッピング — `amdvi_mmio_read64/write64` モデル + PRODUCTION NOTE
7. ✅ Control Register 操作 — `amdvi_enable()` (IOMMU_EN + EVT_LOG_EN + CMD_BUF_EN)
8. ✅ `fbvbs_amdvi_detect()` / `fbvbs_amdvi_init()` エントリポイント
9. ✅ `fbvbs_iommu_detect` が AMD vendor時に `fbvbs_amdvi_detect` を呼び出すよう統合
10. ✅ GCC -fanalyzer 13ファイル全通過、テスト通過、cpu_security.c WP 628/628 維持
11. WP検証: iommu_amdvi.c は void* キャストを使用するため WP 対象外

#### 0B-4. IOMMU ドメイン管理 ✅

**アクション:**
1. ✅ パーティション ↔ IOMMU ドメインマッピング — `fbvbs_iommu_domain_create()` (partition.c)
2. DMA ページテーブル構築と更新 — PRODUCTION NOTE（物理ページアロケータ必要）
3. ✅ Device → Domain 割り当て/解放 — `vm_assign_device` / `vm_release_device` 完全実装
   - 割り当て: qualification → domain作成 → デバイススロット記録 → domain count更新 → 監査ログ
   - 解放: デバイススロット解除 → domain count更新 → 監査ログ → PRODUCTION NOTE (FLR, context/DTE clear)
4. passthrough デバイスの DMA 分離検証 — PRODUCTION NOTE（MMIO + context/DTE プログラミング必要）
5. ✅ partition destroy 時のドメインクリーンアップ — 既存（fbvbs_partition_destroy_common内）

---

### Phase 0C: 物理ページアロケータ

**目標:** EPT/NPT/HLAT/IOMMU/VMCS/CET が依存する物理ページフレームアロケータの実装。全翻訳テーブル構築の前提条件。

**対象要件:**
- REQ-0203 (メモリゼロ化)
- REQ-0903 (再利用前ゼロ化)
- REQ-0301/0302 (HLAT/NPT テーブル構築)
- REQ-0350 (DMA ページテーブル)

**現状:** HLAT(12箇所), NPT(21箇所), IOMMU VT-d(20+箇所), IOMMU AMD-Vi(10箇所), VMCS(2箇所), CET(1箇所) が物理ページアロケータの不在により fail-closed。

#### 0C-1. ビットマップアロケータ

**アクション:**
1. EFI/Multiboot2 メモリマップから利用可能物理フレームのビットマップ構築
2. Buddy アロケータまたは単純ビットマップアロケータ（連続ページ割当不要の場合）
3. ベアメタル環境: malloc/free なし、静的プールのみ
4. 割り当て失敗 = fail-closed（degraded mode なし）
5. ACSL 契約: 二重割り当て不在、use-after-free 不在の証明
6. ハイパーバイザー自身のメモリ領域をアロケータから除外

#### 0C-2. ページゼロ化保証

**アクション:**
1. 割り当て時の無条件ページゼロ化（REQ-0203）
2. 解放時のゼロ化（REQ-0903 再利用前ゼロ化）
3. `fbvbs_zero_memory` のページ単位版（4KiB aligned、定数時間）
4. ゼロ化完了の ACSL ensures 契約

#### 0C-3. 統合ポイント ✅ (2026-03-22)

**完了:**
1. ✅ EPT ページテーブル構築（memory.c）— `fbvbs_ept_create_root/map_region/unmap_region/cleanup_partition` + ページアロケータ接続 + partition destroy 連携 + GPA overflow/52-bit validation + transactional rollback on partial map failure (セキュリティレビュー修正 2026-03-22)
2. ✅ NPT ページテーブル構築（amd_npt.c）— per-partition 状態 + PML4 アロケーション + VMCB config
3. ✅ HLAT ページテーブル構築（hlat.c）— PML4/PDPT/PD/PT 4ページアロケーション + VMCS 適用
4. ✅ IOMMU root/context テーブル（iommu_vtd.c）— root_table_phys + irta_phys アロケーション
5. ✅ IOMMU cmd_buf/evt_log テーブル（iommu_amdvi.c）— cmd_buf_phys + evt_log_phys アロケーション
6. ✅ VMCS ページ割り当て（vmcs_setup.c）— VMCS ページ + revision stamp + VMCLEAR/VMPTRLD
7. ✅ CET Shadow Stack ページ（vmx_controls.c）— SSP + ISST ページアロケーション

---

### Phase 1: プラットフォームブートパス

**目標:** UEFI → マイクロハイパーバイザー → FreeBSD の完全ブートチェーンを実装する。

**対象要件:**
- REQ-0001 (FreeBSD より前にロード)
- REQ-0002 (VMX root 取得)
- REQ-0006 (起動時検証・測定)
- REQ-0360–0362 (DRTM, Boot Guard/PSB, TPM)

#### 1-1. UEFI アプリケーション ✅

**新規ファイル:** `hypervisor/include/fbvbs_efi.h`, `hypervisor/src/uefi_entry.c`, `hypervisor/src/early_init.c`

**アクション:**
1. ✅ UEFI application エントリポイント (`efi_main`) — MS ABI、EFI_SYSTEM_TABLE 受け取り
2. ✅ EFI_BOOT_SERVICES を使った メモリマップ取得 — `get_memory_map()` + ExitBootServices retry
3. ✅ ACPI RSDP 発見 — EFI Configuration Table から ACPI 2.0 GUID 検索
4. ✅ ハイパーバイザースタック割り当て — `allocate_pages()` (64 KiB)
5. ✅ `fbvbs_efi.h` — 最小 UEFI 型定義（EDK2/gnu-efi 非依存）
6. ✅ ExitBootServices → `fbvbs_efi_to_hypervisor()` 遷移
7. ✅ `early_init.c` — EFI メモリマップ処理、VMX/SVM 検出、serial debug output
8. ページテーブル初期設定（identity mapping）— PRODUCTION NOTE（boot.S と同等ロジック必要）
9. GDT/IDT 初期設定 — PRODUCTION NOTE（アセンブリ必要）
10. VMX/SVM 有効化 — PRODUCTION NOTE（CR4.VMXE/EFER.SVME、アセンブリ必要）
11. **IDT 例外ハンドラ実装**:
    - 最小 IDT エントリ: #DE, #DB, #NMI, #BP, #UD, #GP, #PF, #DF, #MC
    - IST スタック分離: #NMI, #DF, #MC に専用スタック（スタック破損カスケード防止）
    - 例外ハンドラ: UART 一次ログ出力後 halt
    - IST スタック境界の ACSL 契約

#### 1-2. ベアメタル初期化（boot.S） ✅（Multiboot2 パス実装済み）

**既存ファイル:** `hypervisor/src/boot.S` (Multiboot2), `hypervisor/src/early_init.c` (UEFI)

**アクション:**
1. ✅ x86_64 long mode 確認 — boot.S `check_long_mode`
2. ✅ CR0/CR4 初期ビット設定 — boot.S (CR0.PG|WP|PE, CR4.PAE, EFER.LME|NXE)
3. VMX enable (CR4.VMXE → VMXON) — PRODUCTION NOTE（要アセンブリ）
4. 初期 VMCS/VMCB 構築 — Phase 1-3 で実装
5. ✅ ハイパーバイザースタック確保 — boot.S (16KiB BSS) + uefi_entry.c (64KiB allocated)
6. ✅ BSP CPU セキュリティ初期化呼び出し — kernel.c `fbvbs_hypervisor_init`
7. ✅ W^X ページテーブル — boot.S `setup_page_tables_wx` (identity mapped, NX, guard page)
8. ✅ GDT (64-bit flat model) — boot.S `gdt64`

#### 1-3. FreeBSD deprivilege ⬜（VMCS構成ロジックは実装済み、end-to-end VMLAUNCH handoff は未完）

**新規ファイル:** `hypervisor/src/vmcs_setup.c`

**アクション:**
1. FreeBSD カーネルイメージをゲストメモリ領域に配置 — PRODUCTION NOTE（EPT構築後に実装）
2. ✅ VMCS フィールドエンコーディング定義（Intel SDM Appendix B 完全対応）
3. ✅ VM実行制御ビット定義（Pin/Primary/Secondary/Exit/Entry controls）
4. ✅ `fbvbs_vmcs_build_host_config()` — FreeBSD deprivilege 用 VMCS 構成
   - Pin: 外部割り込みExiting + NMI Exiting + Virtual NMIs
   - Primary: HLT/CR3/DR/MSR bitmap Exiting + Secondary activate
   - Secondary: EPT + VPID + RDTSCP + INVPCID + XSAVES
   - Exit: 64-bit host + EFER save/load
   - Entry: 64-bit guest + EFER load
   - Exception bitmap: #DB, #BP, #UD, #MC
   - CR0/CR4 guest-host mask = pinned security bits
5. ✅ `fbvbs_vmcs_apply()` — VMWRITE シーケンス文書化（要アセンブリ）
6. ⬜ `fbvbs_deprivilege_host()` — CPU 状態キャプチャ→VMCS構築と assembly `VMLAUNCH` stub はあるが、guest RIP/RSP・EPT・host TR base・VM exit dispatch を含む end-to-end handoff は未完で fail-closed
7. EPT/NPT ページテーブル構築 — Phase 2 で HLAT 統合と併せて実装
8. VM exit ハンドラチェーン — PRODUCTION NOTE（アセンブリ vmexit_handler 必要）
9. ✅ 一次監査ログ初期化（UART 経路） — early_init.c `serial_print`

#### 1-4. DRTM 統合（高保証構成） ✅ (2026-03-22) — 検出 + シーケンス文書化

**完了:**
1. ✅ Intel TXT: SMX bit CPUID 検出、GETSEC[SENTER] シーケンス PRODUCTION NOTE 文書化
2. ✅ AMD SKINIT: CPUID 0x80000001 ECX[12] 検出、SKINIT シーケンス PRODUCTION NOTE 文書化
3. ⬜ ACM (Authenticated Code Module) ロードと検証 — 要実機テスト
4. ⬜ TPM 2.0 PCR 拡張 — 要 TPM ドライバ
5. ✅ 起動測定チェーン記録 — `fbvbs_boot_integrity.measured_boot_active` フラグ

#### 1-5. Secure Boot 統合 ✅ (2026-03-22) — 検出 + 検証ロジック文書化

**完了:**
1. ⬜ UEFI Secure Boot 変数検証 — PRODUCTION NOTE（ExitBootServices 前に取得必要）
2. ⬜ マイクロハイパーバイザー署名検証 — Phase 5 暗号ライブラリ依存
3. ✅ Boot Guard / PSB 状態確認 — MSR 0x13A 検出 (Intel)、PSB 文書化 (AMD)
4. ✅ 起動チェーン証拠の監査ログ記録 — `FBVBS_EVENT_BOOT_INTEGRITY` (DRTM/TPM/SecureBoot/BootGuard/measured 6バイトペイロード) (2026-03-22)
5. ⬜ S3 レジューム時のブート整合性再検証 — 要 ACPI S3 ハンドラ
6. ⬜ TPM 2.0 NV カウンタ更新（アンチロールバック）— 要 TPM ドライバ
7. ✅ 完全ブートチェーン検証: DRTM + TPM + SecureBoot/BootGuard 三要件チェック
8. ✅ fail-closed: 検証不完全時は measured_boot_active = 0、return -1

#### 1-6. 並行性設計書 ✅ (2026-03-21)

**完了:**
1. ✅ サブシステム別ロック戦略文書 — `fbvbs_concurrency.h` (BHL + per-CPU 戦略)
2. ✅ 方針決定: BHL (Big Hypervisor Lock) + per-CPU state 併用
3. ✅ ロック順序定義 (#MC ハンドラはロック取得禁止)
4. ✅ ACSL `\separated` 設計（並行性未適用状態での WP 基盤維持）
5. ✅ 既存 WP 証明影響評価: 現在 single-core のため影響なし

#### 1-7. xAPIC/x2APIC 仮想化（BSP） ✅ (2026-03-21)

**完了:**
1. ✅ xAPIC / x2APIC モード検出 — `fbvbs_apic_detect_mode` (MSR IA32_APIC_BASE)
2. ✅ APIC access page EPT 設定 — `fbvbs_apic_configure_ept` (APIC MMIO トラップ)
3. ✅ 外部割り込みの仮想化 — `fbvbs_apic_handle_vm_exit_extint`
4. ✅ タイマー割り込み配信 — `fbvbs_apic_timer_tick` (one-shot + TSC deadline)
5. ✅ EOI 仮想化 — `fbvbs_apic_handle_vm_exit_eoi`

#### 1-8. RDRAND/RDSEED エントロピー ✅ (2026-03-22)

**対象要件:** REQ-0006 (起動時測定), IKS/SKS 鍵生成前提

**完了:**
1. ✅ RDRAND/RDSEED 対応検出（CPUID ECX[30], EBX[18]）— `fbvbs_cpu_has_rdrand/rdseed` + fbvbs_asm.h asm
2. ✅ RDRAND retry + health check（10回失敗で -1 返却）— `fbvbs_rdrand64`
3. ✅ フォールバック: RDSEED 非対応時は RDRAND へ自動フォールバック — `fbvbs_rdseed64`
4. ✅ boot_id 生成への接続 — `fbvbs_entropy_seed_boot_ids` (kernel.c)
5. ⬜ IKS/SKS 鍵導出への接続（Phase 5 暗号統合）
6. ✅ エントロピー品質の起動時ログ記録 — `FBVBS_EVENT_ENTROPY_QUALITY` (RDRAND/RDSEED 可用性 4バイトペイロード) (2026-03-22)

#### 1-9. ウォッチドッグ / 活性監視 ✅ (2026-03-21)

**完了:**
1. ✅ VMX preemption timer ウォッチドッグ — `fbvbs_watchdog_on_timer_exit` (連続カウント + 閾値)
2. ✅ NMI ウォッチドッグ — PRODUCTION NOTE (perfctr overflow)
3. ✅ ウォッチドッグ期限切れ時の監査ログ — SEVERITY_ALERT + FBVBS_EVENT_WATCHDOG_EXPIRY
4. ✅ ハング検出後 recovery: `fbvbs_partition_fault` → FAULTED 状態遷移 + ログ

#### 1-10. Destroy 時メモリ完全消去検証 ✅ (2026-03-22)

**対象要件:** REQ-0203 (メモリゼロ化), REQ-0903 (再利用前ゼロ化)

**完了:**
1. ✅ パーティション全ページのゼロ化 — `fbvbs_partition_sanitize_memory` (memory object イテレーション + `fbvbs_zero_page_at_gpa`)
2. ✅ EPT/NPT/HLAT テーブルページの解放とクリーンアップ — `fbvbs_hlat_cleanup_partition`, `fbvbs_npt_cleanup_partition`, `fbvbs_ept_cleanup_partition`
3. ✅ IOMMU DTE/context エントリのクリア — `destroy_common` 内 domain zeroing
4. ✅ vCPU 状態ゼロ化 — struct zeroing + PRODUCTION NOTE (FPU/XMM/YMM/ZMM/MSR/DR0-DR7/LBR)
5. ✅ ページアロケータへの返却前ゼロ化 — `fbvbs_page_free()` がページをゼロ化してから返却

#### 1-11. 状態構造体サイズガード + メモリレイアウト ✅ (2026-03-22)

**完了:**
1. ✅ `_Static_assert(sizeof(fbvbs_hypervisor_state) < 2MB)` + partition < 64KB + log storage exact + memory_object <= 256 + IOMMU domain <= 64 + CPU profile <= 512 + VMX caps == 32 + shared_registration <= 64 + command_page == 4096
2. ✅ メモリレイアウト文書: ガードページ配置ポリシー、IST スタック分離、FBVBS_GUARD_PAGE_SIZE 定義
3. ✅ BSS セクションのガードページ配置 — `fbvbs.ld` リンカスクリプト: .text/.rodata/.data/.bss 間ガードページ + IST スタック分離 + boot スタックガードページ + ASSERT 検証
4. ✅ サブシステム別セグメント分割 — `fbvbs.ld`: IST1(NMI)/IST2(DF)/IST3(MC) 専用スタック + per-stack ガードページ + シンボルエクスポート

#### 1-12. アセンブリバックエンド体系化 ✅ (2026-03-21)

**完了:**
1. ✅ **VMCS 操作**: fbvbs_asm.h — VMWRITE/VMREAD/VMCLEAR/VMPTRLD/VMLAUNCH/VMRESUME inline asm + Frama-C model
2. ✅ **MSR 操作**: fbvbs_asm.h — RDMSR/WRMSR inline asm + Frama-C model
3. ✅ **CPUID**: fbvbs_asm.h — cpuid_query inline asm + Frama-C model
4. ✅ **CR 操作**: fbvbs_asm.h — CR0/CR3/CR4 read/write inline asm
5. ✅ **ページテーブル**: PRODUCTION NOTE (early_init.c)
6. ✅ **RSB fill**: PRODUCTION NOTE (cpu_security.c)
7. ✅ **VERW 配置**: PRODUCTION NOTE (cpu_security.c)
8. ✅ **スピンロック**: log.c xchg asm 本番実装 (output constraint修正済み)
9. ✅ **ABI トランポリン**: PRODUCTION NOTE (uefi_entry.c)
10. ✅ **ACPI テーブル探索**: PRODUCTION NOTE (iommu_vtd.c, iommu_amdvi.c)
11. ✅ **RDRAND/RDSEED**: fbvbs_asm.h — rdrand/rdseed inline asm + Frama-C model

---

### Phase 2: Intel HLAT 翻訳整合性

**目標:** HLAT による カーネルコード領域の翻訳整合性保護。

**対象要件:**
- REQ-0301 (Intel HLAT 必須)
- REQ-0330–0333 (CET 要件)
- REQ-0340–0345 (MSR/レジスタ分離)
- REQ-0370–0372 (仮想化制御)
- REQ-0400–0402 (KCI)

#### 2-1. HLAT テーブル管理 ✅ (2026-03-21)

**新規ファイル:** `hypervisor/src/hlat.c`

**アクション:**
1. ✅ HLAT 対応検出 (CPUID)
2. ✅ HLAT ページテーブル構築（カーネルテキスト領域のみ）
3. ✅ VMCS HLAT pointer 設定
4. ✅ EPT + HLAT 二重翻訳の整合性検証
5. ✅ HLAT テーブル更新（KLD ロード時）

#### 2-2. CR ピン留め強化 ✅ (2026-03-21)

**アクション:**
1. ✅ CR0.WP, CR4.SMEP, CR4.SMAP, CR4.CET, CR4.DE ピン留め (CR4.DE追加: 2026-03-22, DR4/DR5 aliasing防止)
2. ✅ VM exit ハンドラでの CR 書き込みインターセプト — `vm_policy.c`
3. ✅ 不正 CR 変更の拒否とログ記録 — `FBVBS_EVENT_CR_PIN_VIOLATION`
4. ✅ CR4.PCE = 0 ピン留め (REQ-0343)
5. ✅ CR4.UMIP ピン留め (REQ-0345)

#### 2-3. CET Shadow Stack 統合 ✅ (2026-03-21)

**新規ファイル:** `hypervisor/src/vmx_controls.c`

**アクション:**
1. ✅ マイクロハイパーバイザー自身の CET-SS 有効化 — `fbvbs_cet_build_vmcs_config`
2. ✅ CET MSR の per-vCPU 保存・復元 (REQ-0331) — `cpu_security.c`
3. ✅ Shadow Stack ページの EPT 属性設定 (REQ-0332) — PRODUCTION NOTE
4. ✅ CET-IBT 有効化 (REQ-0333) — `S_CET_ENDBR_EN`

#### 2-4. MSR ビットマップとインターセプト ✅ (2026-03-21)

**アクション:**
1. ✅ セキュリティ重要 MSR の無条件インターセプト (REQ-0340) — `fbvbs_msr_bitmap_init`
2. ✅ VPID/ASID 一意割り当て (REQ-0341) — `vmcs_setup.c` `g_next_vpid` allocator
3. ✅ デバッグレジスタ分離 (REQ-0342) — `fbvbs_vmx_dr_access_exit` VM exit ハンドラ + per-vCPU DR0-DR7 shadow state + DR7 64-bit sanitization (bits[63:32]=0, bit11=0, bit10=1, GD=0) + DR6 reserved bits enforcement (FFFF8FF0 | guest bits) + DR4/DR5→DR6/DR7 aliasing + shadow value return on guest read (host DR leak防止) + architectural reset values (DR6=FFFF0FF0, DR7=400) + rate-limited logging
4. ✅ Intel PT / AMD IBS MSR インターセプト (REQ-0344)

#### 2-5. VMX Preemption Timer / Notify Exit ✅ (2026-03-21)

**アクション:**
1. ✅ VMX Preemption Timer 設定 (REQ-0370) — `fbvbs_preemption_build_config`
2. ✅ NOTIFY VM Exit / Bus Lock VM Exit 検出 (REQ-0371)
3. ✅ ゲスト CPU 独占防止ポリシー

---

### Phase 3: AMD 翻訳整合性（複合経路）

**目標:** AMD プラットフォームで HLAT と同等のセキュリティ目標を NPT + 複合機構で達成する。

**対象要件:**
- REQ-0302 (AMD NPT 複合経路必須)
- REQ-0303 (高保証: PFN 差替え等の実証)
- REQ-0304 (SEV-SNP は補強のみ)
- REQ-1100 (本番前実証必須)

#### 3-1. NPT Write-Protect 経路 ✅ (2026-03-21)

**新規ファイル:** `hypervisor/src/amd_npt.c`

**アクション:**
1. ✅ NPT ページテーブル構築 — `fbvbs_npt_config_init`
2. ✅ カーネルテキスト PTE ページの write-protect — `fbvbs_npt_protect_pte_page`
3. ✅ PTE 改ざん検出（NPT violation ハンドラ）— `fbvbs_npt_handle_fault`
4. ✅ Shadow translation テーブル管理 — VMCB config builder

#### 3-2. ページテーブル更新トラップ ✅ (2026-03-21)

**アクション:**
1. ✅ NPT write fault ハンドラ — `fbvbs_npt_handle_fault_exit`
2. ✅ PTE 更新リクエストの検証（KCI 連携）— `fbvbs_npt_validate_pte_write`
3. ✅ 正当な PTE 更新（KLD ロード時）のみ許可 — result==-2 → KCI check
4. ✅ 不正 PFN 差し替えの検出と拒否 — PFN substitution → -1

#### 3-3. TLB 同期と競合防止 ✅ (2026-03-21)

**アクション:**
1. ✅ INVLPG/INVLPGA インターセプト — `SVM_INTERCEPT_INVLPG/INVLPGA`
2. ✅ マルチコア TLB invalidation の原子性保証 — generation counter + IPI (PRODUCTION NOTE)
3. ✅ TLB invalidate race condition テスト — `fbvbs_npt_check_tlb_sync`
4. ⬜ マルチコア PTE 更新競合テスト — Phase 9 実機テスト

#### 3-4. SEV-SNP 補助（オプション）✅ (2026-03-21)

**アクション:**
1. ✅ RMP テーブル操作（補強として）— `fbvbs_sev_snp_validate_code_page`
2. ✅ VMPL レベル設定 — `FBVBS_VMPL_HYPERVISOR/GUEST`
3. ✅ SEV-SNP 有効時の追加分離保証 — complement model (REQ-0304)

### セキュリティレビュー修正 (2026-03-22)

**実施:** 2段階自動セキュリティレビュー（EPT/DR/IOMMU/HLAT/CET 全新規コード対象）

**修正済み脆弱性:**

| 重大度 | コンポーネント | CWE | 修正内容 |
|--------|-------------|-----|---------|
| **Critical** | EPT map/unmap | CWE-190 | `gpa + offset` 整数オーバーフロー防止 + 52-bit 上限検証 |
| **Critical** | DR handler | CWE-284 | CR4.DE ピン留め追加（DR4/DR5 aliasing 防止） |
| **Critical** | IOMMU VT-d | CWE-401 | init 失敗時のページリーク修正（root_table/irta 全解放） |
| **Critical** | IOMMU AMD-Vi | CWE-401 | enable 失敗時のページリーク修正（cmd_buf/evt_log 全解放） |
| **High** | DR handler | CWE-20 | DR6 予約ビット強制（FFFF8FF0 | guest bits） |
| **High** | DR handler | CWE-20 | DR7 64-bit サニタイズ（bits[63:32]=0, bit11=0, bit10=1） |
| **High** | DR handler | CWE-200 | DR read: shadow 値返却（host DR 漏洩防止） |
| **High** | EPT map | CWE-459 | 部分マッピング失敗時のトランザクショナルロールバック |
| **High** | CET | CWE-252 | SSP ページアロケーション失敗時 fail-closed（fail-open → return -1） |
| **High** | HLAT | CWE-190 | `linear_base + size` オーバーフロー検証追加 |
| **High** | HLAT | CWE-401 | `build_vmcs_fields` 失敗時の4ページ解放 |
| **Medium** | DR handler | -- | DR4/DR5→DR6/DR7 aliasing ハンドリング追加 |
| **Low** | vCPU init | CWE-665 | DR6/DR7 アーキテクチャリセット値設定 |
| **Low** | EPT | -- | `_Static_assert` EPT partition state サイズガード追加 |
| **Medium** | NPT | CWE-691 | SEV-SNP スコープ構造修正（PML4 アロケーション移動） |
| **Medium** | NPT/HLAT | CWE-693 | 7件の `assigns \nothing` 契約修正（static 配列変更関数） |
| **Low** | kernel.c | -- | 起動チェーン証拠ログ + エントロピー品質ログ追加 |

### セキュリティレビュー修正 第3回 (2026-03-22)

**実施:** 2独立エージェントによるクロスファイルセキュリティ監査 (全ソース対象)

**修正済み脆弱性:**

| 重大度 | コンポーネント | CWE | 修正内容 |
|--------|-------------|-----|---------|
| **High** | CET (vmx_controls.c) | CWE-401, CWE-665 | `host_isst_addr` 未伝搬修正: ISST ページリーク + VMCS_HOST_ISST_ADDR 未設定 → NMI/MC triple-fault |
| **Medium** | CET (vmx_controls.c) | CWE-636 | CET 利用可能時の SSP alloc 失敗 → fail-closed (return -1) に変更 |
| **Medium** | DR handler (vm_policy.c) | CWE-394 | invalid access_type → FAULTED + audit log (以前は silent OK with zeroed exit_reason) |
| **Medium** | HLAT (hlat.c) | CWE-269 | PML4 index 一貫性検証追加: cross-PML4 リージョン拒否 (single-table aliasing 防止) |
| **Medium** | EPT rollback (memory.c) | CWE-400 | intermediate table ページリクレイム: saved_table_count → rollback 時に free + count 復元 |
| **Medium** | NPT fault (amd_npt.c) | CWE-362 | シリアライゼーション不変量文書化: BHL による NPT fault 処理の直列化保証 |
| **Low** | DR save (cpu_security.c) | CWE-200 | save_guest 後の DR0-DR3 ゼロ化: inter-partition debug register address リーク防止 |
| **Low** | EPT unmap (memory.c) | CWE-20 | unmap_region に page alignment 検証追加 (map_region と一致) |
| **Low** | CR response (vm_policy.c) | CWE-440 | CR exit payload に enforced 値を報告 (requested 値ではなく) |
| **Low** | HLAT populate (hlat.c) | -- | 格納済みリージョンの overflow 再検証 (破損ガード) |
| **Low** | CET validation (vmx_controls.c) | CWE-440 | CET save/restore 検証を CET-capable ハードウェアのみに限定 (#GP 防止) |

### セキュリティレビュー修正 第4回 (2026-03-23)

**実施:** secure-coding-verifier エージェントによるファジングハーネス/テスト/watchdog/boot_multiboot.c 監査

**修正済み脆弱性:**

| 重大度 | コンポーネント | CWE | 修正内容 |
|--------|-------------|-----|---------|
| **Medium** | boot_multiboot.c | CWE-704 | uint32_t* 未アラインポインタ逆参照を fbvbs_copy_memory() 全面置換 (C11 UB 排除) |
| **Medium** | watchdog.c | CWE-20 | on_voluntary_exit: bounds/occupied 検証追加 (防御的プログラミング) |
| **Medium** | fuzz_multiboot2.c | CWE-704 | アラインドバッファコピー + uint32_t size_t 切り捨て防止 |
| **Low** | watchdog.c | CWE-252 | partition_fault 戻り値チェック (SMP TOCTOU ガード) |
| **Low** | fuzz_iommu.c | CWE-681 | fbvbs_dmar_info/fbvbs_ivrs_info 出力構造体 _Static_assert 追加 |
| **Medium** | test_fault_injection.c | -- | LOADED/RUNNABLE/QUIESCED 正例テスト追加 (テストギャップ) |
| **Low** | test_fault_injection.c | -- | 二重障害 return value 明示 assert + watchdog 負例テスト追加 |

### Phase 8: マルチソケット対応 ✅ (2026-03-22) — モデル実装 + PRODUCTION NOTE

**新規ファイル:** `hypervisor/src/mp_init.c` (~750行)

**目標:** UPI リンク接続のマルチソケット環境での正常動作。

**現状:**
- `mp_init.c` に MADT/SRAT パーサ、AP 初期化シーケンス、IPI 送信、TLB shootdown、NUMA 対応を実装
- PRODUCTION NOTE で実機動作に必要なアセンブリ/MMIO 操作を文書化
- モデルパス: BSP-only トポロジで動作、AP 初期化はスキップ（実機では INIT-SIPI-SIPI）
- REQ-0319 (CPU 一貫性検証) 接続: `verify_cpu_consistency()` が `cpu_security.c` の既存インフラを利用
- 24ソースファイル全て GCC -fanalyzer 通過、全テスト通過

#### 8-1. AP (Application Processor) 初期化 ✅

**完了:**
1. ✅ ACPI MADT パーサ — `madt_parse_entries()` (Local APIC + x2APIC + I/O APIC + LAPIC Override、bounded parsing、ACSL loop invariants)
2. ✅ AP の SIPI 送信シーケンス — `start_all_aps()` + INIT-SIPI-SIPI PRODUCTION NOTE (10ms/200µs delays)
3. ✅ per-AP スタック割り当て — `fbvbs_page_alloc()` × 4ページ (16KB/AP)
4. ✅ per-AP の CPU セキュリティ初期化（REQ-0319）— `verify_cpu_consistency()` → `cpu_security.c` の `features_match_*`/`vuln_profiles_match` 連携
5. ✅ BSP 識別 — `identify_bsp()` (CPUID.01H initial APIC ID)
6. ⬜ AP の VMCS/VMCB 構築 — PRODUCTION NOTE（per-AP VMCS ページ割り当て必要）

#### 8-2. IPI (Inter-Processor Interrupt) ハンドリング ✅

**完了:**
1. ✅ IPI 送信 — `send_ipi_broadcast()` / `send_ipi_to_cpu()` (xAPIC ICR MMIO + x2APIC MSR、PRODUCTION NOTE)
2. ✅ TLB shootdown 協調 — `fbvbs_mp_tlb_shootdown()` (broadcast IPI → 全 CPU ack 待機 → ローカル INVEPT)
3. ✅ TLB shootdown ハンドラ — `fbvbs_mp_tlb_shootdown_handler()` (AP 側: INVEPT + ack カウンタ)
4. ⬜ パーティション間コンテキスト切替の IPI 協調 — PRODUCTION NOTE

#### 8-3. NUMA 対応 ✅

**完了:**
1. ✅ ACPI SRAT パーサ — `srat_parse_entries()` (Processor Affinity + Memory Affinity + x2APIC Affinity、proximity domain → CPU/memory 紐付け)
2. ✅ NUMA ドメインごとのメモリ割り当てポリシー — `fbvbs_mp_page_alloc_local()` (ローカルドメイン優先、フォールバック)
3. ✅ CPU → NUMA ドメインマッピング — `fbvbs_cpu_info.numa_domain` / `.socket_id`
4. ⬜ パーティションの NUMA affinity — PRODUCTION NOTE（パーティション作成時にドメイン指定）

#### 8-4. マルチソケット IOMMU 統合 ✅

**完了:**
1. ✅ per-socket IOMMU 検証 — `verify_per_socket_iommu()` (NUMA ドメイン数 vs IOMMU 数の整合性チェック)
2. ⬜ socket をまたぐデバイスの DMA ドメイン管理 — PRODUCTION NOTE
3. ⬜ interrupt remapping のソケット間整合性 — PRODUCTION NOTE

#### 8-5. MP トポロジ監査ログ ✅

**完了:**
1. ✅ `FBVBS_EVENT_MP_TOPOLOGY` — CPU数/オンライン数/NUMAドメイン数/IOAPICカウント/APエラー数 (8バイトペイロード)
2. ✅ `FBVBS_EVENT_MP_CPU_INFO` — per-CPU APIC ID/NUMAドメイン/状態 (4バイトペイロード)

---

## カテゴリ B: 信頼サービス + 暗号 (Ada/SPARK 2014)

### Phase 4: 信頼サービスパーティション

**目標:** Ada/SPARK による信頼サービスパーティションイメージの構築と IPC 通信。

**対象要件:**
- REQ-0200 (責務限定)
- REQ-0400–0402 (KCI)
- REQ-0500–0508 (KSI)
- REQ-0600–0604 (IKS/SKS)
- REQ-0700–0705 (UVS)
- REQ-1002 (SPARK 実行時例外不在証明)

#### 4-1. パーティション基盤

**新規ディレクトリ:** `trusted-services/common/`

**アクション:**
1. Ada 2022 + SPARK 2014 ベアメタルランタイム
2. パーティション間 IPC ライブラリ（共有コマンドページ操作）
3. GNATprove 構成ファイル
4. 最小パーティションイメージ（エコーサービスで起動検証）

#### 4-2. Kernel Code Integrity Service (KCI)

**新規ディレクトリ:** `trusted-services/kci/`

**対象要件:** REQ-0400–0402

**アクション:**
1. W^X 強制ポリシー管理
2. モジュール署名検証（Ed25519）
3. モジュール失効リスト管理
4. コード整合性 + 翻訳整合性連携（HLAT/NPT経由）
5. KLD ロードイベントハンドラ
6. GNATprove 全関数証明

#### 4-3. Kernel State Integrity Service (KSI)

**新規ディレクトリ:** `trusted-services/ksi/`

**対象要件:** REQ-0500–0508

**アクション:**
1. Tier A (不変): sysent, IDT, GDT, .rodata, vop_vector 等の read-only 設定
2. Tier B (制御付き更新): ucred, prison, securelevel, MAC 等
   - Shadow copy 管理
   - Callsite 検証 (RIP ベース, REQ-0506)
   - Write-enable 区間の最小化
3. setuid/setgid 検証 (REQ-0503, REQ-0507)
   - fsid + fileid ベース識別 (REQ-0504)
   - Setuid DB 照合
4. 許可 callsite table 管理 (REQ-0508)
   - KASLR 再配置後の実アドレス導出
   - KLD 更新時の原子的再計算
5. Reference pointer 更新制限: registered legitimate object set のみ許可 (REQ-0502)
6. fd 継承リスクの残留リスク文書化 (REQ-0505)
7. マルチコア Tier B 更新の原子性 (Section 27.1):
   - write-enable/copy/read-only サイクルの最小時間化
   - 複数 CPU コアの当該ページ書込み一時停止メカニズム
   - 大構造体のページ置換方式（新ページ構成→ポインタ原子切替→旧ページ解除）
8. GNATprove 全関数証明

#### 4-4. Identity Key Service (IKS)

**新規ディレクトリ:** `trusted-services/iks/`

**対象要件:** REQ-0600–0602, REQ-0604

**アクション:**
1. IMPORT_KEY, SIGN, KEY_EXCHANGE, DERIVE, DESTROY API
2. 鍵素材の非抽出性保証（サービス境界内保持）
3. KEY_EXCHANGE の不透明ハンドル返却 (REQ-0604)
4. レート制限とアクセスログ

#### 4-5. Storage Key Service (SKS)

**新規ディレクトリ:** `trusted-services/sks/`

**対象要件:** REQ-0603

**アクション:**
1. ディスク暗号鍵管理
2. マウント/アンマウント連携
3. 未マウント時の鍵非抽出性

#### 4-6. Update Verification Service (UVS)

**新規ディレクトリ:** `trusted-services/uvs/`

**対象要件:** REQ-0700–0705

**アクション:**
1. 署名付きマニフェスト検証 (REQ-0701)
2. freshness/freeze 攻撃検出 (REQ-0702, REQ-0704)
3. mix-and-match 防止 (REQ-0705)
4. ロールバック防止（TPM NV / version store）(REQ-0004)
5. A/B パーティショニング
6. snapshot view 一貫性検証

---

### Phase 5: 暗号ライブラリ

**目標:** 信頼サービスで必要な暗号 primitive の安全な実装。

**対象要件:**
- REQ-0602 (外部暗号ライブラリの TCB 帰属)
- REQ-1104 (暗号実装の TCB 範囲確定)

#### 5-1. ハッシュ関数

**アクション:**
1. SHA-256 実装（Ada/SPARK、定数時間）
2. SHA-384 実装（Ada/SPARK、定数時間）
3. CRC32C（既存 C 実装を信頼サービスからも利用可能に）
4. GNATprove によるオーバーフロー不在証明

#### 5-2. 署名

**アクション:**
1. Ed25519 検証（verify のみ、sign は HSM 前提）
2. 定数時間フィールド演算
3. テストベクタ検証

#### 5-3. 対称暗号

**アクション:**
1. AES-256-GCM（SKS 用）
2. HMAC-SHA-256（ログ改ざん検知用、REQ-0104）
3. 定数時間性の実測確認

#### 5-4. 鍵導出

**アクション:**
1. HKDF-SHA-256
2. 鍵素材のゼロ化保証

#### 5-5. HSM 統合と鍵セレモニー (REQ-0703)

**対象要件:** REQ-0703 (HSM ベース鍵管理), Section 40 (署名階層と鍵セレモニー)

**アクション:**
1. Off-line root key 管理手順（HSM 内保持、オフライン署名）
2. Intermediate online key の自動化されたセキュリティ境界
3. Dual-approval 署名手順（高保証プロファイル用）
4. Emergency key revocation 手順（鍵漏洩時の即時失効）
5. 鍵ローテーションスケジュールとトリガー条件
6. Per-component usage constraint（どの鍵がどのコンポーネントに使用可能か）
7. Revocation as first-class mechanism（失効を例外でなく標準操作として設計）

#### 5-6. FIPS 140-3 準拠検討

**対象要件:** Section 41 (高保証プロセス)

**アクション:**
1. 暗号モジュール境界定義（Phase 5 全体が暗号モジュール？サービス単位？）
2. 認証対象アルゴリズムの特定と準拠確認
3. 自己テスト実装（起動時 + 条件付き）
4. 鍵管理要件への準拠確認
5. FIPS 認証取得 vs FIPS 準拠（目標レベルの明確化）

---

## カテゴリ C: FreeBSD フロントエンド (Rust no_std)

### Phase 6: FreeBSD フロントエンド

**目標:** Rust による非信頼 ABI 変換層 fbvbs.ko の実装。

**対象要件:**
- REQ-0800–0804 (FreeBSD 統合)
- REQ-1003 (Rust TCB 部の制約)

#### 6-1. fbvbs.ko 基盤

**新規ディレクトリ:** `fbvbs-frontend/`

**アクション:**
1. Rust `no_std` + `panic=abort` + 固定 toolchain
2. FreeBSD KLD インターフェース
3. VMCALL ラッパー（hypercall 発行）
4. `unsafe` 局所化と安全性契約文書化

#### 6-2. 介入点実装 (REQ-0802, REQ-0804)

**アクション:**
1. KLD ロードフック → KCI 通知
2. execve/fexecve 検証フック → KSI setuid 検証
3. setuid/setgid 系検証フック
4. Jail 操作フック
5. MAC framework フック — mac(9) entry point の各不変条件に対する個別十分性証明 (REQ-0803)
6. Capsicum capability mode/rights 縮減フック
7. 鍵利用経路フック → IKS/SKS 連携
8. vmm(4) boot-time / loader-stage 介入点 (REQ-0804) — 起動時およびローダ段階での FBVBS 介入

#### 6-3. ミラーログ消費

**アクション:**
1. ミラーログリングバッファの読み取り専用マッピング
2. syslog / devd / sysctl 経由の公開
3. ログ形式のユーザーランドパーサ

---

## カテゴリ D: bhyve/vmm 統合 (C/Rust)

### Phase 7: bhyve/vmm 統合

**目標:** 既存 bhyve ユーザーランドの再利用と vmm.ko 互換層。

**対象要件:**
- REQ-0900–0909 (bhyve/仮想化)

**明示的非目標 (REQ-0905):**
- ライブマイグレーション: ABI v1 では対象外。VMCS/EPT 状態転送の複雑性と攻撃面拡大のため除外
- ネスト仮想化: ABI v1 では対象外。L2 ゲストの VMCS shadowing + EPT chaining の攻撃面拡大のため除外

#### 7-1. vmm.ko 互換層

**新規ディレクトリ:** `vmm-compat/`

**アクション:**
1. /dev/vmm デバイスノード
2. libvmmapi 互換 ioctl 群 (REQ-0901)
   - VM_CREATE, VM_DESTROY, VM_RUN
   - VM_SET_REGISTER, VM_GET_REGISTER
   - VM_MAP_MEMORY, VM_INJECT_INTERRUPT
   - VM_ASSIGN_DEVICE, VM_RELEASE_DEVICE
3. VM_GET_VCPU_STATUS (REQ-0908)

#### 7-2. VM exit ルーティング

**アクション:**
1. ファストパス（EPT violation, I/O, CPUID）
2. スローパス（FreeBSD ユーザーランドへの委譲）
3. 未分類 exit の fail-closed 処理 (REQ-0902)
4. exit/entry 緩和シーケンス適用 (REQ-0372)
5. VM exit payload layout 適合 (Appendix L.1.F):
   - PIO/MMIO/external interrupt/EPT violation/CR access の固定 payload 構造準拠
   - exit_length 境界検証
   - 未分類 exit の fail-closed 処理テスト
6. vCPU 状態機械 (Section 35.1, REQ-0906, REQ-0907):
   - 6状態: Created/Runnable/Running/Blocked/Faulted/Destroyed
   - VM exit 種別→状態遷移の固定規則
   - halt → Blocked、割り込み注入 → Runnable 復帰
   - 未分類 exit → Faulted の fail-closed
   - multi-vCPU fault 集約（任意 vCPU fault → VM 全体 Faulted）
   - VM_RUN は Runnable のみ、VM_INJECT_INTERRUPT は Runnable/Blocked のみ
   - VM_SET/GET_REGISTER は Running 時禁止
7. VM_CREATE vs PARTITION_CREATE 制限 (Section 34):
   - PARTITION_CREATE(kind=GUEST_VM) → INVALID_PARAMETER 強制
   - VM_CREATE のみで guest VM 生成可能
   - PARTITION_DESTROY は guest VM に使用不可（VM_DESTROY のみ）
8. タイマー仮想化:
   - ゲスト APIC timer 仮想化（TSC deadline, one-shot, periodic）
   - ゲスト TSC offsetting/scaling
   - HPET/PIT エミュレーション or パススルー戦略

#### 7-3. ゲストメモリ管理

**アクション:**
1. ゲストメモリ所有権モデル
2. 再利用前ゼロ化 (REQ-0903)
3. メモリオブジェクトと shared registration のライフサイクル (REQ-0909)

#### 7-4. Passthrough デバイス管理

**アクション:**
1. IOMMU グループ検証 (REQ-0904)
2. ACS capability 検証
3. MSI/MSI-X 制御
4. Interrupt remapping 設定
5. FLR/reset capability 検証
6. qualification matrix の運用

---

## カテゴリ E: 品質保証・リリース (全体横断)

### Phase 9: 品質保証とリリース準備

**目標:** 本番宣言に必要な品質基準を全て達成する。

**対象要件:**
- REQ-1000–1006 (品質・供給網)
- REQ-1100–1105 (本番準備)

#### 9-1. 検証キャンペーン (一部完了 2026-03-23)

**対象要件:** REQ-1004 (ファジング), REQ-1005 (MC/DC), REQ-1000 (トレーサビリティ), Section 44

**完了:**
- ✅ ファジングハーネスインフラ: `fuzz/fuzz_command_page.c` (hypercall dispatch)、`fuzz/fuzz_manifest.c` (manifest/hash 検証)、`fuzz/fuzz_multiboot2.c` (ブートパーサ)
- ✅ IOMMU パーサファジング: `fuzz/fuzz_iommu.c` (DMAR + IVRS 両パーサ、`#ifdef FUZZ_TARGET` 条件付きリンク)
- ✅ AFL++ persistent mode + libFuzzer + standalone 3モードサポート
- ✅ Makefile `fuzz-build` ターゲット追加。現在は command_page, manifest, multiboot2, iommu, log_decoder, partition_loader の 6 ハーネスを構築
- ✅ ファジングハーネスセキュリティ監査 (2026-03-22): state invariant 初期化修正、capability_mask 本番値使用、完全状態リセット、アラインドバッファコピー、size_t 切り捨て防止、_Static_assert 型サイズガード、AFL LEN 符号修正
- ✅ Multiboot2 パーサ防御強化: `buffer_size` 引数追加 + total_size 外部境界クランプ (boot_multiboot.c)
- ✅ WP 検証境界文書: `compliance/wp_verification_boundary.md` (current in-scope / out-of-scope file boundary と根拠)
- ✅ 故障注入テスト: `tests/test_fault_injection.c` — 17テスト (ログ枯渇/飽和、ロールバック拒否、IOMMU fail-closed、watchdog介入+負例、レートリミッタ+ウィンドウ回転、状態制限 (LOADED/RUNNABLE/QUIESCED正例追加)、二重障害 (return value assert)、IDアロケータ枯渇/サイクル、Multiboot パーサ頑健性)
- ✅ cppcheck 静的解析: `make cppcheck` — 現行 host source set で 0 errors/0 warnings (warning/performance/portability)
- ✅ gcov 分岐カバレッジ: `make coverage` — command.c 24.44% lines / 57.62% branches executed, vm_policy.c 67.34% / 59.32%, vmx.c 95.00% / 100.00%, log.c 88%, watchdog.c 100%
- ✅ host-side MSR safety model: userspace test/coverage/fuzz builds は CPU security 内部で deterministic MSR software model を使用し、privileged `RDMSR/WRMSR` によるクラッシュを避けつつ retained-C 挙動を検証
- ✅ トレーサビリティツール: `tools/traceability_matrix.py` — REQ-XXXX ソース参照スキャン + 孤立分析 (全115要件にソースタグ)
- ✅ MISRA C:2023 逸脱ログ: `compliance/misra_c_deviation_log.md` — 6逸脱 (asm, _Static_assert, void*, volatile, uintptr_t, goto) + 緩和策 + 承認根拠
- ✅ 隠れチャネル分析: `compliance/covert_channel_analysis.md` — CC EAL5+ AVA_VAN.5 準拠、7カテゴリ (タイミング/キャッシュ/分岐予測/メモリバス/MDS/IOMMU/デバッグレジスタ)、残留リスク評価
- ✅ ログデコーダファジング: `fuzz/fuzz_log_decoder.c` (CRC32C、リングバッファ、レートリミッタ、シーケンス枯渇) と `fuzz/fuzz_partition_loader.c` (retained-C ELF64 loader) を追加し、合計 6 ハーネス
- ✅ VMCS ページリーク修正: vmcs_setup.c `fbvbs_vmcs_apply` VMWRITE失敗時の goto cleanup パターン (CWE-401)
- ✅ VPID 直列化文書化: vmcs_setup.c BSP-only 実行保証の明文化 (CWE-362)
- ✅ セキュリティレビュー #6 (2026-03-23): 全変更ファイルの横断監査完了 (14ファイル、3アクション修正)

**アクション:**
1. 全 hypercall パーサの継続的 Fuzzing (REQ-1004)
   - ✅ AFL++ / libFuzzer による command page ファジング — `fuzz/fuzz_command_page.c`
   - ✅ manifest/hash 検証ファジング — `fuzz/fuzz_manifest.c`
   - ✅ Multiboot2 ブートパーサファジング — `fuzz/fuzz_multiboot2.c`
   - ✅ IOMMU DMAR/IVRS パーサファジング — `fuzz/fuzz_iommu.c`
   - IPC parser ファジング
   - update parser ファジング
   - signature loader ファジング
   - log decoder ファジング
   - bhyve front-end 境界ファジング
2. 中核分岐の MC/DC カバレッジ (REQ-1005)
3. 要求→設計→実装→試験→証拠の双方向トレーサビリティ (REQ-1000)
4. **故障注入テスト** (Section 44):
   - ログオーバーフロー（リングバッファ飽和状態での優先イベント保持）
   - 署名破損（改ざんされた Ed25519 署名の検出と拒否）
   - ロールバック攻撃（古い manifest の generation/security_epoch 拒否）
   - 部分メモリ破損（EPT/NPT 保護境界でのビットフリップ検出）
   - DMA 故障（IOMMU ドメイン不整合時の fail-closed 動作）
   - サービスクラッシュ（KCI/KSI/IKS/SKS/UVS 個別停止時の影響範囲限定）
   - vCPU スタック（ゲスト vCPU 無限ループ時の preemption timer 介入）
   - 割り込みストーム（大量 VM exit でのログ保全 + レートリミッタ動作）
5. **IOMMU/HLAT/NPT 検証拡大**:
   - iommu_vtd.c (900行), iommu_amdvi.c (470行), hlat.c, amd_npt.c, vmcs_setup.c は WP 対象外
   - 少なくとも Frama-C Eva 値解析 or CBMC bounded model checking を適用
   - WP 互換サブセット（純粋検証関数、境界チェック）の特定と証明
   - 証明境界文書: どの関数が証明済み、どの関数がランタイムチェック + テスト依存か
6. **MISRA C:2023 準拠証拠** (Section 43):
   - cppcheck --addon=misra or PC-lint による全 WP ソースの解析
   - 正当な逸脱の Deviation log（asm, compiler barriers, atomics）
   - MISRA 準拠マトリクス文書
7. **ID アロケータ耐久テスト**:
   - 長時間連続稼働での create/destroy サイクル（2^32+ 回）
   - Tombstone 蓄積の影響評価
   - monotonic ID exhaustion ポリシー検証

#### 9-2. AMD 翻訳整合性実証 (REQ-1100) — 設計分析完了 (2026-03-23)

**完了:** `compliance/amd_npt_certification.md`
1. ✅ PFN 差替え攻撃テスト — テスト設計 + 実装根拠 (amd_npt.c:554 fault handler)
2. ✅ PTE 改ざん検出テスト — テスト設計 + validate_pte_write 参照
3. ✅ TLB invalidate race テスト — テスト設計 + tlb_generation 同期機構
4. ✅ マルチコア更新競合テスト — テスト設計 + BHL 直列化保証
5. ✅ SEV-SNP complement 検証 — 設計レビュー + REQ-0304 準拠文書
6. ⬜ 実機テスト: Zen 2+ ハードウェアでの敵対的テスト実行

#### 9-3. リリース成果物とサプライチェーン

**対象要件:** REQ-1006, Section 45 (サプライチェーンと再現性)

**アクション:**
1. 再現可能ビルド (REQ-1006) — hermetic ビルド環境、deterministic output
2. SBOM (Software Bill of Materials) — 全依存関係の署名付きリスト
3. 署名付き provenance — ビルド環境・入力・出力の暗号学的証拠
4. Frama-C WP 証明アーティファクト
5. GNATprove 証明アーティファクト
6. 依存関係 allowlist — 許可された外部ライブラリの明示的リスト
7. Version pinning — 全ツールチェーン・依存関係の固定バージョン
8. 脆弱性追跡 — CVE 監視、依存関係の脆弱性スキャン自動化
9. CI isolation — ビルド環境の分離（ネットワーク制限、権限最小化）
10. boot.S 逆アセンブリレビュー文書 (Section 43) — 前提状態・後続状態の明文化

#### 9-4. 監査と認証準備 (一部完了 2026-03-23)

**対象要件:** REQ-1001, REQ-1103–1105, Section 41-42

**完了:**
- ✅ Common Criteria Security Target アウトライン: `compliance/security_target_outline.md` (ISO 15408 準拠、SKPP PP 適合、15 SFR マッピング、EAL5+ 保証要件)
- ✅ インシデント対応手順: `compliance/incident_response.md` (P0-P3 重大度分類、鍵侵害対応、監査証跡保護、復旧シーケンス、エスカレーション基準)
- ✅ fd 継承リスク残留リスク文書: `compliance/fd_inheritance_residual_risk.md` (REQ-0505、KSI保護範囲、FreeBSD Capsicum/closefrom 緩和、受容根拠)
- ✅ passthrough デバイス qualification matrix: `compliance/device_qualification_matrix.md` (REQ-1105、Q1-Q8 8基準)

**アクション (残):**
1. 独立セキュリティ監査 (外部委託)
2. TCB 変更の独立レビュア承認プロセス (REQ-1001) — プロセス策定
3. 暗号実装の TCB 範囲確定 (REQ-1104) — Phase 5 crypto 完了後
4. **プロセス規律フレームワーク** (Section 42) — レビュー証拠保存
5. **言語固有ルール証拠** (Section 43) — SPARK/Rust CI 検証
6. **FreeBSD 介入点十分性の最終実証** (REQ-1101) — Phase 6 完了後
7. **更新メタデータ freshness/freeze/mix-and-match 最終実証** (REQ-1102) — Phase 4-6 完了後

#### 9-5. 隠れチャネル分析 ✅ (2026-03-23) — 設計分析

**対象要件:** Section 41 (Common Criteria EAL5+ 前提)

**完了:** `compliance/covert_channel_analysis.md`
1. ✅ タイミングチャネル: VMX preemption timer (定数リロード), exit処理時間 (残留: RDTSC 観測可能)
2. ✅ キャッシュベースチャネル: L1D (L1D_FLUSH), L1I (残留), L2/LLC (高残留: CAT/QoS未実装), TLB (VPID)
3. ✅ 分岐予測器: BTB (IBPB+eIBRS), RSB (fill), PHT (LFENCE), BHB (BHI_DIS_S), PBRSB (修正済み)
4. ✅ MDS/TAA/RFDS: VERW (条件付き), TSX無効化 (MSR intercept)
5. ✅ メモリバスコンテンション: DRAM row buffer (高残留), QPI/UPI (NUMA-local 軽減)
6. ✅ IOMMU/DMA: ドメイン分離 (低残留), ACS (デバイス qualification 必須)
7. ✅ デバッグレジスタ: DR0-3 ゼロ化, DR6/DR7 サニタイズ, shadow値返却 (残留なし)
8. ✅ 残留リスク推奨: LLC CAT, SMT-aware scheduling, core dedication

#### 9-6. 性能バジェット検証 (Appendix J) ✅ (2026-03-23) — 設計分析

**対象要件:** Section 48 (性能規律)

**完了:** `compliance/performance_budget.md`
1. ✅ 通常 syscall: 追加コストゼロ設計保証 (VMX non-root 内完結, VMCALL 挿入なし)
2. ✅ Tier B 読取り: EPT read-only マッピングで直接メモリ読取り (VM exit なし)
3. ✅ Tier B 変更: ~1-2µs baseline (2 VM exits) + ~5-10µs TLB shootdown
4. ✅ Setuid exec 検証: ~1.5µs (1 VM exit + DB lookup)
5. ✅ KLD ロード: 10ms-100ms (SHA-256 hash + HLAT update + TLB shootdown)
6. ✅ VM exit ファストパス: ~800ns (hardware save + IBPB + handler + VMRESUME)
7. ✅ 禁止事項文書化: syscall VMCALL禁止, Tier B 読取りVMCALL禁止, ログ同期ブロッキング禁止
8. ⬜ 実機計測: ハードウェア計測未実施 (Ice Lake+/Zen 2+ 必要)

#### 9-7. サービス障害影響テスト (Appendix I) ✅ (2026-03-23) — 設計分析

**完了:** `compliance/service_failure_impact.md`

**アクション:**
1. ✅ 各サービス（KCI/KSI/IKS/SKS/UVS）障害時の影響テスト — 設計分析完了
2. 「停止する機能」vs「維持される保護」の実証
3. マイクロハイパーバイザー自体の障害 = 全システム停止の文書化
4. 障害時の第二レベルページング保護維持の検証
5. サービス依存関係マトリクスの実測確認

#### 9-8. CI/CD 継続検証パイプライン ✅ (2026-03-23) — 設計完了

**完了:**
- ✅ GitHub Actions CI ワークフロー: `.github/workflows/ci.yml` — 6ゲート並列実行
- ✅ Gate 1: GCC -fanalyzer + cppcheck (静的解析)
- ✅ Gate 2: 3テストスイート (leaf boundary, policy security, fault injection)
- ✅ Gate 3: 5ファジングハーネスビルド
- ✅ Gate 4: gcov 分岐カバレッジ
- ✅ Gate 5: 再現可能ビルド検証 + SBOM アーティファクト生成
- ✅ Gate 6: 115要件トレーサビリティ検証 (孤立要件 = CI 失敗)
- ✅ Frama-C WP: 週次スケジュール or `[run-wp]` コミットメッセージトリガー
- ✅ Makefile `ci` ターゲット: ローカルで全ゲート順次実行

**残:**
1. ⬜ 署名付きアーティファクト生成の自動化 (HSM 統合要)

---

## 要件トレーサビリティマトリクス

### G.1 Boot/Platform (REQ-0001–0006)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0001 FreeBSD より前にロード | Phase 1 | 未実装 |
| REQ-0002 VMX/SVM root 取得 | Phase 1 | 未実装 |
| REQ-0003 IOMMU 有効化 | Phase 0B | モデルのみ |
| REQ-0004 ロールバック防止 | Phase 4-6 | 未実装 |
| REQ-0005 一次監査ログ経路 | Phase 0A | log.c 実装済み（UART モデル） |
| REQ-0006 起動時検証・測定 | Phase 1 | 未実装 |

### G.2 Logging (REQ-0100–0107)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0100 一次/ミラー分離 | Phase 0A | log.c 実装済み |
| REQ-0101 OOB 経路 | Phase 1 | UART パス実装済み（実機テスト未） |
| REQ-0102 ミラー非根拠 | — | 文書で対応 |
| REQ-0103 レコード形式 | Phase 0A | fbvbs_log_record_v1 実装済み |
| REQ-0104 CRC のみ不可 | Phase 5 | HMAC 未実装 |
| REQ-0105 ミラー read-only | Phase 2 | EPT 設定未実装 |
| REQ-0106 early boot/panic | — | 文書で対応 |
| REQ-0107 リングバッファ形式 | Phase 0A | 実装済み |

### G.3 Partition (REQ-0200–0212)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0200 責務限定 | Phase 0A | アーキテクチャ準拠 |
| REQ-0201 形式的解析 | Phase 0A | Frama-C WP 99.4% |
| REQ-0202 パーティション状態 | Phase 0A | partition.c 実装済み |
| REQ-0203 メモリゼロ化 | Phase 0A | 実装済み |
| REQ-0204 capability 管理 | Phase 0A | 実装済み |
| REQ-0205 hypercall ABI | Phase 0A | command.c 実装済み |
| REQ-0206 未使用領域ゼロ化 | Phase 0A | validate_command_page 実装済み |
| REQ-0207 trap レジスタ規約 | Phase 0A | 実装済み |
| REQ-0208 ABI version check | Phase 0A | 実装済み |
| REQ-0209 caller_sequence | Phase 0A | 実装済み |
| REQ-0210 command page 状態機械 | Phase 0A | CAS 実装済み |
| REQ-0211 lifecycle 遷移限定 | Phase 0A | 実装済み |
| REQ-0212 RESUME/RECOVER 分離 | Phase 0A | 実装済み |

### G.4 CPU Control (REQ-0300–0372)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0300 CR ピン留め | Phase 2 | ✅ vm_policy.c CR exit handler + 強制 |
| REQ-0301 Intel HLAT 必須 | Phase 2 | ✅ hlat.c テーブル管理 + VMCS 設定 |
| REQ-0302 AMD NPT 複合経路 | Phase 3 | ✅ amd_npt.c NPT write-protect + fault handler |
| REQ-0303 AMD 高保証実証 | Phase 3+9 | ✅ モデル実装 (PFN差替え拒否、PTE検証) |
| REQ-0304 SEV-SNP 補強のみ | Phase 3 | ✅ amd_npt.c SEV-SNP complement model |
| REQ-0310 eIBRS/AutoIBRS | Phase 0A | cpu_security.c 実装済み |
| REQ-0311 IBPB on context switch | Phase 0A | 実装済み |
| REQ-0312 BHI_DIS_S | Phase 0A | 実装済み |
| REQ-0313 PBRSB 緩和 | Phase 0A | 実装済み |
| REQ-0314 AMD STIBP | Phase 0A | 実装済み |
| REQ-0315 RSB fill | Phase 0A | 実装済み |
| REQ-0316 L1TF flush | Phase 0A | 実装済み |
| REQ-0317 VERW/MDS/TAA | Phase 0A | 実装済み |
| REQ-0318 AMD LFENCE serialize | Phase 0A | 実装済み |
| REQ-0319 per-CPU vuln profile | Phase 0A | 実装済み |
| REQ-0320 AMD SRSO/Inception | Phase 0A | 実装済み |
| REQ-0321 Intel GDS check | Phase 0A | 実装済み |
| REQ-0330 CET-SS | Phase 2 | ✅ vmx_controls.c CET VMCS config |
| REQ-0331 CET MSR per-vCPU | Phase 2 | ✅ cpu_security.c save/restore |
| REQ-0332 Shadow Stack EPT | Phase 2 | ✅ モデル実装 (PRODUCTION NOTE) |
| REQ-0333 CET-IBT | Phase 2 | ✅ S_CET_ENDBR_EN |
| REQ-0340 MSR インターセプト | Phase 2 | ✅ vmx_controls.c bitmap init |
| REQ-0341 VPID/ASID | Phase 2 | ✅ vmcs_setup.c per-vCPU VPID 割り当て |
| REQ-0342 DR 分離 | Phase 0A | DR save/restore 実装済み |
| REQ-0343 RDPMC インターセプト | Phase 2 | ✅ CR4.PCE=0 ピン留め |
| REQ-0344 Intel PT/AMD IBS | Phase 2 | ✅ RTIT MSR インターセプト |
| REQ-0345 UMIP | Phase 2 | ✅ CR4.UMIP ピン留め |
| REQ-0350 DMA remapping | Phase 0B | モデルのみ |
| REQ-0351 Interrupt remapping | Phase 0B | 未実装 |
| REQ-0352 Passthrough qualification | Phase 0A | 基盤のみ |
| REQ-0353 外部 DMA 分離 | Phase 0B | 未実装 |
| REQ-0360 DRTM | Phase 1 | 未実装 |
| REQ-0361 Boot Guard/PSB | Phase 1 | 未実装 |
| REQ-0362 TPM PCR 検証 | Phase 1 | 未実装 |
| REQ-0370 Preemption Timer | Phase 2 | ✅ vmx_controls.c preemption config |
| REQ-0371 NOTIFY/Bus Lock Exit | Phase 2 | ✅ vmx_controls.c notify + bus lock |
| REQ-0372 exit/entry シーケンス | Phase 0A | vmentry/exit mitigate 実装済み |

### G.5 KCI (REQ-0400–0402)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0400 W^X | Phase 0A + 4-2 | kci_set_wx 実装済み（binding 未完） |
| REQ-0401 モジュール署名 | Phase 4-2 | 未実装 |
| REQ-0402 翻訳整合性連携 | Phase 2 + 4-2 | 未実装 |

### G.6 KSI (REQ-0500–0508)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0500 KSI 基本機能 | Phase 4-3 | 未実装 |
| REQ-0501 Shadow copy + write-enable window | Phase 4-3 | 未実装 |
| REQ-0502 Reference pointer → registered object set | Phase 4-3 | 未実装 (深層監査で追加) |
| REQ-0503 setuid/setgid 検証 | Phase 4-3 | 未実装 |
| REQ-0504 fsid + fileid 識別 | Phase 4-3 | 未実装 |
| REQ-0505 fd 継承リスク → 残留リスク文書化 | Phase 9-4 | 未実装 (深層監査で追加) |
| REQ-0506 Callsite 検証 (RIP) | Phase 4-3 | 未実装 |
| REQ-0507 setuid DB 照合 | Phase 4-3 | 未実装 |
| REQ-0508 許可 callsite table | Phase 4-3 | 未実装 |

### G.7 Key Services (REQ-0600–0604)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0600 IKS 基本機能 | Phase 4-4 | 未実装 |
| REQ-0601 IKS API 制限 | Phase 4-4 | 未実装 |
| REQ-0602 外部暗号 TCB 帰属 | Phase 5 | 未実装 |
| REQ-0603 SKS ディスク暗号鍵 | Phase 4-5 | 未実装 |
| REQ-0604 KEY_EXCHANGE 不透明ハンドル | Phase 4-4 | 未実装 |

### G.8 Update (REQ-0700–0705)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0700 UVS 基本機能 | Phase 4-6 | 未実装 |
| REQ-0701 署名付きマニフェスト | Phase 4-6 | 未実装 |
| REQ-0702 freshness 検出 | Phase 4-6 | 未実装 |
| REQ-0703 HSM + dual-approval | Phase 5-5 | 未実装 (深層監査で追加) |
| REQ-0704 freeze 攻撃検出 | Phase 4-6 | 未実装 |
| REQ-0705 mix-and-match 防止 | Phase 4-6 | 未実装 |

### G.9 FreeBSD Integration (REQ-0800–0804)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0800 FreeBSD 統合基盤 | Phase 6 | 未実装 |
| REQ-0801 非信頼 ABI 変換層 | Phase 6-1 | 未実装 |
| REQ-0802 介入点 | Phase 6-2 | 未実装 |
| REQ-0803 mac(9) 十分性証明 | Phase 6-2 | 未実装 |
| REQ-0804 vmm(4) boot-time 介入 | Phase 6-2 | 未実装 (深層監査で追加) |

### G.10 bhyve/VM (REQ-0900–0909)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0900 bhyve 互換 | Phase 7 | 未実装 |
| REQ-0901 libvmmapi 互換 | Phase 7-1 | 未実装 |
| REQ-0902 未分類 exit fail-closed | Phase 7-2 | 未実装 |
| REQ-0903 再利用前ゼロ化 | Phase 7-3 | 未実装 |
| REQ-0904 IOMMU グループ検証 | Phase 7-4 | 未実装 |
| REQ-0905 非目標: ライブマイグレーション/ネスト仮想化除外 | Phase 7 | 文書化 (深層監査で追加) |
| REQ-0906 vCPU 状態機械 VM_RUN→Runnable のみ | Phase 7-2 | 未実装 (深層監査で追加) |
| REQ-0907 vCPU 状態遷移規則 | Phase 7-2 | 未実装 |
| REQ-0908 VM_GET_VCPU_STATUS | Phase 7-1 | 未実装 |
| REQ-0909 メモリオブジェクトライフサイクル | Phase 7-3 | 未実装 |

### G.11 Quality (REQ-1000–1006)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-1000 トレーサビリティ | Phase 9-1/9-4 | **実装** — `tools/traceability_matrix.py` 自動生成ツール + 115/115 要件にソースタグ |
| REQ-1001 TCB 変更独立レビュー | Phase 9-4 | 未実装 |
| REQ-1002 SPARK 例外不在証明 | Phase 4 | 未実装 |
| REQ-1003 Rust TCB 制約 | Phase 6 | 未実装 |
| REQ-1004 継続的ファジング | Phase 9-1 | **部分実装** — 6ハーネス構築済み (command_page, manifest, multiboot2, iommu, log_decoder, partition_loader) + セキュリティ監査完了。CI 統合・seed corpus・継続実行基盤は未完 |
| REQ-1005 MC/DC カバレッジ | Phase 9-1 | **部分実装** — `make coverage` gcov ターゲット + 分岐カバレッジレポート。`command.c` / `vm_policy.c` / `vmx.c` の 0% regression を gate 化済み。残: lcov HTML レポート、全ファイル目標値設定 |
| REQ-1006 再現可能ビルド | Phase 9-3 | **実装済み** — `make reproducible` (決定性ビルド + 二重ビルド検証) + `make sbom` (SBOM 自動生成) |

### G.12 Production Readiness (REQ-1100–1105)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-1100 AMD 翻訳整合性実証 | Phase 9-2 | 未実装 |
| REQ-1101 FreeBSD 介入点十分性 | Phase 9-4 | 未実装 (深層監査で追加) |
| REQ-1102 更新メタデータ freshness | Phase 9-4 | 未実装 (深層監査で追加) |
| REQ-1103 一次ログ経路運用成立性 | Phase 9-4 | 未実装 |
| REQ-1104 暗号 TCB 確定 | Phase 9-4 | 未実装 |
| REQ-1105 passthrough qualification | Phase 9-4 | 未実装 |

---

## 依存関係グラフ

```
╔══════════════════════════════════════════════════════════════════╗
║  カテゴリ A: マイクロハイパーバイザー (C11 + Frama-C ACSL + asm)  ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Phase 0A (WP品質完結)  ← 完了                                   ║
║      │                                                           ║
║      ├──→ Phase 0B (IOMMU) ── ✅ モデル完了                      ║
║      │         │                                                 ║
║      │         └──→ Phase 0C (ページアロケータ) ── ★ 致命的      ║
║      │                   │                                       ║
║      │                   └──→ Phase 2 (Intel HLAT) ── ✅ 完了    ║
║      │                             │                             ║
║      │                             └──→ Phase 3 (AMD NPT) ✅    ║
║      │                                                           ║
║      ├──→ Phase 1 (ブートパス) ── UEFI/VMCS ✅、IDT/APIC/asm 未 ║
║      │         │                                                 ║
║      │         ├── 1-1 IDT ★  1-6 並行性設計 ★                  ║
║      │         ├── 1-7 APIC仮想化  1-8 エントロピー              ║
║      │         └── 1-12 asm バックエンド体系化                    ║
║      │                                                           ║
║      └──→ Phase 8 (マルチソケット) ── 将来（商用展開前提）        ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  カテゴリ B: 信頼サービス + 暗号 (Ada/SPARK 2014)                ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Phase 4 (信頼サービス) ── Phase 0A hypercall 基盤に依存         ║
║      │                                                           ║
║      └──→ Phase 5 (暗号ライブラリ) ── 信頼サービスが消費         ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  カテゴリ C: FreeBSD フロントエンド (Rust no_std)                 ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Phase 6 (fbvbs.ko) ── Phase 1 + Phase 4 完了後                 ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  カテゴリ D: bhyve/vmm 統合 (C/Rust)                             ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Phase 7 (bhyve/vmm) ── Phase 0B + Phase 1 完了後               ║
║                                                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  カテゴリ E: 品質保証・リリース (全体横断)                        ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Phase 9 (品質保証) ── 全フェーズの成果を統合検証                 ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

**クリティカルパス:** 0A → 0B → 0C → 1 → 2 → 3 → 9

**カテゴリ間依存関係:**
- **A→B:** Phase 4 は Phase 0A の hypercall 基盤に依存（並行開始可能）
- **A→C:** Phase 6 は Phase 1 (FreeBSD 起動) 完了後
- **A→D:** Phase 7 は Phase 0B (IOMMU) + Phase 1 完了後
- **B→C:** Phase 6 の介入点は Phase 4 の信頼サービスに通知
- **B→E:** Phase 5 の暗号は Phase 9 で TCB 監査

**カテゴリ内並行可能:**
- **A 内:** Phase 0B と Phase 1 は並行開発可能。Phase 8 は独立設計可能
- **B 内:** Phase 5 (暗号) は Phase 4 と並行開発可能

---

## リスクと制約

### 技術リスク

| リスク | 影響 | 緩和策 |
|-------|------|--------|
| HLAT 対応 CPU の入手 | Phase 2 ブロック | 12th Gen+ Intel で対応。QEMU エミュレーション活用 |
| AMD NPT 複合経路の十分性実証 | REQ-1100 未達 | 早期に PFN スワップテストを設計 |
| Ada/SPARK ベアメタルランタイム | Phase 4 遅延 | GNAT Community + ZFP ランタイム検証 |
| 暗号実装の監査コスト | Phase 5 遅延 | 検証済み外部ライブラリ（HACL*等）の評価を並行 |
| FreeBSD 15 KLD ABI の安定性 | Phase 6 変更 | FreeBSD CURRENT のトラッキング |

### リソース制約

| 制約 | 影響 | 対策 |
|------|------|------|
| 3.5GB RAM 開発環境 | Frama-C 全ファイル同時実行不可 | per-file WP 実行で回避（確立済み） |
| 実機テスト環境なし | boot path / IOMMU / HLAT の実機検証不可 | QEMU + KVM で最大限シミュレーション |
| 暗号ライブラリ監査 | 外部依存の TCB 帰属問題 | 最小 primitive に限定、TCB 範囲明文化 |

### 残留リスク（Section 50 — 明示的認知）

設計仕様 Section 50 で定義された残留リスク。緩和はするが完全排除は不可能であり、運用者への開示が必要。

| # | 残留リスク | 影響 | 緩和策 | 受容根拠 |
|---|----------|------|--------|---------|
| R-1 | **AMD 翻訳整合性の実装難度** | NPT + PTE trap + shadow + TLB sync の複合経路は HLAT の単一機構より複雑。実証不十分の可能性 | Phase 9-2 で6種の攻撃テスト実施。Appendix F.1 立証課題として構造化 | Intel HLAT が利用可能な場合は HLAT 優先。AMD 経路は補助的位置づけ |
| R-2 | **Tier C 高頻度状態の攻撃面** | filedesc, socket, routing, scheduler, mbuf 等の高頻度変更構造体は KSI 保護対象外 | Tier C は設計上の非保護領域として文書化。MAC/Capsicum/Jail による FreeBSD 側保護で緩和 | 保護コスト（性能影響）が効果を上回る。W^X + Tier A/B で根本的な特権昇格を阻止 |
| R-3 | **外部暗号ライブラリ依存** | 外部暗号実装は TCB に帰属（REQ-0602）。脆弱性発見時に FBVBS の安全性保証が影響を受ける | 最小 primitive に限定。Phase 5-6 で FIPS 認証検討。Phase 9-4 で TCB 範囲確定 | 暗号 primitive の自作は更に高リスク。検証済み実装の採用が最善 |
| R-4 | **OOB 監査ログの品質** | 一次ログ経路（UART/BMC/SOL）はハードウェア・ファームウェア・物理配線に依存。FBVBS の制御外 | Phase 9-4 で運用成立性確認（F.4 立証課題）。対象 HW/FW 設定/BMC 設定/収集サーバの文書化 | OOB 経路の信頼性は運用環境に依存。FBVBS はログ生成に責任、配信は運用者の責任 |
| R-5 | **fd 継承リスク** (REQ-0505) | File descriptor 継承による情報漏洩。KSI の保護範囲外 | FreeBSD の Capsicum capability mode による fd 制限で緩和 | fd 継承は OS 設計の根幹。ハイパーバイザーレベルでの介入はコスト対効果が低い |
| R-6 | **隠れチャネル** | キャッシュ・タイミング・メモリバスによるパーティション間情報漏洩 | Phase 9-5 で分析。IBPB/L1 flush/VERW で部分緩和。残留チャネルの帯域を測定・文書化 | 完全排除は現行 x86 アーキテクチャでは不可能。帯域の定量化と受容判断 |

---

## 優先順位と推奨実行順序

### 最高優先（ブロッカー解消） — カテゴリ A

1. **Phase 0A**: WP 品質完結 ✅ 完了
2. **Phase 0B**: IOMMU 実機有効化 ✅ モデル完了
3. **Phase 0C**: 物理ページアロケータ ★ **致命的ブロッカー**
4. **Phase 1**: ブートパス（UEFI ✅、IDT/APIC/asm/並行性設計 残）
5. **Phase 2**: Intel HLAT ✅ 完了
6. **Phase 3**: AMD NPT ✅ 完了

### 高優先（セキュリティサービス） — カテゴリ B

7. **Phase 4-1**: 信頼サービス基盤（全サービスの前提）
8. **Phase 4-2**: KCI（カーネルコード保護）
9. **Phase 4-3**: KSI（カーネル状態保護）
10. **Phase 5**: 暗号ライブラリ + HSM 統合 + FIPS 検討
11. **Phase 4-4/4-5/4-6**: IKS/SKS/UVS

### 中優先（統合） — カテゴリ C・D

12. **Phase 6**: fbvbs.ko (Rust)
13. **Phase 7**: bhyve/vmm 統合（タイマー仮想化、vCPU 状態機械含む）

### 通常優先（品質） — カテゴリ E

14. **Phase 9**: 品質保証・リリース（故障注入、MISRA、CC/FIPS、隠れチャネル、CI/CD）

### 低優先（将来） — カテゴリ A 拡張

15. **Phase 8**: マルチソケット

---

## 監査補遺: 設計仕様との差分（2026-03-20 自己監査）

本ロードマップを plan/fbvbs-design.md の全セクション・全 Appendix と照合した結果、以下の要素が欠落または不十分であった。これらは極めてクリティカルなシステムとして全て対処が必要である。

### A. Appendix F: 本番宣言前の6つの立証課題（明示的構造化不足）

設計仕様 Appendix F は6つの独立した立証課題を定義している。Phase 9 で部分的に言及したが、各課題を独立した検証タスクとして構造化していなかった。

| # | 立証課題 | 対応フェーズ | 追加すべき証拠要件 |
|---|---------|-----------|-----------------|
| F.1 | AMD 翻訳整合性経路 | Phase 3 + 9-2 | PFN差替え・PTE改ざん・TLB race・マルチコア競合・異常fault順序・復旧経路の全証拠 |
| F.2 | FreeBSD 介入点の十分性 | Phase 6 | 各不変条件に対する介入点の個別実証（mac(9) entry point だけでは不十分） |
| F.3 | 更新メタデータ freshness/整合性 | Phase 4-6 | freeze攻撃・mix-and-match・期限切れ・stale mirror・ロールバック復旧手順の全テスト |
| F.4 | 一次監査ログ経路の運用実在性 | Phase 9-4 | 対象HW・FW設定・BMC設定・配線・収集サーバ・保存ポリシー・障害代替・過負荷欠落特性 |
| F.5 | 暗号実装選定の TCB 確定 | Phase 5 + 9-4 | primitive vs protocol の境界確定、外部依存の TCB 帰属文書化 |
| F.6 | bhyve passthrough/IOMMU 統合 | Phase 7 + 9-4 | サポート対象デバイス群ごとの qualification matrix 作成 |

### B. 欠落した Appendix 対応

#### B.1 Appendix D.4: Bootstrap Metadata Page（未言及）

Phase 1 および Phase 4 に追加必要:
- `fbvbs_bootstrap_page_v1` 構造体の実装と WP 検証
- 各パーティションへの bootstrap page 公開（read-only）
- `RSI` レジスタ経由の GPA 受け渡し
- vCPU 数と command_page_gpa 配列の整合性検証

#### B.2 Appendix I: サービス障害影響マトリクス（未言及）

Phase 9 に追加必要:
- 各サービス（KCI/KSI/IKS/SKS/UVS）障害時の影響テスト
- 「停止する機能」vs「維持される保護」の実証
- マイクロハイパーバイザー自体の障害 = 全システム停止の文書化
- 障害時の第二レベルページング保護維持の検証

#### B.3 Appendix J: 性能バジェット（未言及）

Phase 9 に追加必要:
- 通常 syscall: 追加コスト実質ゼロの計測
- Tier B 読取り: IPC なし（直接メモリ読取り）の確認
- Tier B 変更: 数µs〜十数µs 目標の計測
- Setuid exec 検証: 十数µs 目標の計測
- KLD ロード: 100ms〜サブ秒の計測
- VM exit ファストパス: サブµs の計測
- **禁止事項の検証**: 通常 syscall への VMCALL 挿入禁止、Tier B 読取りへの VMCALL 禁止

#### B.4 Appendix K: 設計仕様内ロードマップとの整合

設計仕様 Appendix K は7つのインクリメントを定義。本ロードマップの Phase 体系との対応:
- Increment 1 → Phase 0A + 0B + 1
- Increment 2 → Phase 4-2 (KCI) + Phase 2 (CR pinning)
- Increment 3 → Phase 4-3 (KSI)
- Increment 4 → Phase 4-4/4-5 + Phase 3 + Phase 5
- Increment 5 → Phase 7 + Phase 4-3 拡張
- Increment 6 → Phase 4-6 (UVS) + Phase 2 (HLAT)
- Increment 7 → Phase 9

### C. 欠落した ABI/プロトコル要件

#### C.1 vCPU 状態機械（Section 35.1, REQ-0907）

Phase 7 に追加必要:
- vCPU 6状態（Created/Runnable/Running/Blocked/Faulted/Destroyed）の完全実装
- VM exit 種別→状態遷移の固定規則実装
- `halt` → `Blocked` 遷移と割込み注入による `Runnable` 復帰
- 未分類 exit → `Faulted` の fail-closed 処理
- multi-vCPU VM の集約規則（任意 vCPU fault → VM 全体 Faulted）
- `VM_GET_VCPU_STATUS` call の実装（REQ-0908）
- `VM_RUN` は `Runnable` のみ、`VM_INJECT_INTERRUPT` は `Runnable`/`Blocked` のみ
- `VM_SET_REGISTER`/`VM_GET_REGISTER` は `Running` 時禁止

#### C.2 VM_CREATE vs PARTITION_CREATE 制限（Section 34）

Phase 7 に追加必要:
- `PARTITION_CREATE(kind=PARTITION_KIND_GUEST_VM)` → `INVALID_PARAMETER` の強制
- guest VM は `VM_CREATE` のみで生成可能
- `PARTITION_DESTROY` は guest VM に使用不可、`VM_DESTROY` のみ許可

#### C.3 FBVBS_CMD_FLAG_SEPARATE_OUTPUT 検証

Phase 0A に追加必要:
- 別出力ページが `MEMORY_REGISTER_SHARED(peer_partition_id=0)` で登録済み writable shared object であることの検証
- output_page_gpa のアラインメント検証（実装済みだが ACSL 検証要）
- `BUFFER_TOO_SMALL` 時の `actual_output_length` 書き戻しテスト

#### C.4 Manifest-Driven Autostart（Section 12, 19）

Phase 1 + Phase 4 に追加必要:
- manifest の `autostart=true` に基づく boot 時自動パーティション生成
- `service_kind`, `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp` の manifest 決定
- `SERVICE_KIND_KCI/KSI/IKS/SKS/UVS` の 5 種限定
- 測定前は `SERVICE_KIND_NONE` として扱う

#### C.5 Canonical CBOR Manifest パーサ（Appendix L.1.D）

Phase 4-6 (UVS) に追加必要:
- RFC 8949 準拠の canonical CBOR パーサ実装
- 必須キー検証（component_type, payload_hash, signature, generation, security_epoch）
- 依存関係解決（dependencies フィールドの component_type + payload_hash + minimum_generation）
- Ed25519 64-byte raw signature 検証
- 失効リスト（revocation_refs）の処理

#### C.6 Fixed Executable Loader 検証（Appendix L.1.E）

retained-C では fixed `ET_EXEC` subset を実装済み:
- `ET_EXEC` ELF64 のみ許可（`ET_DYN` と他の ELF type は拒否）
- `PT_LOAD` セグメント検証
- 動的リンク禁止、圧縮禁止、self-unpack 禁止
- executable entry segment 必須
- stack page は writable かつ non-executable でなければならない
- 非 canonical アドレス拒否

#### C.7 VM Exit Payload Layout 適合（Appendix L.1.F）

Phase 7 に追加必要:
- PIO/MMIO/external interrupt/EPT violation/CR access の固定 payload 構造準拠
- exit_length 境界検証
- 未分類 exit の fail-closed 処理テスト

#### C.8 memory_limit_bytes アカウンティング（Section 19）

Phase 0A に確認必要:
- `MEMORY_REGISTER_SHARED` 成功時点では memory_limit_bytes/mapped_bytes を消費しない
- 実際の map 時点でのみ page-aligned bytes をアカウンティング
- shared registration 解除時: peer mapping 剥がし → registration metadata 削除の順序

#### C.9 CPU 初期状態凍結（Section 18）

Phase 1 + Phase 4 に追加必要:
- `RFLAGS = 0x0000000000000002`（bit 1 必須）
- `CR0` 基底値 `0x80010033` + pin policy 適用
- `CR4` 基底値 `0x000006f0` + pin policy 適用
- 汎用レジスタ（RIP/RSP 除き）= 0
- XMM/YMM/ZMM = 0
- FS.base/GS.base = 0
- flat 64-bit segment model
- RSI = bootstrap page GPA

### D. MBEC/GMET（実行制御細粒度化）✅ (2026-03-21)

Phase 2 + Phase 3 に追加必要:
- ✅ Intel MBEC: EPT のユーザー/スーパーバイザー実行権限分離 — `hlat.c` `fbvbs_mbec_build_config`
- ✅ AMD GMET: NPT の同等機能 — `amd_npt.c` `fbvbs_gmet_build_config`
- ✅ W^X 強制で MBEC/GMET を活用（カーネルモード execute-only の実現）— both enforce W^X invariant

### E. マルチコア Tier B 更新の原子性（Section 27.1）

Phase 4-3 (KSI) に追加必要:
- write-enable/copy/read-only サイクルの最小時間化
- 複数 CPU コアの当該ページ書込み一時停止メカニズム
- 大構造体のページ置換方式（新ページ構成→ポインタ原子切替→旧ページ解除）

### F. Passthrough デバイス詳細（Section 37）

Phase 7-4 に追加必要:
- Function Level Reset (FLR) または同等の安全リセット手順
- MSI/MSI-X 再設定の制御（意図しないベクタ/CPU 注入防止）
- デバイス解除時の状態持ち越し防止
- per-device qualification matrix（Appendix F.6 立証課題）

### G. モノトニック caller_sequence のテスト（Section 20.3）

Phase 0A に追加必要:
- per-vCPU のシーケンス管理（グローバルではない）の確認
- 後退/再利用 → `REPLAY_DETECTED` のネガティブテスト
- 並列 vCPU での独立シーケンス進行テスト

### H. Tombstone 管理（Section 18.1）

Phase 0A に確認必要:
- destroy 済み partition ID は tombstone として保持
- `PARTITION_GET_STATUS` に `Destroyed` を返す
- destroy 済み ID を他 call に使用 → `INVALID_STATE`
- ABI v1 では再起動まで ID 再利用禁止

---

## 改訂後の要件カバレッジサマリ (2026-03-21 深層監査改訂)

| カテゴリ | 要件数 | カバー済み | 深層監査追加 | 未対応 |
|---------|--------|----------|------------|--------|
| G.1 Boot/Platform | 6 | 6 | 0 | 0 |
| G.2 Logging | 8 | 8 | 0 | 0 |
| G.3 Partition | 13 | 13 | 0 | 0 |
| G.4 CPU Control | 38 | 38 | 0 | 0 |
| G.5 KCI | 3 | 3 | 0 | 0 |
| G.6 KSI | 9 | 9 | +2 (REQ-0502, 0505) | 0 |
| G.7 Key Services | 5 | 5 | 0 | 0 |
| G.8 Update | 6 | 6 | +1 (REQ-0703) | 0 |
| G.9 FreeBSD | 5 | 5 | +1 (REQ-0804) | 0 |
| G.10 bhyve/VM | 10 | 10 | +2 (REQ-0905, 0906) | 0 |
| G.11 Quality | 7 | 7 | 0 | 0 |
| G.12 Production | 6 | 6 | +2 (REQ-1101, 1102) | 0 |
| **Appendix D** | — | — | **+4** | 0 |
| **Appendix F** | 6 | 6 | **構造化** | 0 |
| **Appendix I** | — | — | **+4** | 0 |
| **Appendix J** | — | — | **+7** | 0 |
| **ABI/Protocol** | — | — | **+15** | 0 |
| **インフラ基盤** | — | — | **+3** (Phase 0C, IDT, 並行性) | 0 |
| **セキュリティ強化** | — | — | **+8** (硬化フラグ, ログ制限, APIC, entropy, watchdog, asm, FIPS, HSM) | 0 |
| **品質プロセス** | — | — | **+12** (故障注入, MISRA, CC, 隠れチャネル, CI/CD, 性能, 障害影響, プロセス規律) | 0 |
| **残留リスク** | 6 | 6 | **新規セクション** | 0 |
| **合計** | 116+ REQ | 116 | +58 項目 | 0 |
