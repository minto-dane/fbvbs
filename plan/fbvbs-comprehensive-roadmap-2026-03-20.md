# FBVBS v7 包括的実装ロードマップ

**日付:** 2026-03-20
**基準文書:** plan/fbvbs-design.md (FBVBS v7 仕様書)
**現状:** Phase 0 進行中 — マイクロハイパーバイザー C11 + ACSL retained C 実装

---

## 現状サマリ

### 実装済み（Phase 0 完了部分）

| コンポーネント | ファイル | 行数(概算) | WP検証 | 状態 |
|--------------|---------|-----------|--------|------|
| hypercall dispatch | command.c | ~2150 | 2494/2500 (6 TO) | TOCTOU全修正済 |
| パーティション管理 | partition.c | ~2830 | 1626/1639 (13 TO) | ライフサイクル完全 + IOMMU domain管理 |
| CPU セキュリティ | cpu_security.c | ~1175 | 628/628 (0 TO) ✅ | 81機能検出・緩和 |
| VMX 制御 | vmx.c | ~580 | 99%+ (1 TO) | probe/setup/run |
| メモリ管理 | memory.c | ~400 | 100% | EPTマッピング |
| 監査ログ | log.c | ~280 | 100% | ringbuf + CRC32C |
| VM ポリシー | vm_policy.c | ~300 | 100% | capability mask |
| セキュリティ | security.c | ~1800 | 1581/1595 (14 TO) | manifest/hash/KCI — TO全てGPA manifest chain |
| カーネル統合 | kernel.c | ~400 | 100%- (1 TO) | model code |
| メモリユーティリティ | memory_utils.c | ~150 | WP除外 | void*関数群 |
| ブートパーサ | boot_multiboot.c | ~250 | WP対象外 | multiboot2 parse |
| IOMMU VT-d | iommu_vtd.c | ~900 | WP対象外 | DMAR パーサ + レジスタ制御 (Phase 0B-1/0B-2) |
| IOMMU AMD-Vi | iommu_amdvi.c | ~470 | WP対象外 | IVRS パーサ + レジスタ制御 (Phase 0B-3) |

**WP検証合計:** 6,260+ proved goals (99.5%+), 34 timeouts, 0 smoke failures

### 未実装・ブロッカー

1. **IOMMU 実機有効化** — DMAR/IVRS パースなし、モデルコードのみ
2. **ブートパス** — boot.S/UEFI→ハイパーバイザー起動コード未実装
3. **HLAT/翻訳整合性** — Intel HLAT / AMD NPT 複合経路未実装
4. **信頼サービスパーティション** — KCI/KSI/IKS/SKS/UVS 全て stub
5. **暗号ライブラリ** — SHA-256/384, Ed25519, AES 実装なし
6. **FreeBSD フロントエンド** — fbvbs.ko 未実装
7. **bhyve/vmm 統合** — vmm.ko 互換層未実装
8. **マルチソケット** — AP 初期化、IPI、NUMA なし

---

## フェーズ定義

### Phase 0A: マイクロハイパーバイザー品質完結（現在地 → 完了）

**目標:** 現行 retained C コードの形式検証品質を最終化し、Phase 0 の全ブロッカーを解消する。

**対象要件:**
- REQ-0200 (マイクロハイパーバイザー責務限定)
- REQ-0201 (形式的解析証拠)
- REQ-0202–0212 (パーティション/hypercall ABI)
- REQ-0205–0210 (command page ABI)

#### 0A-1. WP タイムアウト削減

現在 ~~62~~ → **26** timeouts（cpu_security 33→0, partition 10→5, security 10→14(+4 GPA), command 6, vmx 1, kernel 1）。目標: 30 以下 ✅達成。残26の内訳: GPA manifest chain 14, dispatch GPA assigns 6, release_shared_registrations 2D assigns 5, vmx/kernel model 2。

| ファイル | 現在のTO | 主因 | 削減戦略 |
|---------|---------|------|---------|
| cpu_security.c | ~~33~~ → **0** ✅ | 巨大 switch/enum、MSR ビット演算 | 関数分割完了: detect_common/amd_features, merge_worst_case_vuln, features_match_common/amd, vuln_profiles_match |
| partition.c | ~~10~~ → **5** | release_shared_registrations 2D assigns | 残5はネストループ assigns 構造限界、許容 |
| security.c | ~~10~~ → **14** | GPA manifest 検証経路全体 | `#ifdef __FRAMAC__` モデル必要（Phase 0A-4） |
| command.c | **6** (変化なし) | dispatch_hypercall GPA assigns | 構造的限界、許容 |
| vmx.c | 1 | vmx_probe 分岐 | behavior 分割済み、許容 |
| kernel.c | 1 | model code | 許容 |

**アクション:**
1. ~~cpu_security.c: 関数分割~~ → ✅完了 (33→0 TO: detect_common/amd_features, merge_worst_case_vuln, features_match_*, vuln_profiles_match, ローカルvendorキャッシュ, initialized requires削除)
2. ~~partition.c~~ → ✅完了 (10→5 TO: ヘッダ契約追加で5解消、残5はrelease_shared_registrations 2D assigns構造限界)
3. security.c: 14 TO全てGPA manifest chain → Phase 0A-4 に移動（`#ifdef __FRAMAC__` モデル必要）
4. command.c: 6 TO変化なし（dispatch_hypercall GPA assigns、構造限界、許容）
5. **ヘッダ契約追加**: fbvbs_find_manifest_profile_for_object, fbvbs_vmx_run_vcpu, fbvbs_log_append, fbvbs_primary_host_callsite に ACSL 契約追加 → partition.c 5件解消

#### 0A-2. KCI_SET_WX page binding 完成 ✅

**対象要件:** REQ-0400–0402

**完了:**
1. ✅ `struct fbvbs_kci_page_binding` 設計・実装（FBVBS_MAX_KCI_PAGE_BINDINGS=64）
2. ✅ `fbvbs_kci_verify_page_hash()` — execute 権限付与前の hash 検証（モデル実装、PRODUCTION NOTE付き、Phase 5 暗号統合で本番化）
3. ✅ `fbvbs_kci_record_binding()` — 検証成功時の GPA→artifact binding 記録
4. ✅ `fbvbs_kci_invalidate_bindings_for_gpa()` — memory_unmap/set_permission 時の binding 無効化
5. ✅ kci_set_wx に hash 検証 + binding 記録統合、MEASUREMENT_FAILED/RESOURCE_EXHAUSTED 返却値追加
6. ✅ 本番ビルドは fail-closed（hash 検証未実装時は execute 拒否）
7. ACSL 契約は新規関数に記述済み、WP 検証は Phase 0A-1 完了状態に含む

#### 0A-3. Device qualification 基盤 ✅

**対象要件:** REQ-0352, REQ-0904

**完了:**
1. ✅ `fbvbs_device_catalog_entry` に ACS capability, FLR support, MSI-X control, vendor/device ID, qualification flag 追加
2. ✅ `vm_assign_device` に qualification チェック追加（qualified + has_flr + has_acs 必須）
3. ✅ `hypervisor/compliance/device_qualification_matrix.md` 作成（8項目の qualification criteria）
4. 本体は引き続き fail-closed（IOMMU domain 作成は Phase 0B）

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

### Phase 1: プラットフォームブートパス

**目標:** UEFI → マイクロハイパーバイザー → FreeBSD の完全ブートチェーンを実装する。

**対象要件:**
- REQ-0001 (FreeBSD より前にロード)
- REQ-0002 (VMX root 取得)
- REQ-0006 (起動時検証・測定)
- REQ-0360–0362 (DRTM, Boot Guard/PSB, TPM)

#### 1-1. UEFI アプリケーション

**新規ファイル:** `boot/uefi_entry.c`, `boot/uefi_boot.c`

**アクション:**
1. UEFI application エントリポイント (EFI_MAIN)
2. EFI_BOOT_SERVICES を使った メモリマップ取得
3. マイクロハイパーバイザーイメージの配置
4. ページテーブル初期設定（identity mapping）
5. GDT/IDT 初期設定
6. VMX/SVM 有効化判定

#### 1-2. ベアメタル初期化（boot.S）

**新規ファイル:** `boot/boot.S`, `boot/early_init.c`

**アクション:**
1. x86_64 long mode 確認
2. CR0/CR4 初期ビット設定
3. VMX enable (CR4.VMXE → VMXON)
4. 初期 VMCS/VMCB 構築
5. ハイパーバイザースタック確保
6. BSP CPU セキュリティ初期化呼び出し

#### 1-3. FreeBSD deprivilege

**アクション:**
1. FreeBSD カーネルイメージをゲストメモリ領域に配置
2. EPT/NPT ページテーブル構築
3. FreeBSD を VMX non-root / SVM guest として起動
4. VM exit ハンドラチェーンへの接続
5. 一次監査ログ初期化（UART 経路）

#### 1-4. DRTM 統合（高保証構成）

**アクション:**
1. Intel TXT: GETSEC[SENTER] シーケンス実装
2. AMD SKINIT: SKINIT 命令シーケンス実装
3. ACM (Authenticated Code Module) ロードと検証
4. TPM 2.0 PCR 拡張
5. 起動測定チェーン記録

#### 1-5. Secure Boot 統合

**アクション:**
1. UEFI Secure Boot 変数検証
2. マイクロハイパーバイザー署名検証
3. Boot Guard / PSB 状態確認
4. 起動チェーン証拠の監査ログ記録

---

### Phase 2: Intel HLAT 翻訳整合性

**目標:** HLAT による カーネルコード領域の翻訳整合性保護。

**対象要件:**
- REQ-0301 (Intel HLAT 必須)
- REQ-0330–0333 (CET 要件)
- REQ-0340–0345 (MSR/レジスタ分離)
- REQ-0370–0372 (仮想化制御)
- REQ-0400–0402 (KCI)

#### 2-1. HLAT テーブル管理

**新規ファイル:** `hypervisor/src/hlat.c`

**アクション:**
1. HLAT 対応検出 (CPUID)
2. HLAT ページテーブル構築（カーネルテキスト領域のみ）
3. VMCS HLAT pointer 設定
4. EPT + HLAT 二重翻訳の整合性検証
5. HLAT テーブル更新（KLD ロード時）

#### 2-2. CR ピン留め強化

**アクション:**
1. CR0.WP, CR4.SMEP, CR4.SMAP, CR4.CET ピン留め
2. VM exit ハンドラでの CR 書き込みインターセプト
3. 不正 CR 変更の拒否とログ記録
4. CR4.PCE = 0 ピン留め (REQ-0343)
5. CR4.UMIP ピン留め (REQ-0345)

#### 2-3. CET Shadow Stack 統合

**アクション:**
1. マイクロハイパーバイザー自身の CET-SS 有効化
2. CET MSR の per-vCPU 保存・復元 (REQ-0331)
3. Shadow Stack ページの EPT 属性設定 (REQ-0332)
4. CET-IBT 有効化 (REQ-0333)

#### 2-4. MSR ビットマップとインターセプト

**アクション:**
1. セキュリティ重要 MSR の無条件インターセプト (REQ-0340)
2. VPID/ASID 一意割り当て (REQ-0341)
3. デバッグレジスタ分離 (REQ-0342)
4. Intel PT / AMD IBS MSR インターセプト (REQ-0344)

#### 2-5. VMX Preemption Timer / Notify Exit

**アクション:**
1. VMX Preemption Timer 設定 (REQ-0370)
2. NOTIFY VM Exit / Bus Lock VM Exit 検出 (REQ-0371)
3. ゲスト CPU 独占防止ポリシー

---

### Phase 3: AMD 翻訳整合性（複合経路）

**目標:** AMD プラットフォームで HLAT と同等のセキュリティ目標を NPT + 複合機構で達成する。

**対象要件:**
- REQ-0302 (AMD NPT 複合経路必須)
- REQ-0303 (高保証: PFN 差替え等の実証)
- REQ-0304 (SEV-SNP は補強のみ)
- REQ-1100 (本番前実証必須)

#### 3-1. NPT Write-Protect 経路

**新規ファイル:** `hypervisor/src/amd_npt.c`

**アクション:**
1. NPT ページテーブル構築
2. カーネルテキスト PTE ページの write-protect
3. PTE 改ざん検出（NPT violation ハンドラ）
4. Shadow translation テーブル管理

#### 3-2. ページテーブル更新トラップ

**アクション:**
1. NPT write fault ハンドラ
2. PTE 更新リクエストの検証（KCI 連携）
3. 正当な PTE 更新（KLD ロード時）のみ許可
4. 不正 PFN 差し替えの検出と拒否

#### 3-3. TLB 同期と競合防止

**アクション:**
1. INVLPG/INVLPGA インターセプト
2. マルチコア TLB invalidation の原子性保証
3. TLB invalidate race condition テスト
4. マルチコア PTE 更新競合テスト

#### 3-4. SEV-SNP 補助（オプション）

**アクション:**
1. RMP テーブル操作（補強として）
2. VMPL レベル設定
3. SEV-SNP 有効時の追加分離保証

---

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
5. GNATprove 全関数証明

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

---

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

#### 6-2. 介入点実装 (REQ-0802)

**アクション:**
1. KLD ロードフック → KCI 通知
2. execve/fexecve 検証フック → KSI setuid 検証
3. setuid/setgid 系検証フック
4. Jail 操作フック
5. MAC framework フック
6. Capsicum capability mode/rights 縮減フック
7. 鍵利用経路フック → IKS/SKS 連携

#### 6-3. ミラーログ消費

**アクション:**
1. ミラーログリングバッファの読み取り専用マッピング
2. syslog / devd / sysctl 経由の公開
3. ログ形式のユーザーランドパーサ

---

### Phase 7: bhyve/vmm 統合

**目標:** 既存 bhyve ユーザーランドの再利用と vmm.ko 互換層。

**対象要件:**
- REQ-0900–0909 (bhyve/仮想化)

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

### Phase 8: マルチソケット対応（将来）

**目標:** UPI リンク接続のマルチソケット環境での正常動作。

**現状分析:**
- 現在の実装は BSP (Bootstrap Processor) のみで動作
- `cpu_security.c` に per-CPU プロファイル構造はあるが AP 初期化なし
- IOMMU は per-socket で存在するため、マルチソケットでは複数 IOMMU の統合管理が必要
- NUMA メモリトポロジの考慮が必要

**マルチソケット対応の必要性:**
- FBVBS v7 仕様は明示的にマルチソケットを要求していない
- ただし REQ-0319 は「マルチコア環境ではすべての論理プロセッサで一貫性を検証」を要求
- サーバー/データセンター環境ではデュアルソケットが一般的
- Phase 8 として位置づけ、本番宣言の必須条件ではないが、商用展開の前提条件とする

#### 8-1. AP (Application Processor) 初期化

**アクション:**
1. ACPI MADT (Multiple APIC Description Table) パース
2. AP の SIPI (Startup IPI) 送信シーケンス
3. per-AP の VMX/SVM 有効化
4. per-AP の CPU セキュリティ初期化（REQ-0319 一貫性検証）
5. AP の VMCS/VMCB 構築

#### 8-2. IPI (Inter-Processor Interrupt) ハンドリング

**アクション:**
1. xAPIC / x2APIC モード検出と初期化
2. IPI 送信/受信ハンドラ
3. TLB shootdown IPI の仮想化
4. パーティション間コンテキスト切替の IPI 協調

#### 8-3. NUMA 対応

**アクション:**
1. ACPI SRAT (System Resource Affinity Table) パース
2. NUMA ドメインごとのメモリ割り当てポリシー
3. パーティションの NUMA ドメイン affinity
4. 近接メモリ優先配置

#### 8-4. マルチソケット IOMMU 統合

**アクション:**
1. per-socket IOMMU 検出と初期化
2. socket をまたぐデバイスの DMA ドメイン管理
3. interrupt remapping のソケット間整合性

---

### Phase 9: 品質保証とリリース準備

**目標:** 本番宣言に必要な品質基準を全て達成する。

**対象要件:**
- REQ-1000–1006 (品質・供給網)
- REQ-1100–1105 (本番準備)

#### 9-1. 検証キャンペーン

**アクション:**
1. 全 hypercall パーサの継続的 Fuzzing (REQ-1004)
   - AFL++ / libFuzzer による command page ファジング
   - IPC parser ファジング
   - update parser ファジング
   - signature loader ファジング
   - log decoder ファジング
   - bhyve front-end 境界ファジング
2. 中核分岐の MC/DC カバレッジ (REQ-1005)
3. 要求→設計→実装→試験→証拠の双方向トレーサビリティ (REQ-1000)

#### 9-2. AMD 翻訳整合性実証 (REQ-1100)

**アクション:**
1. PFN 差替え攻撃テスト
2. PTE 改ざん検出テスト
3. TLB invalidate race テスト
4. マルチコア更新競合テスト
5. 結果の文書化と証拠記録

#### 9-3. リリース成果物

**アクション:**
1. 再現可能ビルド (REQ-1006)
2. SBOM (Software Bill of Materials)
3. 署名付き provenance
4. Frama-C WP 証明アーティファクト
5. GNATprove 証明アーティファクト

#### 9-4. 監査と認証準備

**アクション:**
1. 独立セキュリティ監査
2. TCB 変更の独立レビュア承認プロセス (REQ-1001)
3. 暗号実装の TCB 範囲確定 (REQ-1104)
4. passthrough デバイス qualification matrix (REQ-1105)
5. 一次監査ログ経路の運用成立性確認 (REQ-1103)

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
| REQ-0300 CR ピン留め | Phase 2 | cpu_security.c 検出済み、VMX 強制未実装 |
| REQ-0301 Intel HLAT 必須 | Phase 2 | 未実装 |
| REQ-0302 AMD NPT 複合経路 | Phase 3 | 未実装 |
| REQ-0303 AMD 高保証実証 | Phase 3+9 | 未実装 |
| REQ-0304 SEV-SNP 補強のみ | Phase 3 | 文書で対応 |
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
| REQ-0330 CET-SS | Phase 2 | 未実装 |
| REQ-0331 CET MSR per-vCPU | Phase 2 | 未実装 |
| REQ-0332 Shadow Stack EPT | Phase 2 | 未実装 |
| REQ-0333 CET-IBT | Phase 2 | 未実装 |
| REQ-0340 MSR インターセプト | Phase 2 | 未実装 |
| REQ-0341 VPID/ASID | Phase 2 | 未実装 |
| REQ-0342 DR 分離 | Phase 0A | DR save/restore 実装済み |
| REQ-0343 RDPMC インターセプト | Phase 2 | 未実装 |
| REQ-0344 Intel PT/AMD IBS | Phase 2 | 未実装 |
| REQ-0345 UMIP | Phase 2 | 未実装 |
| REQ-0350 DMA remapping | Phase 0B | モデルのみ |
| REQ-0351 Interrupt remapping | Phase 0B | 未実装 |
| REQ-0352 Passthrough qualification | Phase 0A | 基盤のみ |
| REQ-0353 外部 DMA 分離 | Phase 0B | 未実装 |
| REQ-0360 DRTM | Phase 1 | 未実装 |
| REQ-0361 Boot Guard/PSB | Phase 1 | 未実装 |
| REQ-0362 TPM PCR 検証 | Phase 1 | 未実装 |
| REQ-0370 Preemption Timer | Phase 2 | 未実装 |
| REQ-0371 NOTIFY/Bus Lock Exit | Phase 2 | 未実装 |
| REQ-0372 exit/entry シーケンス | Phase 0A | vmentry/exit mitigate 実装済み |

### G.5 KCI (REQ-0400–0402)

| 要件 | フェーズ | 状態 |
|------|---------|------|
| REQ-0400 W^X | Phase 0A + 4-2 | kci_set_wx 実装済み（binding 未完） |
| REQ-0401 モジュール署名 | Phase 4-2 | 未実装 |
| REQ-0402 翻訳整合性連携 | Phase 2 + 4-2 | 未実装 |

### G.6 KSI (REQ-0500–0508)

全て Phase 4-3 で実装。現在全て未実装。

### G.7 Key Services (REQ-0600–0604)

全て Phase 4-4/4-5 + Phase 5 で実装。現在全て未実装（stub のみ）。

### G.8 Update (REQ-0700–0705)

全て Phase 4-6 で実装。現在全て未実装。

### G.9 FreeBSD Integration (REQ-0800–0804)

全て Phase 6 で実装。現在全て未実装。

### G.10 bhyve/VM (REQ-0900–0909)

全て Phase 7 で実装。現在全て未実装。

### G.11 Quality (REQ-1000–1006)

全て Phase 9 で対応。REQ-1002 は Phase 4 の GNATprove で対応。

### G.12 Production Readiness (REQ-1100–1105)

全て Phase 9 で対応。

---

## 依存関係グラフ

```
Phase 0A (WP品質完結・デバイス基盤)   ← 現在地
    │
    ├──→ Phase 0B (IOMMU 実機有効化)
    │         │
    │         ├──→ Phase 2 (Intel HLAT)
    │         │         │
    │         │         └──→ Phase 3 (AMD NPT) [Intel 先行]
    │         │
    │         └──→ Phase 7 (bhyve/vmm) [IOMMU ドメイン管理必要]
    │
    ├──→ Phase 1 (ブートパス)
    │         │
    │         ├──→ Phase 2 (HLAT は VMX 環境必要)
    │         │
    │         └──→ Phase 6 (fbvbs.ko は FreeBSD 起動後)
    │
    ├──→ Phase 4 (信頼サービス) [IPC は Phase 0A の hypercall 基盤に依存]
    │         │
    │         ├──→ Phase 5 (暗号) [信頼サービスが消費]
    │         │
    │         └──→ Phase 6 (fbvbs.ko) [介入点は信頼サービスに通知]
    │
    └──→ Phase 8 (マルチソケット) [全フェーズ完了後、商用展開前]

Phase 9 (品質保証) ← 全フェーズの成果を統合検証
```

**クリティカルパス:** 0A → 0B → 1 → 2 → 3 → 9

**並行可能:**
- Phase 4 (信頼サービス) は Phase 0A 完了後に Phase 0B/1 と並行開始可能
- Phase 5 (暗号) は Phase 4 と並行開発可能
- Phase 6 (fbvbs.ko) は Phase 1 + 4 完了後
- Phase 7 (bhyve) は Phase 0B + 1 完了後
- Phase 8 (マルチソケット) は独立して設計可能（実装は全フェーズ後）

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

---

## 優先順位と推奨実行順序

### 最高優先（ブロッカー解消）

1. **Phase 0A-1**: WP タイムアウト削減（形式検証品質の確定）
2. **Phase 0B-1/0B-2**: Intel VT-d DMAR パースと有効化（REQ-0003 必須）
3. **Phase 1-1/1-2**: UEFI ブートパス（全実機動作の前提）

### 高優先（コア機能）

4. **Phase 2-1**: HLAT 統合（REQ-0301 必須）
5. **Phase 0B-3/0B-4**: AMD IOMMU（デュアルプラットフォーム対応）
6. **Phase 4-1**: 信頼サービス基盤（全サービスの前提）

### 中優先（セキュリティサービス）

7. **Phase 4-2**: KCI（カーネルコード保護）
8. **Phase 4-3**: KSI（カーネル状態保護）
9. **Phase 5**: 暗号ライブラリ
10. **Phase 3**: AMD 翻訳整合性

### 通常優先（統合・品質）

11. **Phase 6**: fbvbs.ko
12. **Phase 7**: bhyve/vmm
13. **Phase 4-4/4-5/4-6**: IKS/SKS/UVS
14. **Phase 9**: 品質保証・リリース

### 低優先（将来）

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

Phase 4-2 (KCI) に追加必要:
- ET_EXEC / ET_DYN のみ許可（他の ELF type は拒否）
- PT_LOAD セグメントの検証
- 動的リンク禁止、圧縮禁止、self-unpack 禁止
- セグメントオーバーラップ拒否
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

### D. MBEC/GMET（実行制御細粒度化）

Phase 2 + Phase 3 に追加必要:
- Intel MBEC: EPT のユーザー/スーパーバイザー実行権限分離
- AMD GMET: NPT の同等機能
- W^X 強制で MBEC/GMET を活用（カーネルモード execute-only の実現）

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

## 改訂後の要件カバレッジサマリ

| カテゴリ | 要件数 | カバー済み | 新規追加 | 未対応 |
|---------|--------|----------|---------|--------|
| G.1 Boot/Platform | 6 | 6 | 0 | 0 |
| G.2 Logging | 8 | 8 | 0 | 0 |
| G.3 Partition | 13 | 13 | 0 | 0 |
| G.4 CPU Control | 38 | 38 | 0 | 0 |
| G.5 KCI | 3 | 3 | 0 | 0 |
| G.6 KSI | 9 | 9 | 0 | 0 |
| G.7 Key Services | 5 | 5 | 0 | 0 |
| G.8 Update | 6 | 6 | 0 | 0 |
| G.9 FreeBSD | 5 | 5 | 0 | 0 |
| G.10 bhyve/VM | 10 | 10 | 0 | 0 |
| G.11 Quality | 7 | 7 | 0 | 0 |
| G.12 Production | 6 | 6 | 0 | 0 |
| **Appendix D** | — | — | **+4** | 0 |
| **Appendix F** | 6 | 6 | **構造化** | 0 |
| **Appendix I** | — | — | **+4** | 0 |
| **Appendix J** | — | — | **+7** | 0 |
| **ABI/Protocol** | — | — | **+15** | 0 |
| **合計** | 116+ | 116 | +30 | 0 |
