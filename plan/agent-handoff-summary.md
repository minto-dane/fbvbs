# FBVBS エージェント引き継ぎサマリー

**日付:** 2026-03-23
**目的:** FBVBS を全く知らないエージェントセッション向けの完全なプロジェクトコンテキスト。現時点の bare-metal/QEMU 状態と release blocker も含む。

---

## 1. FBVBS とは

FBVBS (Formally-verified Bare-metal Virtual Boot Security) は x86-64 向けの**政府グレードセキュリティハイパーバイザー**。FreeBSD の下で動作し、OS カーネルを VMX non-root に降格させ、OS 自身が回避できないセキュリティ不変条件を強制する。

**主要特性:**
- C11 + ACSL (ANSI/ISO C Specification Language) アノテーション付き
- Frama-C WP は継続運用中。履歴上の高い証明率はあるが、release 判定では現行ワークツリー上での再現と proof gap 確認が必要
- Intel VT-x + EPT + HLAT / AMD-V + NPT 両プラットフォーム対応
- IOMMU (VT-d / AMD-Vi) 必須 (DMA 分離)
- Multiboot2 bare-metal ELF/GRUB ISO/QEMU smoke 経路あり。現在は TCG smoke とローカル KVM smoke の両方で retained-C init まで進み、VMX を expose しない環境では `VMX unavailable` で fail-closed
- ソース 24 ファイル、ヘッダ 6 ファイル、約 25K SLOC

**アーキテクチャ:**
```
+---------------------------------------------------+
|         マイクロハイパーバイザー (C11 + ACSL)        |
|  EPT/NPT | IOMMU | VMCS | 監査ログ | スケジューラ   |
+-----+------+------+------+------+-----------------+
| KCI | KSI  | IKS  | SKS  | UVS  | FreeBSD ホスト  |
|(P4) |(P4)  |(P4)  |(P4)  |(P4)  | (降格済み)       |
+-----+------+------+------+------+-----------------+
```

KCI=カーネルコード完全性, KSI=カーネル状態完全性, IKS=アイデンティティ鍵サービス, SKS=ストレージ鍵サービス, UVS=更新検証サービス。これらの信頼サービス (Phase 4-5) は未実装。

---

## 2. リポジトリ構造

```
/home/nia/opencode/fbvbs/
  README.md
  plan/
    fbvbs-design.md                               -- 設計仕様書 v7 (115 要件定義)
    fbvbs-comprehensive-roadmap-2026-03-20.md      -- マスターロードマップ + REQ追跡
    cpu-sec.md                                     -- CPU セキュリティ設計メモ
    agent-handoff-summary.md                       -- 本ファイル
  hypervisor/
    Makefile                   -- ビルドシステム (analyze, test, cppcheck, fuzz-build, ci 等)
    fbvbs.ld                   -- リンカスクリプト (ガードページ + IST スタック)
    include/
      fbvbs_abi.h              -- ABI 定義、定数、構造体レイアウト
      fbvbs_hypervisor.h       -- 内部状態構造体、関数宣言
      fbvbs_cpu_security.h     -- CPU セキュリティ検出構造体
      fbvbs_leaf_vmx.h         -- VMX リーフ exit 構造体
      fbvbs_asm.h              -- アセンブリ関数スタブ (MSR, VMWRITE 等)
      fbvbs_concurrency.h      -- 並行性プリミティブ
      fbvbs_efi.h              -- UEFI 型定義
    src/  (24 ファイル)
      cpu_security.c           -- CPU 機能検出、脆弱性プロファイリング、緩和策
      vmx.c                    -- VMX プローブ/セットアップ/実行コア
      vmcs_setup.c             -- VMCS フィールド設定 + ホスト降格
      vmx_controls.c           -- CET-SS, MSR ビットマップ, プリエンプションタイマー
      vm_policy.c              -- CR/DR exit ハンドラ、未分類 exit ディスパッチ
      partition.c              -- パーティションライフサイクル、IOMMU ドメイン管理
      command.c                -- 58 hypercall ハンドラ + ディスパッチ
      security.c               -- マニフェスト/ハッシュ/KCI 信頼境界
      memory.c                 -- EPT マップ/アンマップ + ロールバック
      memory_utils.c           -- void* ユーティリティ (WP 除外)
      log.c                    -- 監査ログリングバッファ + CRC32C + レート制限
      kernel.c                 -- ハイパーバイザー初期化 + モデルコード
      boot_multiboot.c         -- Multiboot2 パーサー (アライメント安全)
      iommu_vtd.c              -- Intel VT-d DMAR パーサー + レジスタ制御
      iommu_amdvi.c            -- AMD-Vi IVRS パーサー + レジスタ制御
      hlat.c                   -- Intel HLAT テーブル管理
      amd_npt.c                -- AMD NPT 書込み保護 + フォルトハンドラ
      early_init.c             -- ExitBootServices 後の初期化
      uefi_entry.c             -- UEFI アプリケーションエントリーポイント
      page_alloc.c             -- ビットマップ PFN アロケータ
      watchdog.c               -- VMX プリエンプションタイマーウォッチドッグ
      apic.c                   -- xAPIC/x2APIC 仮想化
      idt.c                    -- IDT 構築 + IST スタック
      mp_init.c                -- MADT/SRAT パーサー + AP 初期化 + TLB シュートダウン
    tests/  (3 テストスイート)
      test_leaf_boundary.c     -- VMX リーフ関数契約テスト
      test_policy_security.c   -- ポリシー/capability テスト
      test_fault_injection.c   -- 17 フォルトインジェクションテスト
    fuzz/  (5 ハーネス)
      fuzz_command_page.c      -- Hypercall ディスパッチファザー
      fuzz_manifest.c          -- マニフェスト/ハッシュファザー
      fuzz_multiboot2.c        -- Multiboot2 パーサーファザー
      fuzz_iommu.c             -- IOMMU DMAR/IVRS パーサーファザー
      fuzz_log_decoder.c       -- 監査ログサブシステムファザー
    compliance/  (11 文書)
      wp_verification_boundary.md        -- Frama-C WP 証明境界
      retained_c_leaf_boundary.md        -- C サブセット保証
      misra_c_deviation_log.md           -- 6 件の MISRA C 逸脱
      covert_channel_analysis.md         -- CC EAL5+ AVA_VAN.5
      device_qualification_matrix.md     -- PCI デバイス適格性 (8 基準)
      performance_budget.md              -- VM exit タイミング分析
      service_failure_impact.md          -- サービス障害影響 (5 シナリオ)
      security_target_outline.md         -- CC ISO 15408 ST 概要
      amd_npt_certification.md           -- AMD NPT 認証テストマトリクス
      incident_response.md               -- P0-P3 インシデント対応手順
      fd_inheritance_residual_risk.md    -- REQ-0505 残余リスク受容
    tools/
      traceability_matrix.py             -- REQ-XXXX ソーススキャナ (115 要件)
  .github/workflows/ci.yml              -- CI/CD パイプライン (6 ゲート)
```

---

## 3. ビルドと検証コマンド

すべてリポジトリルート (`/home/nia/opencode/fbvbs`) から実行:

```bash
# 全 CI パイプライン (全ゲート順次実行)
make -C hypervisor ci

# 個別ゲート:
make -C hypervisor analyze      # GCC -fanalyzer (24 ソース, -Werror)
make -C hypervisor test         # 3 テストスイート
make -C hypervisor cppcheck     # cppcheck 静的解析 (24 ソース)
make -C hypervisor fuzz-build   # 5 ファズハーネスビルド
make -C hypervisor coverage     # gcov ブランチカバレッジ
make -C hypervisor reproducible # 決定論的ビルド検証
make -C hypervisor sbom         # SBOM 生成
make -C hypervisor traceability # REQ トレーサビリティ (115 要件)

# Frama-C WP 証明 (opam 環境が必要)
eval $(opam env --switch=default)
make -C hypervisor frama-c-wp   # 注意: 全ファイル実行には 8GB+ RAM 必要
```

**現在の検証状態 (コミット前にすべて通過必須):**
- GCC -fanalyzer: 24/24 ソース、警告 0
- テスト: 3/3 スイート (leaf boundary, policy security, fault injection=17 テスト)
- cppcheck: 24 ソース、エラー 0
- ファズハーネス: 5/5 ビルド成功
- トレーサビリティ: 115/115 要件がソースにタグ付き
- `make -C hypervisor frama-c-wp`: 実行可能だが proof gap を残す。特に `command.c` typed-cast 境界、RTE guards、public API contract が継続課題

---

## 4. 開発フェーズ状態

| フェーズ | 概要 | 状態 | 備考 |
|---------|------|------|------|
| 0A-0C | マイクロハイパーバイザーコア + IOMMU + ページアロケータ | ほぼ実装済み | fail-closed/PRODUCTION NOTE と proof gap が残る |
| 1 | UEFI ブート, VMCS, IDT, APIC, ウォッチドッグ | ほぼ実装済み | bare-metal bring-up の authoritative 実装は未完 |
| 2 | HLAT, CR ピン留め, CET, MSR ビットマップ, プリエンプションタイマー | ほぼ実装済み | VM exit 緩和列の実動作化が残る |
| 3 | AMD NPT, PTE トラップ, TLB 同期, SEV-SNP | ほぼ実装済み | 実機検証と一部 production path が残る |
| 4-5 | Ada/SPARK 信頼サービス + 暗号 | **ブロック** | GNAT ツールチェーン未導入 |
| 6 | Rust no_std FreeBSD フロントエンド | **ブロック** | Rust ツールチェーン未導入 |
| 7 | bhyve/vmm 統合 | **ブロック** | Phase 6 依存 |
| 8 | マルチソケット (MADT/SRAT/AP/IPI/TLB/NUMA) | 完了 | |
| 9 | 品質保証・リリース準備 | 進行中 | release-hypervisor と QEMU smoke は通るが、proof gap と release blocker の是正が継続中 |

**ブロック中のフェーズは外部ツールチェーン/アーキテクチャ決定が必要。** retained C マイクロハイパーバイザー基盤はかなり進んでいるが、production release 完了とはみなさないこと。

---

## 5. 主要技術詳細

### 5.1 Frama-C WP 検証

履歴上は 9 ファイルで高い WP 証明率に到達しているが、現行 release 判定では再現実行と proof gap 確認を必須とする:
- cpu_security.c, vmx.c, memory.c, log.c, vm_policy.c, kernel.c, command.c, security.c, partition.c
- `-wp-model Typed+Cast` 使用 (クロスタイプキャスト対応)
- `memory_utils.c` と `boot_multiboot.c` は除外 (void* が Typed モデルと非互換)
- 13 プラットフォーム/ハードウェアファイルは除外 (MMIO, MSR, VMCS, CPUID)
- 現在の主な proof gap は `command.c` typed-cast 境界、Missing RTE guards、一部 timeout
- `#ifdef __FRAMAC__` モデルコードが asm スピンロックと GPA 解決を置換

### 5.2 セキュリティアーキテクチャ

- **パーティション分離**: EPT/NPT パーティション毎、IOMMU ドメインはデバイス割当毎
- **CR ピン留め**: CR0 (WP, NE, PG), CR4 (SMEP, SMAP, UMIP, DE, FSGSBASE, CET) を強制
- **CPU 緩和策**: IBPB は毎 exit、VERW (条件付き)、L1D_FLUSH (パーティション間)、RSB 充填
- **デバッグレジスタ**: vCPU 毎シャドウ状態、DR6/DR7 サニタイズ、DR0-3 保存時ゼロ化
- **ウォッチドッグ**: VMX プリエンプションタイマー、連続 10 回タイマー exit → fault
- **監査ログ**: デュアルパス (一次 UART + ミラー EPT 読取専用)、CRC32C、レート制限
- **トゥームストーンパーティション**: 破棄スロットは再利用しない (単調増加 ID)
- **TOCTOU 防止**: コマンドページフィールドを1回キャッシュ (call_id, input_length, flags, output_gpa, caller_sequence, caller_nonce)
- **Fail-closed**: すべてのエラーパスは許可ではなく拒否/fault

### 5.3 要件

115 要件 (REQ-0001 ～ REQ-0909, REQ-1000 ～ REQ-1105) が `plan/fbvbs-design.md` に定義。
すべてソースファイル参照あり。`tools/traceability_matrix.py` で追跡。

### 5.4 重要な不変条件

- `FBVBS_MAX_PARTITIONS = 16U` (スロット 0 = ホスト、1-15 = VM)
- `FBVBS_PAGE_SIZE = 4096U`
- パーティション作成要件: `memory_limit_bytes >= PAGE_SIZE * (vcpu_count + 1)`
- パーティション fault 許可元: RUNNING, RUNNABLE, LOADED, QUIESCED
- fault パーティションの自動再起動なし (VM_DESTROY + VM_CREATE が必要)
- VPID 0 は予約 (1 から開始、0xFFFF で飽和)
- IOMMU ドメイン ID 0 は予約 (番兵値)、単調増加で再利用しない

---

## 6. コンプライアンス文書

`hypervisor/compliance/` 内の 11 文書:
1. **wp_verification_boundary.md** -- 形式証明範囲 vs 実行時チェック範囲
2. **retained_c_leaf_boundary.md** -- C サブセット保証
3. **misra_c_deviation_log.md** -- 6 件の正当化された MISRA C 逸脱
4. **covert_channel_analysis.md** -- CC EAL5+ AVA_VAN.5 方法論
5. **device_qualification_matrix.md** -- PCI デバイス適格性 8 基準
6. **performance_budget.md** -- VM exit タイミング、禁止操作
7. **service_failure_impact.md** -- 5 信頼サービス障害シナリオ
8. **security_target_outline.md** -- Common Criteria ISO 15408 ST
9. **amd_npt_certification.md** -- AMD NPT 認証テストマトリクス
10. **incident_response.md** -- P0-P3 重要度、復旧手順
11. **fd_inheritance_residual_risk.md** -- REQ-0505 残余リスク受容

---

## 7. 残作業 (ブロック項目)

すべて外部ツールチェーン/アーキテクチャ決定が必要:

1. **Phase 4-5 (Ada/SPARK 信頼サービス)**: KCI, KSI, IKS, SKS, UVS パーティション。GNAT/GNATprove ツールチェーンと Ada/SPARK 専門知識が必要。

2. **Phase 5 (暗号)**: Ed25519 署名検証、HMAC-SHA-256 ログ完全性、HKDF 鍵導出。FIPS 認定暗号ライブラリの選定・統合が必要。

3. **Phase 6 (Rust FreeBSD フロントエンド)**: FreeBSD とハイパーバイザー間の非信頼 ABI 変換層。Rust no_std ツールチェーンと FreeBSD カーネルモジュール開発が必要。

4. **Phase 7 (bhyve 統合)**: FreeBSD の bhyve(4) ハイパーバイザーフレームワークとの統合。Phase 6 依存。

5. **ハードウェアテスト**: 形式検証とテストはすべて VT-x/AMD-V なしの開発マシンで実行。本番テストには Intel Ice Lake+ または AMD Zen 2+ ハードウェア (IOMMU 搭載) が必要。

---

## 8. ユーザー作業スタイル

- **言語**: ユーザーは日本語でコミュニケーション。コード/技術文書は英語、要件記述は日本語
- **自律性**: 確認を求めず自律的に作業すること — 「確認を聞かずに何時間かけてもいいので」
- **徹底性**: 「重要度に関わらずすべての発見事項を修正せよ — クリティカルシステムではすべてのリスクを排除すべき」
- **検証**: 変更バッチごとに完全検証スイート (analyze, test, cppcheck, fuzz-build) を実行
- **セキュリティレビュー**: 定期的な徹底的クロスファイルセキュリティレビュー。すべての発見事項を修正してから次へ進む

---

## 9. よくある落とし穴

1. **`fuzz/*.c` を C ブロックコメント内で使用** → `-Wcomment -Werror` でビルド失敗。`fuzz/ harnesses` と書くこと。
2. **Frama-C WP フル実行** は 8GB+ RAM 必要。制約環境ではファイル単位で実行。
3. **トゥームストーンパーティション**: `FBVBS_MAX_PARTITIONS - 1` が最大 create/destroy サイクル数 (スロット再利用なし)。
4. **`memory_limit_bytes`**: パーティション作成時 `>= PAGE_SIZE * (vcpu_count + 1)` 必須。
5. **VMCS ページクリーンアップ**: エラーパスでは必ず確保ページを解放 (goto cleanup パターン)。
6. **VPID 割当**: BSP のみ、並行アクセスなし。原因なくロックを追加しないこと。
7. **DR レジスタマスク**: DR6 予約ビットは 1 (0xFFFF8FF0)、DR7 bit 10 は 1 (0x400)。
8. **リポジトリルートからビルド**: `make -C hypervisor <target>` を使用。`cd hypervisor && make` ではない。
9. **IOMMU ドメイン ID**: 単調増加、wrap 時は RESOURCE_EXHAUSTED で拒否 (再利用禁止)。

---

## 10. セキュリティ強化履歴

7 回のクロスファイルセキュリティレビューを完了。主な修正:
- VMCS ページリーク修正 (CWE-401): goto cleanup パターン
- TOCTOU 防止: コマンドページ 6 フィールドをキャッシュ (call_id, input_length, flags, output_gpa, caller_sequence, caller_nonce)
- CR シャドウ同期修正: ピンマスク==0 でもシャドウ更新
- クロスページマニフェスト偽造防止: ページ境界チェック追加
- IOMMU ドメイン ID 再利用防止: monotonic ID に統一
- デバイス割当監査ログ修正: 正しいイベントコード使用
- 定数時間操作: ハッシュ比較, memory_is_zero, constant_time_equals
- EPT トランザクショナルロールバック: 部分マッピング失敗時の完全復旧
- ウォッチドッグ TOCTOU: partition_fault 戻り値チェック
- file_offset + size オーバーフロー防止
- measurement_epoch 飽和チェック
