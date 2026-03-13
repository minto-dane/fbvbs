# FBVBS v7 開発計画

## 概要

FBVBS v7 の完全実装に向けた9フェーズの開発計画。各フェーズは依存関係と検証順序に従い、最終実装へ直接収束する。

## アーキテクチャ

```
┌─────────────────────────────────────────────────────────────┐
│                    FBVBS v7 システム                         │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: ゲスト仮想マシン群                                  │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: FreeBSD ホスト（deprivileged）                      │
│    ├── fbvbs.ko（Rust、非信頼 ABI 変換層）                    │
│    ├── vmm.ko 互換層                                         │
│    └── bhyve ユーザーランド                                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: 信頼サービスパーティション（Ada/SPARK）              │
│    ├── Kernel Code Integrity Service (KCI)                   │
│    ├── Kernel State Integrity Service (KSI)                  │
│    ├── Identity Key Service (IKS)                            │
│    ├── Storage Key Service (SKS)                             │
│    └── Update Verification Service (UVS)                     │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: マイクロハイパーバイザー（C11 + Frama-C WP）         │
│    ├── パーティション管理                                     │
│    ├── 第二レベルページング                                   │
│    ├── IOMMU ドメイン制御                                    │
│    ├── CPU 制御強制                                          │
│    └── 一次監査ログ                                           │
└─────────────────────────────────────────────────────────────┘
```

## フェーズ定義

### Phase 0: マイクロハイパーバイザー基盤（完了）

**目標:** FreeBSD を deprivileged host として起動し、最低1つの信頼サービスパーティションを稼働させる。

**成果物:**
- C11 + Frama-C WP マイクロハイパーバイザー: パーティション管理、第二レベルページング、IPC、VMCALL ハンドリング、一次監査ログ（UART）
- Intel VT-x 対応（AMD は Phase 4）
- 最小限のブートシーケンス: UEFI → マイクロハイパーバイザー → 空の信頼サービスパーティション → FreeBSD パーティション
- FreeBSD が VMX non-root で正常起動することの実証

**検証:**
- FreeBSD が信頼サービスパーティションのメモリにアクセスできないことの実証
- IPC ラウンドトリップ時間の計測
- Frama-C WP によるパーティション管理ロジックの実行時例外不在証明

**状態:** ✅ 完了（1599/1599 証明目標達成）

---

### Phase 1: 信頼サービスパーティション構築

**目標:** Ada/SPARK による信頼サービスパーティションイメージの構築。

**成果物:**
- Ada 2022 + SPARK 2014 による信頼サービスパーティション基盤
- GNATprove による実行時例外不在証明
- パーティション間 IPC 通信ライブラリ
- 共有コマンドページ操作ライブラリ

**検証:**
- GNATprove による全関数の実行時例外不在証明
- パーティション間メモリ分離の実証
- IPC ラウンドトリップ時間の計測

---

### Phase 2: ベアメタルブートパス

**目標:** UEFI → マイクロハイパーバイザー → 信頼サービス → FreeBSD の完全ブートチェーン。

**成果物:**
- UEFI Secure Boot 統合
- マイクロハイパーバイザーイメージ検証
- 信頼サービスパーティション自動起動
- FreeBSD パーティション起動

**検証:**
- ブートチェーン全体の測定値検証
- ロールバック攻撃検出の実証
- 一次監査ログ経路の動作確認

---

### Phase 3: FreeBSD フロントエンド fbvbs.ko

**目標:** Rust による非信頼 ABI 変換層の実装。

**成果物:**
- Rust `no_std` + `panic=abort` による fbvbs.ko
- VMCALL ラッパー
- KLD ロードフック
- execve/setuid 検証フック
- Jail/MAC/Capsicum 統合フック

**検証:**
- fbvbs.ko 侵害時の影響範囲テスト
- 全フックの動作確認
- Fuzzing キャンペーン

---

### Phase 4: vmm.ko 互換層と bhyve 統合

**目標:** 既存 bhyve ユーザーランドの再利用。

**成果物:**
- vmm.ko 互換層（VM_CREATE, VM_DESTROY, VM_RUN 等）
- VM exit ルーティング（ファストパス/スローパス）
- guest memory 所有権モデル
- IOMMU ドメイン管理

**検証:**
- bhyve VM の正常起動・動作
- VM エスケープ時の信頼サービスメモリ保護
- passthrough デバイスの DMA 分離

---

### Phase 5: 暗号ライブラリ統合

**目標:** Identity Key Service と Storage Key Service の暗号操作実装。

**成果物:**
- Ada/SPARK 暗号 primitive 統合
- 外部ライブラリ隔離利用方針
- 鍵ライフサイクル管理
- レート制限とアクセスログ

**検証:**
- 鍵素材の非抽出性実証
- 暗号操作の定数時間性計測
- レート制限機能確認

---

### Phase 6: 更新検証パイプライン

**目標:** Update Verification Service の完全実装。

**成果物:**
- 署名付きマニフェスト検証
- ロールバック防止（TPM NV または version store）
- freshness/freeze 攻撃検出
- A/B パーティショニング

**検証:**
- ロールバック攻撃検出実証
- 署名不正成果物の拒否確認
- 更新失敗時のフォールバック動作

---

### Phase 7: Intel 翻訳整合性（HLAT + IOMMU）

**目標:** Intel HLAT によるカーネルコード領域の翻訳整合性。

**成果物:**
- HLAT 統合
- カーネルテキスト領域の翻訳整合性保護
- IOMMU ドメイン管理強化

**検証:**
- HLAT 有効時の PFN スワップ攻撃防止
- マルチコア競合テスト

---

### Phase 8: AMD 翻訳整合性

**目標:** AMD NPT + 複合機構による同等のセキュリティ目標達成。

**成果物:**
- NPT write-protect
- ページテーブル更新トラップ
- シャドウ翻訳経路
- TLB 無効化監視
- SEV-SNP 補助機構（オプション）

**検証:**
- PFN 差替え攻撃防止実証
- PTE 改ざん検出実証
- TLB invalidate race テスト
- マルチコア更新競合テスト

---

### Phase 9: 品質保証とリリース

**目標:** 本番宣言に必要な品質基準達成。

**成果物:**
- 全 hypercall パーサの継続的 Fuzzing
- 中核分岐の MC/DC カバレッジ達成
- 再現可能ビルド + SBOM + 署名付き provenance
- 独立セキュリティ監査

**検証:**
- 全テストスイート実行
- カバレッジ目標達成確認
- セキュリティ監査完了

---

## 依存関係グラフ

```
Phase 0 (完了)
    │
    ├──→ Phase 1 (信頼サービス基盤)
    │         │
    │         ├──→ Phase 3 (fbvbs.ko)
    │         │         │
    │         │         └──→ Phase 4 (bhyve 統合)
    │         │
    │         ├──→ Phase 5 (暗号ライブラリ)
    │         │
    │         └──→ Phase 6 (更新検証)
    │
    ├──→ Phase 2 (ブートパス)
    │
    ├──→ Phase 7 (Intel HLAT)
    │
    ├──→ Phase 8 (AMD 翻訳整合性)
    │
    └──→ Phase 9 (品質保証)
```

## ファイル構成計画

```
fbvbs/
├── hypervisor/
│   ├── src/                    # C11 + Frama-C WP（現在）
│   ├── include/                # ヘッダファイル
│   ├── tests/                  # テスト
│   └── compliance/             # コンプライアンス文書
├── trusted-services/           # Ada/SPARK 信頼サービス（新規）
│   ├── common/                 # 共通ライブラリ
│   ├── kci/                    # Kernel Code Integrity Service
│   ├── ksi/                    # Kernel State Integrity Service
│   ├── iks/                    # Identity Key Service
│   ├── sks/                    # Storage Key Service
│   └── uvs/                    # Update Verification Service
├── fbvbs-frontend/             # Rust fbvbs.ko（新規）
│   ├── src/
│   └── tests/
├── vmm-compat/                 # vmm.ko 互換層（新規）
│   ├── src/
│   └── tests/
├── plan/                       # 計画文書
│   ├── fbvbs-design.md         # FBVBS v7 仕様書
│   └── development-plan.md     # このファイル
└── README.md
```

## 次のステップ

1. Phase 1 の詳細設計と実装開始
2. Ada/SPARK 信頼サービスパーティション基盤の構築
3. GNATprove 証明環境の整備
4. パーティション間 IPC ライブラリの実装
