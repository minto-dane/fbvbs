# FBVBS: FreeBSD Virtualization-Based Security
## Architecture, Requirements, and Assurance Specification

> **対象 OS:** FreeBSD 15 系フォーク  
> **対象 CPU:** x86_64  
> **主対象環境:** サーバー、データセンター、高信頼ワークステーション  
> **文書種別:** 要求仕様書 · 設計仕様書 · 実装契約書 · 検証要求書  
> **日付:** 2026-03

---

## Document Map

| Part | Sections | Focus |
|------|----------|-------|
| **Abstract** | — | 設計思想、従来案からの修正 |
| **I. Scope & Conventions** | §1–4 | 規範用語、適合性水準、トレーサビリティ |
| **II. Security Model** | §5–8 | 五つの中核保護性質、限界、脅威モデル |
| **III. Architecture** | §9–11 | マルチサーバー、deprivileged host |
| **IV. Boot & Logging** | §12–15 | OOB 一次監査、ミラーログ |
| **V. Microhypervisor** | §16–21 | TCB、SPARK、状態機械、ABI |
| **VI. Translation Integrity** | §22–25 | Intel HLAT 必須、AMD 複合経路 |
| **VII. Trusted Services** | §26–30 | KCI · KSI · IKS · SKS · UVS |
| **VIII. FreeBSD Integration** | §31–32 | 非信頼フロントエンド |
| **IX. bhyve Integration** | §33–38 | 制御/実行プレーン分離 |
| **X. Update Model** | §39–40 | 搬送手段非依存、署名階層 |
| **XI. Quality** | §41–45 | MC/DC、fuzzing、supply chain |
| **XII. Platform Positioning** | §46–47 | Windows VBS 比較 |
| **XIII. Perf & Risk** | §48–50 | パフォーマンス、残余リスク |
| **XIV. Conclusion** | — | 退けた近道の明示 |

| Appendix | Content |
|----------|---------|
| **A** | 旧略称→説明的名称の対応 |
| **B** | 業界標準略語の定義 |
| **C** | ログレコード構造（frozen） |
| **D** | 共有コマンドページ構造（frozen） |
| **E** | 本仕様の自己検証 |
| **F** | 本番前立証課題 |
| **G** | 要件カタログ（FBVBS-REQ-0001〜1105） |
| **H** | FreeBSD 構造体保護カタログ |
| **I** | サービス障害影響マトリクス |
| **J** | パフォーマンスバジェット |
| **K** | 実装ロードマップ |
| **L** | Hypercall ABI カタログ（frozen） |

---
---

# Abstract

本書は、FreeBSD カーネルが侵害された後でも、いくつかの中核的なセキュリティ不変条件を維持することを目的とした仮想化ベースの保護基盤 FBVBS の完全仕様である。ここでいう「完全仕様」とは、単なる構想説明ではなく、実装者、監査者、運用者、ならびに自動実装エージェントが、同一の設計判断、同一の責務分担、同一の保証境界、同一の検証要求に基づいて作業できる水準の文書を意味する。本書は、そのために必要な要求定義、脅威モデル、アーキテクチャ、コンポーネント境界、更新機構、監査機構、仮想化統合、暗号方針、品質基準、および残余リスクを、相互に矛盾しない形で定義する。

FBVBS は、FreeBSD に既に存在する Capsicum、Jail、MAC Framework、securelevel といった機構を「そのまま別のセキュアカーネルに移植する」ものではない。むしろ、FreeBSD を意図的に非信頼ホストとして扱い、最上位特権を持つ最小のマイクロハイパーバイザーが、コード整合性、カーネル重要状態、鍵素材、DMA 境界、および監査証跡を、FreeBSD の権限から切り離して保持する。その意味で FBVBS は、FreeBSD 自体を守る設計ではなく、FreeBSD 侵害後にも残るべき保護性質を、より狭い信頼境界の内側で維持する設計である。

> **従来案からの四つの修正:**
>
> 1. **ログ:** UART のみの議論は不十分 → OOB 一次監査ログとミラーログを明確に分離
> 2. **HLAT:** 任意機能扱いは矛盾 → Intel では HLAT 必須、AMD は複合経路で同等目標
> 3. **更新:** `freebsd-update` 固定 → 搬送手段非依存の署名付き成果物モデル
> 4. **暗号:** Ada/SPARK 完結の前提 → 現実的な primitive 優先評価 + 外部隔離方針

また本書は、設計そのものと同じだけ、品質保証と検証の構造を重視する。高保証という言葉を、単に Ada/SPARK を採用したという事実だけに還元してはならない。要求からコード、証明、試験、カバレッジ、供給網、リリース成果物に至るまでの証拠構造が存在して初めて、高保証と呼ぶに値する。本書はそのための最低限の規律を明文化する。

---
---

# Part I. Scope, Intent, and Document Conventions

> *本パートは、文書全体の読み方、規範用語、適合性水準、要件管理の枠組みを定義する。実装者はまずここで「必須」「推奨」「禁止」の意味を確認すること。*

## §1. Purpose of this Document

本書の目的は、FBVBS を「実装可能であり、監査可能であり、将来的に認証対応も可能な設計仕様」として定義することである。従来の設計メモは、思想や方向性を示すには有用であったが、実装契約としては粗く、さらにいくつかの主要な点で、強い主張と実際の限界が十分に整合していなかった。たとえば、「FreeBSD カーネルが完全に侵害されてもセキュリティ機能が破壊されない」という表現は、保護不能であると既に認めているファイルディスクリプタテーブル、ソケット状態、平文処理データ、意味論的な正規コードパス悪用といった領域と衝突する。そのため本書では、保護対象を「中核不変条件」に限定し、それぞれについて必要な機構、前提条件、信頼境界、失敗条件、残余リスクを明示する。

本書は、読者として、人間の設計者だけでなく、自動コード生成エージェントも想定している。このため、アーキテクチャの説明は抽象的な理念に留めず、パーティション状態、メモリ所有権、更新成果物の形式、ハイパーコール ABI の原則、ログ記録形式、仮想マシン統合境界、テスト義務といった、実装に必要な拘束条件まで定義する。

## §2. Normative Language

本書では、要件の強さを明確に区別するため、以下の語を用いる。

| 語 | 意味 |
|---|---|
| **必須** | 実装適合の条件。満たされなければ FBVBS v7 準拠を主張してはならない |
| **推奨** | 高保証性や運用安全性の観点から強く望ましいが、代替根拠があれば例外可 |
| **任意** | 存在してもよい拡張。本書の保証主張には自動的には含まれない |
| **禁止** | たとえ実装可能でも、保証境界や将来監査を著しく損ねるため採用不可 |
| **非目標** | 本設計の意図的な適用外 |

### §2.1. Conformance Profiles

| プロファイル | 内容 |
|---|---|
| **基本適合構成** | CPU ベンダごとの翻訳整合性要件、IOMMU 有効化、OOB 一次監査経路を含む必須要件を満たす構成 |
| **高保証構成** | 基本適合構成 + 起動時検証、測定、関連する立証・監査要件 |
| **高保証運用プロファイル** | 高保証構成 + HSM、複数人承認、証跡保全、成果物配布統制、緊急失効手順 |

### §2.2. Requirements Identification and Traceability

要求は `FBVBS-REQ-XXXX` 形式の ID を持つ。各 ID は少なくとも以下を持つ:

- 要求本文、要求種別（`security` / `functional` / `interface` / `update` / `quality` / `operational`）
- 根拠節、実装対象コンポーネント
- 検証方法（primary class: `analysis` / `test` / `proof` / `inspection` / `operational drill`）
- 関連試験識別子、関連証拠識別子、状態

**正規化規則:** `* test`→`test`、`fault injection`→`test`、`fuzzing`→`test`、`* campaign`→`test`、`* analysis`→`analysis`、`* inspection`→`inspection`、`* review` / `* audit`→`inspection`、`proof artifact review`→`proof`、`operational *`→`operational drill`。

本文中の叙述的説明はそのままでは要求とはみなさない。トレーサビリティに入るのは、requirements ID が付与された要求、または固定 ABI 等の凍結規範付録のみ。

## §3. Audience and Use

対象読者: マイクロハイパーバイザー実装者、FreeBSD フロントエンド実装者、信頼サービス実装者、`bhyve` 統合担当者、更新・鍵管理担当者、セキュリティレビュー担当者、AI エージェント監督者。

## §4. Terminology and Naming Discipline

| 旧略称 | 本書での説明的名称 |
|--------|-------------------|
| HEKI | Kernel Code Integrity Service |
| KDP | Kernel State Integrity Service |
| IKV | Identity Key Service |
| DKV | Storage Key Service |

> **用語規律:**
> - 「TCB」は常に「ある保護性質を成立させるために信頼しなければならない最小構成要素」を意味し、固定の全体 TCB を意味しない
> - 「保証」は定義済み前提条件の下での特定不変条件の維持に限定して用いる

---
---

# Part II. Security Objectives, Non-Objectives, and Threat Model

> *本パートは、FBVBS が何を守り、何を守らないかを定義する。五つの中核保護性質、明示的な限界、脅威モデル、信頼の前提が含まれる。*

## §5. Security Objectives — 五つの中核保護性質

| # | 性質 | 意味 |
|---|------|------|
| 1 | **パーティション間メモリ分離** | FreeBSD と各信頼サービス、ゲスト VM 同士が他方のメモリに CPU または DMA で到達できない |
| 2 | **カーネルコード整合性** | カーネルコードおよび許可モジュールのコードページが攻撃者により書き換えられない |
| 3 | **カーネル重要状態整合性** | `securelevel`、Jail 制約、MAC 状態、ucred、主要関数テーブル等が定義済み経路を経ずに改ざんされない |
| 4 | **秘密鍵の非抽出性** | TLS/SSH/IPsec 等の高価値鍵が FreeBSD メモリ空間から読み出され得ない |
| 5 | **監査証跡完全性** | 少なくとも一つの監査チャネルが FreeBSD 制御外で観測可能であり、改ざん不可 |

これら五つは互いに独立ではない。コード整合性が崩れれば攻撃面が増え、ログ完全性がなければ違反が隠蔽され、鍵非抽出性が崩れれば認証基盤が破綻する。

## §6. Non-Objectives and Explicit Limits

> **明示的に守らないもの:**
>
> - **平文データの完全保護** — マウント後の平文は FreeBSD 経由でアクセス可能
> - **可用性** — 侵害後の DoS は防がない。守るのは境界と監査証跡
> - **意味論的悪用の完全防止** — 署名済みだが脆弱な `setuid` バイナリ経由の権限昇格等は緩和対象であっても完全境界ではない

## §7. Threat Model

**対象とする攻撃者:** FreeBSD カーネルへの任意コード実行、または同等権限での任意メモリ読書きが可能。カーネルモジュール挿入、コードページ書換え、ucred/Jail/MAC/sysent/vop_vector/cdevsw 改ざん、Thunderbolt/USB4/PCI passthrough 経由 DMA、ゲスト VM からのホスト横移動を含む。

**対象外:** SMM、悪意ある CPU マイクロコード、完全物理侵入、電圧/クロックグリッチ、破壊的プロービング。

## §8. Trust Assumptions

適合を主張する構成では:

- **IOMMU** が存在し有効化されていなければならない
- **一次監査ログ経路**（BMC/SOL/UART/専用ロガー）が構成され有効でなければならない

高保証構成ではさらに:

- UEFI Secure Boot 等の起動時検証
- TPM 2.0 等による測定
- 一次監査ログ経路の運用成立性の立証

---
---

# Part III. Overall Architecture

> *本パートは、FBVBS のマルチサーバー構造と deprivileged host の意味を定義する。*

## §9. Architectural Thesis

FBVBS の設計思想は、モノリシックなセキュアカーネルをもう一つ導入することではない。仮にすべての保護機能を単一の大規模特権コンポーネントへ集約すれば、そのコンポーネントの欠陥がすべての保護性質を同時に無効化しうるため、保護対象面積の縮小という目的は達成されない。したがって本設計では、最上位特権に置く要素を、メモリ分離、CPU 遷移、IOMMU 制御、起動検証、一次監査ログ生成という最小の強制機構に限定し、ポリシー判断、鍵処理、更新判断は、それぞれ独立した信頼サービスへ分離する。

FreeBSD は、この構造の中で二つの重要な役割を持つ。一つは、既存アプリケーション互換性を維持するための汎用 OS としての役割であり、もう一つは、`bhyve` を含む制御プレーン、管理プレーン、デバイスモデル実装のホストとしての役割である。しかし、FreeBSD は保護対象そのものではなく、主要な保護性質に関して保護境界の外側に位置する。FreeBSD はシステム管理を行うが、最終的な書込み許可権、マッピング許可権、鍵読出権、DMA 許可権を持たない。

## §10. Logical Component Structure

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Microhypervisor (VMX root / SVM host)                 │
│  最上位特権。メモリ分離・IPC・IOMMU・ログ・起動検証のみ          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Trusted Service Partitions (各々独立 VMCS+EPT/NPT)    │
│  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐                     │
│  │ KCI │ │ KSI │ │ IKS │ │ SKS │ │ UVS │                     │
│  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘                     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: FreeBSD Host (deprivileged, 非信頼)                    │
│  カーネル + bhyve + fbvbs.ko + ユーザーランド                    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Guest VM Partitions (bhyve 管理、動的)                 │
└─────────────────────────────────────────────────────────────────┘
```

**五つの信頼サービス:**

| Service | ABI Identity | 責務 |
|---------|-------------|------|
| Kernel Code Integrity Service | `SERVICE_KIND_KCI` | コードページ W^X、モジュール署名、翻訳整合性確認 |
| Kernel State Integrity Service | `SERVICE_KIND_KSI` | 重要データ構造の更新制御、setuid 検証 |
| Identity Key Service | `SERVICE_KIND_IKS` | 身元鍵の import/署名/鍵交換 |
| Storage Key Service | `SERVICE_KIND_SKS` | ディスク鍵・アンロック素材の隔離 |
| Update Verification Service | `SERVICE_KIND_UVS` | 成果物・マニフェストの真正性検証 |

ABI v1 では Audit Relay Service は service kind に含めず、内部拡張として扱う。`DIAG_GET_PARTITION_LIST` では列挙しない。

## §11. Why the Host Must Be Deprivileged

FreeBSD を非信頼とする設計は、保護境界の一貫性を維持するための前提である。もし FreeBSD が鍵サービスのメモリを読み取ることができ、更新機構の承認者であり、同時にログ機構の唯一の観測者でもあるなら、攻撃者が FreeBSD を奪取した時点で FBVBS の設計目的は失われる。

> **FreeBSD に残す権限の限定:**
> - パーティション生成を**要求**できるが、第二レベルページテーブルを**自由に変更**してはならない
> - ログミラーを**読める**が、一次監査ログを**書き換え**てはならない
> - 鍵操作を**要求**できるが、鍵素材を**受け取っ**てはならない

---
---

# Part IV. Boot, Measurement, and Logging

> *本パートは、起動連鎖、OOB 一次監査ログ、FreeBSD ミラーログの分離を定義する。*

## §12. Boot Sequence and Root of Trust

FreeBSD が先に VMX root / SVM ホスト側仮想化制御権を取得する構成は、本設計と両立しない。正しい順序:

```
UEFI firmware
  → マイクロハイパーバイザーイメージの検証・ロード
    → 自身のコード、静的データ、マニフェストの測定
      → 信頼サービスイメージの検証・許可
        → FreeBSD パーティションの起動
```

ABI v1 では、autostart trusted-service partition の `service_kind`, `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp`, `autostart` は manifest から決定され、実装依存の既定値に委ねてはならない。

**ロールバック防止:** 各成果物に単調増加世代番号を持たせ、TPM NV 領域等の version store でロールバックを検出。

## §13. Authoritative Out-of-Band Logging

> **ログチャネルの分離（最重要設計判断の一つ）:**
>
> | チャネル | 性質 | 観測手段 |
> |---------|------|---------|
> | **一次監査ログ（OOB）** | FreeBSD 侵害時にも観測・保全可能 | UART / BMC host serial / IPMI SOL / 専用ロガー |
> | **ミラーログ（in-band）** | FreeBSD から読めるが改ざん耐性なし | 共有リングバッファ → `fbvbslogd` / カーネルラッパー |

「常にシリアルから取得できる」とは記述してはならない。物理 UART が露出せず BMC もない環境では成立しない。

**レコード形式:** テキストではなく構造化バイナリ。各レコードは sequence, boot ID, CPU ID, source component, severity, event code, payload length, payload, CRC32C を含む。帯域制限のため固定長/上限付き可変長とする。CRC32C 単独では改ざん耐性を与えない。

## §14. In-Band Mirror Logging for FreeBSD

マイクロハイパーバイザーが読み取り専用の共有リングバッファを FreeBSD に公開する。FreeBSD 側からの書込みは第二レベルページングで物理的に拒否。ミラーは「non-authoritative mirror」であり、監査証跡の唯一の根拠としては用いない。

リングバッファ構造は Appendix C.1 で凍結。

## §15. Early Boot and Panic-Time Caveats

「early boot と panic でもログは常に完全に記録される」と主張してはならない。これらは best effort であり、高保証構成では各段階で同一の OOB 観測チェーンが構成されていることを要求する。

---
---

# Part V. Microhypervisor Design

> *本パートは、マイクロハイパーバイザーの責務範囲、実装言語、パーティション状態機械、ケイパビリティモデル、hypercall ABI を定義する。*

## §16. Scope of the Microhypervisor

**責務（含むもの）:** パーティション生成/破棄、CPU 状態遷移、第二レベルページング管理、IOMMU ドメイン制御、CPU 制御ビット/MSR 強制、起動検証、一次監査ログ生成。

**責務外（含まないもの）:** 暗号高水準ポリシー、鍵ライフサイクル、ファイルシステム解釈、署名ポリシー意味論、デバイス個別挙動、bhyve デバイスモデル。

Kernel State Integrity Service が異常停止しても、既に設定済みの read-only 保護はマイクロハイパーバイザーが維持できる。新規変更機能は停止しうるが、既存保護の一斉喪失は回避される。

## §17. Implementation Language and Proof Boundary

FBVBS の一次実装経路は **Ada 2022 / SPARK 2014** とする。暫定フェーズ専用コードや使い捨て骨組みは適合経路として認めない。

| 区分 | 言語 | 証明対象 |
|------|------|---------|
| マイクロ HV コア | SPARK | 証明対象（AoRTE 以上） |
| VMX/SVM 命令ラッパー | アセンブリ | 証明対象外（手動監査） |
| FreeBSD フロントエンド | Rust | 証明対象外 |
| 例外的 C コード | C (MISRA C:2023 + CERT C) | 証明対象外（静的解析/証明系で UB 不在立証必須） |

## §18. Partition Model and State Machine

パーティションの状態と属性:

- 識別子、所有メモリ集合、第二レベルページング構造、CPU 実行状態
- 受信/送信可能メッセージポート集合、リソース上限、ブート測定値、現在状態

### §18.1. Legal Partition Transitions

| 現在状態 | トリガ | 次状態 | 必須条件 |
|---|---|---|---|
| — | `PARTITION_CREATE` / `VM_CREATE` | Created | 資源確保成功 |
| Created | `PARTITION_MEASURE` | Measured | 成果物検証済み |
| Measured | `PARTITION_LOAD_IMAGE` | Loaded | メモリ確保成功 |
| Loaded | `PARTITION_START` | Runnable | 初期 CPU 状態構築成功 |
| Runnable | スケジューラ選択 | Running | vCPU 割当可能 |
| Running/Runnable | `PARTITION_QUIESCE` | Quiesced | vCPU 停止成功 |
| Quiesced | `PARTITION_RESUME` | Runnable | 中断条件消滅 |
| Running/Runnable/Quiesced | 致命障害 | Faulted | 一次監査ログ必須 |
| Faulted | `PARTITION_RECOVER` | Runnable | 再測定+ゼロ化+復元成功 |
| 全状態 | `PARTITION_DESTROY` | Destroyed | ゼロ化+資源回収 |

表にない遷移 → `INVALID_STATE`。Destroyed は終端。`PARTITION_KIND_GUEST_VM` には `VM_DESTROY` のみ許可。

**初期 CPU 状態（凍結）:** `RFLAGS=0x2`, `CR0=0x80010033`, `CR4=0x6f0`, flat 64-bit model, `RSI`=bootstrap page GPA。

## §19. Capability and Ownership Model

- パーティション自身は capability を生成・拡張してはならない
- あるページが二つの信頼サービスの可変領域であってはならない
- FreeBSD との共有は読取専用ミラーか一時 I/O バッファに限定
- 鍵サービスの内部ページを FreeBSD が直接マップすることは禁止

## §20. Hypercall ABI Principles

### §20.1. Trap and Register Convention

| レジスタ | 呼出時 | 復帰時 |
|---|---|---|
| `RAX` | command page GPA（4096 アラインメント） | `status_code` |
| `RBX` | 0（非ゼロ→`INVALID_PARAMETER`） | `command_state` |
| `RCX` | 0 | `actual_output_length` |
| `RDX` | 0 | 0 |

### §20.2. Command Page State Machine

| 状態 | 値 | 意味 |
|------|---|------|
| EMPTY | 0 | 未使用/再初期化済み |
| READY | 1 | 要求書込み完了、trap 可能 |
| EXECUTING | 2 | HV 受理・処理中 |
| COMPLETED | 3 | 正常完了 |
| FAILED | 4 | エラー終了 |

EXECUTING 中の再 trap → `RESOURCE_BUSY`。

### §20.3. Caller Identity, Sequence, Nonce

- caller partition ID と RIP はマイクロ HV が観測した値が正（caller 申告値は信頼しない）
- `caller_sequence` は vCPU ごとに単調増加、後退/再利用 → `REPLAY_DETECTED`
- callsite table は manifest の `allowed_callsites` + KASLR 再配置で構築

### §20.4–20.5. Output Rules, Call Modes

全 call は同期。`FBVBS_CMD_FLAG_SEPARATE_OUTPUT` 以外のフラグビットは予約（ゼロ必須）。ABI v1 では非同期呼出、scatter-gather 出力、caller-supplied partition identity は範囲外。

## §21. CPU Control and Register Pinning

- CR0.WP, CR4.SMEP/SMAP, CET 関連ビットをインターセプトでピン留め
- パーティション遷移時に汎用/デバッグ/ベクタレジスタをクリア
- IBPB, VERW, L1D flush 等の投機実行対策

---
---

# Part VI. Kernel Translation Integrity Across Intel and AMD

> *本パートは、コード整合性だけでなく翻訳整合性も必須であることを定義し、Intel/AMD で異なる達成経路を規定する。*

## §22. Why Translation Integrity Is Mandatory

コードページを read-only にしても、仮想→物理の対応が差し替えられれば保護は破られる。本書では Kernel Translation Integrity をコード整合性と同格の必須要件とする。

## §23. Intel Path: HLAT Is Mandatory

Intel 実装では **HLAT を必須**とする。HLAT 非使用の Intel 構成は FBVBS v7 適合を名乗ってはならない。

> Intel が AMD より本質的に「安全」であることを意味しない。本設計が必要とする翻訳整合性において Intel には専用機構がある、というだけである。

## §24. AMD Path: Equivalent Objective Through Composite Mechanisms

AMD には HLAT と一対一に対応する単一機構がない。「HLAT 相当がある」と記述してはならない。代わりに:

1. カーネル PTE ページを NPT で write-protect、更新は fault handling 経由のみ
2. CR3 更新、PTE 更新、`INVLPG`、NPT fault、guest page fault の同期
3. シャドウ翻訳経路の維持（FreeBSD が差替え不可）
4. SEV-SNP (RMP/VMPL) は補強として利用可だが単独で HLAT 同等を主張不可

## §25. Conformance Rule for AMD

AMD 実装も同格のセキュリティ目標を負う。ただし同格性は実証が必要: PFN 差替え、PTE 改ざん、TLB invalidate race、複数コア同時更新のテスト群で立証しなければならない。

---
---

# Part VII. Trusted Services

> *本パートは、五つの信頼サービスの責務、API、限界を個別に定義する。*

## §26. Kernel Code Integrity Service

**責務（三つ）:** (1) W^X 維持、(2) モジュール署名/失効/世代番号の検証、(3) 翻訳整合性との整合確認。

未署名モジュールの既定方針は**不許可**。execute 権限付与時には対象 GPA bytes と承認済み artifact bytes の再照合が必須。

> コード整合性が成立しても ROP/JOP は自動消滅しない。CET、Shadow Stack、IBT、SMEP/SMAP との併用が必要。

## §27. Kernel State Integrity Service

**三層分類:**

| 層 | 名称 | 例 | 更新規約 |
|---|------|---|---------|
| Tier A | 起動後不変 | sysent, IDT, GDT, vop_vector, cdevsw | write-enable 経路なし |
| Tier B | 制御付き更新 | ucred, prison, securelevel, MAC, Capsicum, pf/ipfw | shadow copy + 最小 RW 区間 |
| Tier C | 保護対象外 | fd テーブル, socket, 経路表 | 本バージョンで非保護 |

**ポインタチェーン保護:** ucred 本体だけでなく `td->td_ucred` 等のポインタも保護。許可ポインタ差替えは登録済み正規オブジェクト集合内への遷移に限定。

> **防げないもの（明示）:** 意味論的 API 悪用、署名済み脆弱 setuid バイナリ、Tier C 経由のデータ窃取、平文データ読取り。

### §27.1. Controlled Update Path and Atomicity

Tier B 更新フロー: shadow copy → 最小時間 write-enable → memcpy → read-only 復帰。マルチコア競合時は他コア書込み一時停止。大規模ルール集合は新ページ確保→ポインタ原子的切替えを優先。

### §27.2. Setuid and Privilege Elevation Validation

`execve`/`fexecve`/`setuid(2)`系の検査。許可 DB は署名付き成果物として搬送手段非依存で配布。認可キーにパスは使わず vnode / `fsid+fileid` を主とする。ABI v1 では資格情報遷移を `ruid/euid/suid/rgid/egid/sgid` の完全な要求後状態として表現。

## §28. Identity Key Service

**核心:** 鍵素材がサービス境界を越えて出ない（非抽出性）。API は `IMPORT_KEY`, `SIGN`, `KEY_EXCHANGE`, `DERIVE`, `DESTROY` に限定。鍵返却呼出は存在してはならない。

暗号ライブラリ: Ada/SPARK primitive を優先評価。外部 C ライブラリ/Ada バインディング利用時は当該性質の TCB に含める。

## §29. Storage Key Service

**価値の最大化:** 未マウント時の鍵非抽出性、オフライン窃取耐性、侵害復旧時の鍵再生成不要性。

**明示的限界:** マウント後のオンライン平文保護は不可能。BitLocker も同じ制約を受ける。

## §30. Update Verification Service

最重要サービスの一つ。更新経路が悪意ある新バージョンを許せば全防御が正規機能として崩壊する。搬送手段は問わず、成果物とマニフェストの検証に合格したもののみをロード。

---
---

# Part VIII. FreeBSD Integration

> *本パートは、FreeBSD フロントエンドの非信頼性と、カーネル介入点を定義する。*

## §31. FreeBSD Front-End Role

`fbvbs.ko` は非信頼の ABI 変換層。侵害時影響は誤要求、要求省略、DoS に閉じ込める。信頼サービスメモリ、第二レベルページテーブル、一次監査ログへの書換えは不可。

## §32. Integration Hooks in the FreeBSD Kernel

**必要な介入点系統:**

1. **KLD ロード経路** — 署名検証と権限付与
2. **execve/fexecve/setuid/setgid** — 特権上昇検査
3. **Jail, MAC (`mpo_cred_check_execve` 等), Capsicum** — 不変条件関連変更の観測・制御
4. **鍵利用経路** — 秘密鍵を直接所有しない API ラッパー
5. **bhyve/vmm 統合経路** — VM 操作のマイクロ HV 前提書き換え

`mac(9)` の entry point checks だけで全攻撃経路を網羅したと主張してはならない。カーネル差分最小化と将来保守性を重視。

---
---

# Part IX. Deep bhyve and vmm Integration

> *本パートは、bhyve 統合の制御/実行プレーン分離、VM ライフサイクル、passthrough を詳述する。*

## §33. Why the bhyve Section Must Be Deep

既存 bhyve は vmm が VMX root に直接触れることを前提としているが、FBVBS ではその制御権をマイクロ HV が保持する。単なるラッパー差替えではなく責務分担の再設計が必要。

## §34. Control Plane and Execution Plane Separation

| 層 | 場所 | 内容 |
|---|------|------|
| **制御プレーン** | bhyve ユーザーランド（残存） | VM 構成、PCI/virtio デバイスモデル、ACPI、管理 CLI |
| **実行プレーン** | マイクロ HV（移行先） | VM entry/exit、第二レベルページング、IOMMU、割込み再マップ |
| **vmm 互換層** | FreeBSD カーネル（残存） | `/dev/vmm` + `libvmmapi` 高レベル ABI 維持 |

Guest VM も一般パーティション状態機械に従う。ABI v1 の guest boot は常に flat 64-bit model。

## §35. VM Lifecycle Under FBVBS

VM 作成: `VM_CREATE` → `PARTITION_MEASURE` → `PARTITION_LOAD_IMAGE` → `PARTITION_START`。`VM_RUN` はこの完了後のみ。

**未分類 exit の fail-closed:** 分類できない exit は FreeBSD に委譲せず停止・記録。

VM 破棄: ゲストメモリゼロ化 → IOMMU ドメイン解除 → 割込み再マップ解放 → デバイス割当巻き戻し。

### §35.1. vCPU State Machine

| 状態 | 遷移条件 |
|------|---------|
| Created → Runnable | `PARTITION_START` 完了 |
| Runnable → Running | `VM_RUN` |
| Running → Runnable | PIO, MMIO, external interrupt, EPT/NPT violation, CR/MSR access, shutdown |
| Running → Blocked | halt |
| Blocked → Runnable | 外部イベント/割込み注入 |
| Running/Runnable/Blocked → Faulted | 未分類 exit/致命 fault |
| Faulted → Runnable | `PARTITION_RECOVER` 成功 |

ABI v1 では任意の一 vCPU fault で VM 全体を Faulted とする。

## §36. Guest Memory Ownership and Mapping

FreeBSD は guest memory descriptor を保持するが machine frame の最終割当権は持たない。マイクロ HV が拒否、延期、整列変更してよい。

## §37. Passthrough, DMA, and Interrupt Remapping

passthrough デバイスの最終所有権はマイクロ HV。IOMMU group, ACS, リセット能力, MSI/MSI-X 制御, interrupt remapping を検査後にのみ割当。デバイス解除時は Function Level Reset 必須。

## §38. Explicit Non-Goals in Virtualization

本バージョンでは **live migration**, **nested virtualization** は非目標。snapshot は将来拡張点としてのみ。

---
---

# Part X. Update Model, Artifact Model, and Rollback Protection

> *本パートは、搬送手段非依存の更新モデルと署名鍵階層を定義する。*

## §39. Transport-Independent Update Architecture

「どう運ばれてきたか」ではなく「何が運ばれてきたか」で信頼する。`freebsd-update`, `pkg`, オフライン媒体, DevOps 配布基盤のいずれでもよい。

マニフェスト必須項目: format version, component type, target platform, hash, size, signature, generation, security epoch, dependency, revocation reference。

更新メタデータ集合は freshness, freeze 攻撃検出, mix-and-match 防止, snapshot 一貫性を扱えなければならない。

## §40. Signature Hierarchy and Key Ceremony

高保証運用プロファイルでは HSM + 二者承認以上のリリース署名手順が必須。ルート鍵はオフライン管理、中間鍵で用途制約。鍵失効は第一級機能。

---
---

# Part XI. Quality, Verification, and Engineering Discipline

> *本パートは、SPARK 以上の品質保証規律を定義する。*

## §41. Why a High-Assurance Design Needs More Than SPARK

参照モデル: DO-178C/ED-12C (工程規律), DO-333 (形式手法補足), Common Criteria / SESIP (脅威・境界・証拠整理), seL4 (証明範囲の限定主張)。

## §42. Mandatory Process Requirements

要求↔設計↔実装↔試験↔証拠の双方向トレーサビリティ必須。TCB 変更は独立レビュア 1 名以上の承認必須。

## §43. Language-Specific Rules

| 言語 | 要件 |
|------|------|
| SPARK | AoRTE 証明、Pre/Post/型不変条件明記、動的メモリ/再帰/暗黙例外禁止 |
| Rust | `no_std`, `panic=abort`, 固定 toolchain, `unsafe` 局所化+安全性契約 |
| C（例外） | MISRA C:2023 + CERT C 適合、UB 不在の静的解析/証明、Frama-C 等の成果物 |
| ASM | 呼出規約/レジスタ/前提/後続状態の文書化 + 逆アセンブルレビュー |

## §44. Test, Fuzzing, Fault Injection, and Coverage

**必須:** 要求ベース統合試験、境界値、異常系、競合、soak、負荷、fault injection、fuzzing。特に hypercall パーサ、IPC パーサ、更新パーサ、署名ローダ、ログデコーダ、bhyve フロントエンド境界は継続的 fuzzing 対象。

中核分岐（権限判定、状態遷移、隔離境界、更新承認）は **MC/DC** を目標。

## §45. Supply Chain and Reproducibility

再現可能ビルド、SBOM、署名付き provenance 必須。依存関係 allowlist 化、バージョン固定、脆弱性監視。

---
---

# Part XII. Windows Comparison and Platform Positioning

## §46. Correcting the Windows Comparison

「Windows に OS 固有保護はない」は事実に反する。Windows には VBS, HVCI, Credential Guard, App Control for Business, Kernel DMA Protection, PPL, System Guard Secure Launch, KDP 等がある。FBVBS は「FreeBSD に対し別の構造で近い目標を実現する」と位置づける。

## §47. Intel and AMD as Security Platforms

単純な優劣論ではない。Intel は HLAT という直接機構を持ち、AMD は SEV-SNP/RMP/VMPL で別の保護様式を持つ。FBVBS が必要とする翻訳整合性の観点では Intel が有利な出発点だが、それはベンダの優劣ではなく機構の揃い方の差。

---
---

# Part XIII. Performance, Failure Modes, and Residual Risk

## §48. Performance Discipline

通常 syscall/read-only 読取り → ほぼゼロ追加コスト。setuid 検証/モジュール署名/鍵操作/VM exit → 十数µs〜数百ms 許容。

## §49. Failure Semantics

panic 禁止 = 「決して停止しない」ではない。当該サービス/VM を隔離し既存保護を維持したまま明示的エラーとする。KSI 障害時 → Tier B 更新停止だが Tier A 保護は維持。

## §50. Residual Risks

| # | リスク |
|---|--------|
| 1 | AMD 翻訳整合性の実装と立証の難度 |
| 2 | Tier C 経由の論理攻撃 |
| 3 | 外部プロトコル実装の TCB 依存 |
| 4 | OOB ログ経路のハードウェア運用依存 |

---
---

# Part XIV. Conclusion

本書が定義する FBVBS v7 は、FreeBSD を敢えて完全には信頼せず、高価値資産と状態をより狭く監査可能な境界へ移し替える試みである。

> **設計上退けた近道:**
> - `freebsd-update` への固定
> - 監査を欠く独自暗号
> - AMD への根拠不十分な同格主張
> - bhyve 節の簡略化
> - FreeBSD ミラーログを一次監査根拠として扱うこと
> - SPARK 採用のみを根拠とした「形式検証済み」断定

本仕様書は依然として本番宣言前の立証課題を持つが、それらは仕様未完成を意味しない。未解決なのは実装と検証の完了であり、仕様の空欄ではない。

---
---
---

# Normative Appendices

---

# Appendix A. Historical Name Mapping

| 旧略称 | 説明的名称 |
|--------|-----------|
| HEKI | Kernel Code Integrity Service |
| KDP | Kernel State Integrity Service（一部機能概念） |
| IKV | Identity Key Service |
| DKV | Storage Key Service |

---

# Appendix B. Acronym and Term Expansion

**仮想化基盤:**

| 略語 | 正式名称 | 説明 |
|------|---------|------|
| TCB | Trusted Computing Base | ある保護性質のために信頼すべき最小構成要素 |
| VT-x | Intel Virtualization Technology | Intel の仮想化拡張 |
| AMD-V | AMD Virtualization | AMD の仮想化拡張 |
| EPT | Extended Page Tables | Intel の第二レベルアドレス変換 |
| NPT | Nested Page Tables | AMD の第二レベルアドレス変換 |
| HLAT | Hypervisor-Managed Linear Address Translation | Intel のハイパーバイザー管理線形アドレス変換 |
| MBEC | Mode-Based Execute Control | Intel の実行権限細粒度化 |
| GMET | Guest Mode Execute Trap | AMD の対応機能 |
| RMP | Reverse Map Table | SEV-SNP のページ所有権管理 |
| VMPL | Virtual Machine Privilege Level | SEV-SNP guest の特権階層 |

**I/O・DMA:**

| 略語 | 正式名称 | 説明 |
|------|---------|------|
| DMA | Direct Memory Access | CPU 非介在のデバイス→主記憶アクセス |
| IOMMU | I/O Memory Management Unit | DMA 到達範囲の制御 |
| PIO | Programmed I/O | ポート空間 I/O |
| MMIO | Memory-Mapped I/O | メモリ写像 I/O |
| MSI/MSI-X | Message Signaled Interrupts | PCI デバイスの割込み方式 |
| SR-IOV | Single Root I/O Virtualization | 物理デバイスの仮想機能分割 |
| ACS | Access Control Services | PCIe トランザクション分離 |

**セキュリティ・品質:**

| 略語 | 正式名称 | 説明 |
|------|---------|------|
| W^X | Write XOR Execute | 書込/実行の排他原則 |
| OOB | Out-of-Band | FreeBSD 信頼境界外の監査経路 |
| SOL | Serial-over-LAN | BMC 経由シリアルコンソール |
| UART | Universal Asynchronous Receiver/Transmitter | シリアル通信ハードウェア |
| CRC32C | Castagnoli CRC-32 | 伝送破損検出用チェックサム |
| HSM | Hardware Security Module | 署名鍵保護用専用 HW |
| SBOM | Software Bill of Materials | 依存関係部品表 |
| MC/DC | Modified Condition/Decision Coverage | 高水準分岐網羅指標 |

---

# Appendix C. Minimal Binary Log Record Layout

> **エンディアン:** little-endian　**アラインメント:** 自然アラインメント

```c
struct fbvbs_log_record_v1 {
    uint64_t sequence;          // 単調増加シーケンス番号
    uint64_t boot_id_hi;        // ブート識別子（上位）
    uint64_t boot_id_lo;        // ブート識別子（下位）
    uint64_t timestamp_counter; // タイムスタンプカウンタ
    uint32_t cpu_id;            // CPU 識別子
    uint32_t source_component;  // ソースコンポーネント ID
    uint16_t severity;          // 重大度
    uint16_t event_code;        // イベントコード
    uint32_t payload_length;    // ペイロード長（≤ 220）
    uint8_t  payload[220];      // ペイロード本体
    uint32_t crc32c;            // CRC32C（偶発破損検出のみ）
};
```

`payload_length > 220` は禁止。大きなペイロードは複数レコードに分割。CRC32C 単独では暗号学的改ざん耐性を与えない。

## C.1. Frozen Mirror Ring Header Layout

```c
struct fbvbs_log_ring_header_v1 {
    uint32_t abi_version;           // = 1
    uint32_t total_size;            // リングバッファ総バイト数
    uint32_t record_size;           // = sizeof(fbvbs_log_record_v1)
    uint32_t write_offset;          // リング本体先頭からのオフセット
    uint64_t max_readable_sequence; // 読取可能最大シーケンス番号
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};
```

`write_offset` は `record_size` の整数倍。

---

# Appendix D. Frozen Shared Command Page Layout

> **ABI v1 凍結。互換性を破る変更は `abi_version` 更新が必須。**

```c
struct fbvbs_command_page_v1 {
    uint32_t abi_version;        // = 1
    uint16_t call_id;            // 呼出番号
    uint16_t flags;              // D.1 参照
    uint32_t input_length;       // 要求本文長
    uint32_t output_length_max;  // 応答最大長
    uint64_t caller_sequence;    // vCPU 単調増加整数
    uint64_t caller_nonce;       // 監査相関用（認可判断に不使用）
    uint32_t command_state;      // D.2 参照
    uint32_t actual_output_length;
    uint64_t output_page_gpa;    // 別出力ページ GPA（flag bit 0 時のみ有効）
    uint64_t reserved0;          // 0 必須
    uint8_t  body[4040];         // 要求/応答本文
};
```

**規則:**
- `reserved0` と未使用 body 領域は 0 必須（非ゼロ → `INVALID_PARAMETER`）
- `status_code=OK` → `command_state=COMPLETED`、`status_code!=OK` → 必ず `FAILED`
- `actual_output_length=0` なら応答本文無視必須

### D.1. Command Flags

| bit | 名称 | 意味 |
|-----|------|------|
| 0 | `FBVBS_CMD_FLAG_SEPARATE_OUTPUT` | 応答を `output_page_gpa` へ |
| 1–15 | 予約 | 0 必須 |

### D.2. Command States

| 値 | 名称 |
|---|------|
| 0 | EMPTY |
| 1 | READY |
| 2 | EXECUTING |
| 3 | COMPLETED |
| 4 | FAILED |

### D.3. Output Page Rules

別出力ページは 4096 アラインメント。列挙系 call の最大件数: `DIAG_GET_PARTITION_LIST` 252 件、`DIAG_GET_ARTIFACT_LIST` 63 件、`DIAG_GET_DEVICE_LIST` 252 件。

### D.4. Bootstrap Metadata Page

```c
struct fbvbs_bootstrap_page_v1 {
    uint32_t abi_version;               // = 1
    uint32_t vcpu_count;                // 有効 command_page_gpa 数（≤ 252）
    uint64_t command_page_gpa[252];     // 各 vCPU の command page GPA
};
```

GPA は `RSI` レジスタで caller に渡される。

---

# Appendix E. Final Verification of This Specification

本仕様書の最終検証として十項目を確認:

1. 一次監査ログと FreeBSD 可視ログの混同なし
2. Intel HLAT 必須、AMD は「HLAT 相当がある」と虚偽記述なし
3. 更新機構は搬送手段非依存の署名付き成果物モデル
4. 外部ライブラリ利用時は TCB に含めることを明記
5. KSI の防げる攻撃と防げない攻撃を分離
6. bhyve 統合が制御/実行プレーン、DMA、割込み、所有権まで分解
7. Windows 防御機構を正しく認識
8. 主要略語に説明を付与
9. 凍結済み ABI が一意に解釈可能
10. requirements metadata が一意に復元可能

---

# Appendix F. Proof Obligations Before Production Declaration

> **本番宣言前に閉じなければならない六つの立証課題:**

| # | 課題 | 内容 |
|---|------|------|
| 1 | **AMD 翻訳整合性** | PFN 差替え、PTE 改ざん、TLB race、マルチコア競合、異常 fault 順序、復旧経路の実証 |
| 2 | **FreeBSD 介入点の十分性** | 対象 FreeBSD 版での不変条件の観測・制御をコード読解と試験で確認 |
| 3 | **更新 freshness** | freeze 攻撃、mix-and-match、stale mirror、ロールバック復旧手順の fail-closed 実証 |
| 4 | **一次監査ログ経路** | ハードウェア、FW 設定、BMC、配線、収集サーバ、保存ポリシー、過負荷時欠落特性を運用手順込みで確定 |
| 5 | **暗号実装選定** | 採用実装の TCB 範囲、外部依存、証明範囲、監査根拠を成果物レベルで確定 |
| 6 | **bhyve passthrough** | サポート対象デバイス群ごとの qualification matrix 作成 |

---

# Appendix G. Requirements Catalog

> **本付録は実装契約としての最終参照点。本文と矛盾する場合は本付録を優先。**
>
> 各 subsection は先頭に metadata 既定値を持つ。要求行に明示されていない属性はその既定値を継承。試験 ID は `T-<prefix>-<req#>`、証拠 ID は `E-<prefix>-<req#>` の導出規則。

---

## G.1. Roots of Trust, Boot, and Platform

> *type=security,functional,operational | sections=8,12–15,F | components=microhypervisor,firmware,platform | prefix=BOOT*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0001 | マイクロ HV は FreeBSD より前にロード | boot trace inspection, platform test |
| 0002 | FreeBSD が VMX root/SVM ホスト制御権取得前にマイクロ HV 有効化 | boot path analysis, platform test |
| 0003 | FBVBS v7 適合構成では IOMMU が存在し有効化 | configuration inspection, platform test |
| 0004 | ロールバック防止構成では TPM NV 等で世代比較 | update rollback test, inspection |
| 0005 | FBVBS v7 適合構成では OOB 一次監査ログ経路が構成済み。高保証では運用成立性立証 | operational drill, inspection |
| 0006 | 高保証では起動時検証・測定を満たし証拠を監査可能に | boot attestation test, evidence inspection |

## G.2. Logging and Audit

> *type=security,interface,operational | sections=13–15,C | components=microhypervisor,log relay,FreeBSD mirror,OOB path | prefix=LOG*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0100 | 一次監査ログとミラーログを分離 | design inspection, runtime test |
| 0101 | 一次監査ログは FreeBSD 侵害時にも OOB で観測可能 | adversarial operational drill |
| 0102 | ミラーログは一次監査根拠として不使用 | documentation review |
| 0103 | レコードに sequence, boot ID, CPU ID, source, severity, event code, payload, CRC32C | interface test, inspection |
| 0104 | CRC32C のみで改ざん耐性を主張不可 | design inspection |
| 0105 | FreeBSD 可視リングバッファは RO、第二レベルページングで書込拒否 | runtime test, fault injection |
| 0106 | early boot/panic ログ完全性は best effort、完全取得を主張不可 | documentation review, panic-path test |
| 0107 | ミラーログは `fbvbs_log_ring_header_v1` + `fbvbs_log_record_v1` 固定構造 | interface test, inspection |

## G.3. Microhypervisor and Partition

> *type=functional,interface,security | sections=16–20,D,L | components=microhypervisor,partition manager,front-end | prefix=PART*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0200 | マイクロ HV 責務をパーティション管理、CPU 遷移、EPT/NPT、IOMMU、CPU 制御強制、起動検証、ログに限定 | architecture inspection |
| 0201 | 新規 TCB は Ada/SPARK。C 例外は境界/理由/安全性契約/UB 不在根拠を文書化 | code review, proof artifact review |
| 0202 | パーティション状態 8 種、不正遷移不可 | state-machine test, inspection |
| 0203 | Destroyed メモリは再割当前にゼロ化 | memory reuse test |
| 0204 | capability はマイクロ HV のみが付与/取消/監査 | proof, analysis, negative test |
| 0205 | hypercall ABI は固定形式 | interface test, fuzzing |
| 0206 | 未ゼロ化領域の要求は `INVALID_PARAMETER` | negative interface test |
| 0207 | trap レジスタ規約は凍結 ABI | interface test, trap-level inspection |
| 0208 | `abi_version` 不一致 → `ABI_VERSION_UNSUPPORTED` | negative interface test |
| 0209 | `caller_sequence` 単調増加、後退 → `REPLAY_DETECTED` | replay test |
| 0210 | command page 状態機械 5 状態、EXECUTING 再入 → `RESOURCE_BUSY` | state-machine test, concurrency test |
| 0211 | 合法遷移は §18.1 限定、表外 → `INVALID_STATE` | lifecycle transition test, inspection |
| 0212 | `PARTITION_RESUME` は Quiesced→Runnable のみ、Faulted には `PARTITION_RECOVER` | negative lifecycle test |

## G.4. CPU Control and Translation Integrity

> *type=security,functional | sections=21–25 | components=microhypervisor,CPU path,IOMMU | prefix=CPU*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0300 | FreeBSD は CR0.WP/CR4.SMEP/SMAP/CET を任意解除不可 | trap test, inspection |
| 0301 | Intel では HLAT 必須。非使用は適合不可 | platform capability inspection, conformance review |
| 0302 | AMD は HLAT 単一保証を主張不可。複合経路を実装 | design inspection, adversarial test |
| 0303 | AMD 高保証は PFN/PTE/TLB/マルチコア実証完了が必要 | adversarial multiprocessor test |
| 0304 | SEV-SNP のみで HLAT 同等を主張不可 | design review, documentation review |

## G.5. Kernel Code Integrity

> *type=security,functional,interface | sections=26,L | components=KCI,microhypervisor,front-end | prefix=KCI*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0400 | カーネル/モジュールコードページは W^X 維持 | memory protection test |
| 0401 | 未署名モジュールは既定不許可。署名+失効+世代+プラットフォーム合格時のみ execute | module load test, negative test |
| 0402 | コード整合性構成では翻訳整合性も保護 | translation tamper test |

## G.6. Kernel State Integrity

> *type=security,functional,interface | sections=27,H,L | components=KSI,microhypervisor,front-end | prefix=KSI*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0500 | 三層分類（不変/制御付き更新/非保護）の区別 | design inspection |
| 0501 | Tier B 変更は shadow copy + 最小 RW 区間 | concurrency test, analysis |
| 0502 | ポインタ更新は登録済み正規集合への遷移のみ | negative test, proof/analysis |
| 0503 | execve/fexecve/setuid/setgid の特権上昇検査。ruid/euid/suid/rgid/egid/sgid 完全表現 | syscall test, interface review |
| 0504 | 認可主キーにパス不使用。vnode / fsid+fileid | exec path variation test |
| 0505 | fd 継承等の権限持越しは残余リスクとして扱う | documentation review |
| 0506 | callsite 検証はマイクロ HV 観測 RIP に基づく | adversarial caller spoofing test |
| 0507 | KSI_VALIDATE_SETUID は fsid/fileid/ハッシュ/UID・GID 遷移/ucred/Jail/MAC を入力 | interface review, syscall/path test |
| 0508 | CALLSITE_REJECTED は許可 table 完全一致 RIP 比較。KASLR 再配置後導出、KLD 更新時原子的再計算 | callsite relocation test, negative spoofing test |

## G.7. Key Services

> *type=security,functional,interface | sections=28–29,L | components=IKS,SKS,front-end | prefix=KEY*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0600 | IKS は鍵素材をサービス境界外へ返却不可 | interface test, code inspection |
| 0601 | IKS API は IMPORT/SIGN/KEY_EXCHANGE/DERIVE/DESTROY に限定 | interface review |
| 0602 | 外部暗号ライブラリは当該 TCB に含める | dependency review, evidence review |
| 0603 | SKS はオンライン平文保護を主張不可 | documentation review, threat-model review |
| 0604 | KEY_EXCHANGE 返却は不透明ハンドルのみ | interface test, code inspection |

## G.8. Update and Artifact

> *type=update,security,interface | sections=30,39–40,L | components=UVS,KCI,microhypervisor | prefix=UVS*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0700 | 搬送手段を freebsd-update に固定不可 | design inspection |
| 0701 | マニフェスト必須項目: format, type, platform, hash, size, generation, epoch, dep, revocation | parser test, inspection |
| 0702 | freshness/freeze/mix-and-match/snapshot 一貫性 | update adversarial test |
| 0703 | 高保証では HSM + 二者承認以上 | operational audit |
| 0704 | freshness 失敗 → `FRESHNESS_FAILED` | adversarial update test |
| 0705 | snapshot 不整合 → `SNAPSHOT_INCONSISTENT` / `DEPENDENCY_UNSATISFIED` | adversarial metadata consistency test |

## G.9. FreeBSD Integration

> *type=functional,security,interface | sections=31–32 | components=front-end,kernel fork,hooks | prefix=FBSD*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0800 | front-end は非信頼 ABI 変換層。侵害影響は誤要求/省略/DoS に限定 | architecture review, adversarial test |
| 0801 | front-end は信頼サービスメモリ/EPT/ログへの書換え能力不可 | isolation test |
| 0802 | 介入点: KLD, 資格情報, Jail, MAC, Capsicum, 鍵, bhyve/vmm | integration review, syscall/path test |
| 0803 | mac(9) だけで攻撃面網羅を主張不可。各不変条件で個別実証 | code audit, threat traceability review |
| 0804 | vmm(4)/passthrough の boot-time/loader 介入点も設計対象 | boot integration test |

## G.10. bhyve and Virtualization

> *type=functional,security,interface | sections=33–38,L | components=microhypervisor,vmm front-end,bhyve | prefix=VM*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 0900 | bhyve は制御プレーン。実行プレーン最終制御権はマイクロ HV | architecture inspection |
| 0901 | /dev/vmm, libvmmapi の高レベル ABI を仕様定義意味論で維持 | compatibility test |
| 0902 | 未分類 VM exit は fail-closed（停止・記録） | exit classification test, fault injection |
| 0903 | guest memory は再利用前ゼロ化 | memory reuse test |
| 0904 | passthrough は IOMMU group/ACS/MSI-X/interrupt remap/reset 合格後のみ | device qualification test |
| 0905 | live migration, nested virt は本版非目標 | documentation review |
| 0906 | VM_RUN は Runnable vCPU のみ | VM lifecycle negative test |
| 0907 | vCPU 状態機械 6 状態。Blocked は halt 待機のみ | vCPU state-machine test, inspection |
| 0908 | VM_GET_VCPU_STATUS で外部可視 vCPU 状態を返す | interface test, VM lifecycle test |
| 0909 | memory object/shared registration は release/unregister で終了可能 | resource lifecycle test |

## G.11. Quality and Supply-Chain

> *type=quality,operational,security | sections=41–45 | components=all TCB,build,CI,release | prefix=QUAL*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 1000 | 要求↔設計↔実装↔試験↔証拠の双方向トレーサビリティ | traceability audit |
| 1001 | TCB 変更は独立レビュア 1 名以上承認 | review record audit |
| 1002 | SPARK コードは AoRTE 証明 | proof artifact review |
| 1003 | Rust TCB は no_std, panic=abort, 固定 toolchain, unsafe 局所化+契約 | code/build inspection |
| 1004 | hypercall/IPC/update/署名/ログ/bhyve パーサは fuzzing 対象 | fuzz campaign evidence |
| 1005 | 中核分岐は MC/DC 目標。困難時は代替基準+理由記録 | coverage review |
| 1006 | リリース成果物は再現可能ビルド + SBOM + 署名付き provenance | supply-chain audit |

## G.12. Production Readiness

> *type=operational,security,quality | sections=F | components=governance,release authority,validation | prefix=PROD*

| REQ | 要求本文 | 検証方法 |
|-----|---------|---------|
| 1100 | 本番前に AMD 翻訳整合性の実証完了 | adversarial multiprocessor campaign |
| 1101 | 本番前に FreeBSD 介入点の十分性をコード読解+試験で実証 | design review, integration campaign |
| 1102 | 本番前に更新 freshness/freeze/mix-and-match 耐性実証 | update adversarial campaign |
| 1103 | 本番前に一次監査ログ経路の実運用成立性確認 | operational drill |
| 1104 | 本番前に暗号実装の TCB 範囲/依存/証明範囲/監査根拠を確定 | crypto review board, evidence audit |
| 1105 | 本番前にサポート対象 passthrough デバイスの qualification matrix | device qualification report review |

---

# Appendix H. Protected Structure Catalog

> *v7 §27 の三層分類に対し、個々の FreeBSD カーネル構造体の割当を具体化する。*

## H.2. Tier A — 起動後不変

| 構造体 | 攻撃効果 | 頻度 | Incr | 根拠 |
|--------|---------|------|------|------|
| `sysent[]` | syscall フック | ゼロ | 3 | コンパイル時定義 |
| IDT | 割込みハイジャック | ゼロ | 3 | ブート後不変 |
| GDT | セグメント破壊 | ゼロ | 3 | ブート後不変 |
| `.rodata` | 定数改竄 | ゼロ | 3 | 定義上不変 |
| `vop_vector` | VFS リダイレクト | ゼロ | 3 | `.rodata` 配置 |
| `cdevsw` | デバイス操作リダイレクト | ゼロ(ロード後) | 3 | KLD 登録後不変 |
| `filterops` | kqueue リダイレクト | ゼロ | 3 | コンパイル時定義 |
| カーネル PTE (AMD) | PFN スワップ | ゼロ | 4 | Intel は HLAT |

**実装:** write-enable 経路なし。KLD 新規 `cdevsw` は KCI 署名検証後に Tier A 追加登録。

## H.3. Tier B — 制御付き更新

| 構造体 | 攻撃効果 | 頻度 | Incr | 根拠 |
|--------|---------|------|------|------|
| `struct ucred` | 権限昇格 | 低 | 3 | 核心 |
| ucred ポインタ | 間接権限昇格 | 低 | 3 | ポインタ差替え対策 |
| `struct prison` | Jail エスケープ | 極低 | 3 | 主要分離機構 |
| prison ポインタ | prison0 誘導 | 極低 | 3 | 補完 |
| `securelevel` | securelevel 迂回 | 極低 | 3 | FreeBSD 固有 |
| MAC ポリシー | MAC 無効化 | 極低 | 3 | 主要セキュリティ層 |
| Capsicum フラグ | サンドボックス脱出 | 極低 | 3 | 分離基盤 |
| `pf` ルール | FW 無効化 | 極低 | 5 | ネットワーク境界 |
| `ipfw` ルール | 同上 | 極低 | 5 | 同上 |
| `p_textvp` | Setuid 検証基盤改竄 | 極低 | 5 | 識別情報 |

**実装:** shadow copy → callsite/ポリシー検証 → 最小 RW 区間 → RO 復帰。大規模ルールは原子的置換方式。

## H.4. Tier C — 保護対象外

| 構造体 | 攻撃効果 | 非保護の理由 |
|--------|---------|------------|
| `struct filedesc` | ucred チェックなしの fd 差込み | 変更頻度が高すぎる |
| `struct file` | f_ops 差替え | 同上 |
| `struct socket` | ソケットハイジャック | 同上 |
| `struct inpcb` | 接続パラメータ改竄 | 同上 |
| ルーティングテーブル | トラフィックリダイレクト | 動的環境で高頻度 |
| スケジューリング構造体 | スケジュール操作 | 最高頻度操作 |
| mbuf | 通信データ傍受/改竄 | データパス上 |
| VFS キャッシュ | ファイルデータ改竄 | 頻繁な更新不可避 |

fd テーブル攻撃は国家レベルの攻撃者には実行可能（KASLR 下でのアドレス発見が必要だがデータオンリー攻撃で可能）。本バージョンでは明示的限界。

---

# Appendix I. Service Failure Impact Matrix

> *マルチサーバー設計の核心的利点: サービス障害時にも既設定の保護は維持される。*

| 障害サービス | 停止する機能 | 維持される保護 | FreeBSD への影響 | 回復 |
|---|---|---|---|---|
| **KCI** | 新規 KLD 検証、CR/MSR 設定 | 既存 W^X、CR ピニング | 新規 KLD ロード不可 | パーティション再起動 |
| **KSI** | Tier B 変更承認、Setuid 検証 | Tier A/B の RO 保護 | setuid/Jail/securelevel 変更ブロック | 再起動、保護テーブル復元 |
| **IKS** | 鍵インポート、署名、鍵交換 | 他サービス分離 | TLS/SSH/IPsec ハンドシェイク不可 | 再起動、鍵再ロード |
| **SKS** | 新規マウント、暗号操作 | 他サービス分離、鍵残留 | マウント済み I/O 停止 | 再起動、鍵再ロード |
| **UVS** | 成果物検証 | 既ロード済み成果物 | アップデート不可 | 再起動、検証状態再構築 |
| **マイクロ HV** | **全保護崩壊** | なし | **全システム停止** | システム再起動のみ |

**重要:** EPT/NPT の read-only 設定はマイクロ HV が管理。サービス停止 ≠ 保護解除。

---

# Appendix J. Performance Budget

## J.2. 基本コスト参照値

| 操作 | ベースコスト | 備考 |
|------|------------|------|
| 通常 syscall | ~100–300ns | getpid 等 |
| execve | ~1–5ms | ELF パース含む |
| open/close | ~1–10µs | VFS |
| TLS ハンドシェイク | ~1–10ms | 鍵交換+署名 |
| ZFS 128KB read | ~50–200µs | I/O 含む |
| VM exit (I/O) | ~1–3µs | VMCS 保存/復元 |

## J.3. FBVBS 追加コスト目標

| 操作 | 目標 | IPC | 備考 |
|------|------|-----|------|
| 通常 syscall | ≈ 0 | 0 | FBVBS 非関与 |
| Tier B 読取り | ≈ 0 | 0 | EPT RO 直接読取り |
| Tier B 変更 | 数–十数µs | 1 | shadow copy サイクル |
| Setuid exec | 十数µs | 1 | execve に対し小割合 |
| KLD ロード | 100ms–サブ秒 | 2 | 低頻度のため許容 |
| TLS 署名 (IKS) | 数–十数µs | 1 | ハンドシェイクに対し小割合 |
| ZFS I/O (SKS) | < 10% | 1/バッチ | バッチ化で償却 |
| VM exit (fast) | サブµs | 0 | マイクロ HV 内完結 |
| VM exit (slow) | 数µs | 1 | I/O エミュレーション転送 |
| ログ書込み | サブ–数µs | 0 | セキュリティイベントのみ |

> **禁止:** 通常 syscall への毎回 VMCALL、Tier B 読取りへの VMCALL、ログの同期ブロッカー化

---

# Appendix K. Implementation Roadmap

> *各インクリメントは最終実装に残る成果物で構成。暫定コードや使い捨て骨組みは認めない。*

| Incr | 内容 | 成果物概要 | 主要検証 |
|------|------|-----------|---------|
| **1** | マイクロ HV 基盤 | SPARK マイクロ HV (EPT, IPC, VMCALL, UART ログ)、Intel VT-x、FreeBSD VMX non-root 起動 | メモリ分離実証、IPC 時間計測、GNATprove AoRTE |
| **2** | Kernel Code Integrity | KCI パーティション、fbvbs.ko (Rust)、W^X、MBEC/GMET、CR ピニング、KLD 署名 | コードページ書込み違反、未署名 KLD 拒否、CR インターセプト |
| **3** | Kernel State Integrity | KSI パーティション、Tier A/B 保護、ポインタチェーン、Setuid 検証、マルチコア安全性 | Tier A/B 書込み違反、ポインタ差替え検出、Setuid 承認/拒否 |
| **4** | IKS + SKS + AMD | IKS/SKS パーティション、暗号統合、AMD SVM/GMET/NPT、AMD 翻訳整合性 | 鍵非抽出性、レート制限、AMD PFN/PTE/TLB テスト |
| **5** | bhyve + KSI 拡張 | vmm.ko VMCALL 化、VM exit ルーティング、IOMMU、pf/ipfw/p_textvp | VM 起動、VM エスケープ後分離、ゲストメモリゼロ化、DMA 分離 |
| **6** | UVS + HLAT | UVS パーティション、署名マニフェスト、ロールバック防止、HLAT、A/B パーティション | ロールバック検出、署名拒否、HLAT PFN スワップ防止 |
| **7** | 品質保証(継続) | GNATprove 完了、fuzzing、MC/DC、再現可能ビルド、SBOM、独立監査 | Appendix F 立証課題の全完了 |

---

# Appendix L. Frozen Hypercall ABI Catalog

> **本付録は ABI v1 凍結仕様。変更は ABI version 増加が必須。**

## L.1. 共通規則

- 全 call は**同期呼出**
- エンディアン: **little-endian**、アラインメント: **自然アラインメント**、padding: **0 初期化必須**
- ハンドル値 **0 は常に無効**（返却禁止）
- 全 call 共通で返してよいエラー: `INVALID_PARAMETER`, `RESOURCE_BUSY`, `ABI_VERSION_UNSUPPORTED`, `REPLAY_DETECTED`
- 存在しない ID/ハンドル → `NOT_FOUND`、不正状態 → `INVALID_STATE`、資源不足 → `RESOURCE_EXHAUSTED`、重複 → `ALREADY_EXISTS`、バッファ不足 → `BUFFER_TOO_SMALL`、世代古い → `ROLLBACK_DETECTED`

**Caller column の意味:**

| 表記 | 意味 |
|------|------|
| `FreeBSD` | FreeBSD host partition 全体 |
| `fbvbs.ko` | fbvbs.ko の許可 callsite table 上 RIP から発行 |
| `vmm.ko` | vmm.ko の許可 callsite table 上 RIP から発行 |

---

## L.1.B. Frozen Enumerations

### Partition & Service Kinds

| 名称 | 値 |
|------|---|
| `PARTITION_KIND_TRUSTED_SERVICE` | 1 |
| `PARTITION_KIND_FREEBSD_HOST` | 2 |
| `PARTITION_KIND_GUEST_VM` | 3 |
| `SERVICE_KIND_NONE` | 0 |
| `SERVICE_KIND_KCI` | 1 |
| `SERVICE_KIND_KSI` | 2 |
| `SERVICE_KIND_IKS` | 3 |
| `SERVICE_KIND_SKS` | 4 |
| `SERVICE_KIND_UVS` | 5 |
| `PARTITION_ID_MICROHYPERVISOR` | 0 |

### Memory Permissions

| 名称 | 値 |
|------|---|
| `MEM_PERM_R` | 0x0001 |
| `MEM_PERM_W` | 0x0002 |
| `MEM_PERM_X` | 0x0004 |

### KSI Protection Classes

| 名称 | 値 |
|------|---|
| `KSI_CLASS_UCRED` | 1 |
| `KSI_CLASS_PRISON` | 2 |
| `KSI_CLASS_SECURELEVEL` | 3 |
| `KSI_CLASS_MAC` | 4 |
| `KSI_CLASS_CAPSICUM` | 5 |
| `KSI_CLASS_FIREWALL` | 6 |
| `KSI_CLASS_P_TEXTVP` | 7 |

### IKS Key Types & Operations

| 名称 | 値 |
|------|---|
| `IKS_KEY_ED25519` | 1 |
| `IKS_KEY_ECDSA_P256` | 2 |
| `IKS_KEY_RSA3072` | 3 |
| `IKS_KEY_X25519` | 4 |
| `IKS_KEY_ECDH_P256` | 5 |
| `IKS_OP_SIGN` | 0x0001 |
| `IKS_OP_KEY_EXCHANGE` | 0x0002 |
| `IKS_OP_DERIVE` | 0x0004 |

### VM Registers & Flags

| 名称 | 値 |
|------|---|
| `VM_REG_RIP` | 1 |
| `VM_REG_RSP` | 2 |
| `VM_REG_RFLAGS` | 3 |
| `VM_REG_CR0` | 4 |
| `VM_REG_CR3` | 5 |
| `VM_REG_CR4` | 6 |
| `VM_FLAG_X2APIC` | 0x0001 |
| `VM_FLAG_NESTED_VIRT_DISABLED` | 0x0002 |
| `VM_DELIVERY_FIXED` | 1 |
| `VM_DELIVERY_NMI` | 2 |

### State Numeric Assignments

| 名称 | 値 |
|------|---|
| Partition: Created | 1 |
| Partition: Measured | 2 |
| Partition: Loaded | 3 |
| Partition: Runnable | 4 |
| Partition: Running | 5 |
| Partition: Quiesced | 6 |
| Partition: Faulted | 7 |
| Partition: Destroyed | 8 |
| vCPU: Created | 1 |
| vCPU: Runnable | 2 |
| vCPU: Running | 3 |
| vCPU: Blocked | 4 |
| vCPU: Faulted | 5 |
| vCPU: Destroyed | 6 |

### Capability Bitmap

`capability_mask` bits: 0=partition manage, 1=memory map, 2=memory permission set, 3=shared memory register, 4=KCI access, 5=KSI access, 6=IKS access, 7=SKS access, 8=UVS access, 9=VM manage, 10=audit/diag.

### Platform Capability Bitmap

`CAP_BITMAP0`: bit 0=MBEC/GMET, bit 1=HLAT, bit 2=CET, bit 3=AES-NI.

### VM Exit Reasons

| 値 | 理由 |
|---|------|
| 1 | PIO |
| 2 | MMIO |
| 3 | External interrupt |
| 4 | EPT/NPT violation |
| 5 | Control register access |
| 6 | MSR access |
| 7 | Halt |
| 8 | Shutdown |
| 9 | Unclassified fault |

### Log Source Components

1=microhypervisor, 2=KCI, 3=KSI, 4=IKS, 5=SKS, 6=UVS, 7=FreeBSD front-end, 8=bhyve/vmm.

### Severity

0=debug, 1=info, 2=notice, 3=warning, 4=error, 5=critical, 6=alert.

### Event Codes

1=boot complete, 2=partition fault, 3=policy deny, 4=signature reject, 5=rollback detect, 6=DMA deny, 7=VM exit fail-closed, 8=service restart.

### Additional Fixed Values

- `recovery_flags`: bit 0=restore persistent, bit 1=clear volatile, bit 2=extended remeasure
- `credential operation class`: 1=exec elevation, 2=setuid-family, 3=setgid-family
- `credential id mask`: bit 0-5 = ruid/euid/suid/rgid/egid/sgid valid
- `verdict`: 0=denied, 1=approved
- `failure_bitmap`: bit 0-6 = signature/revocation/generation/rollback/dependency/snapshot/freshness
- `hash algorithm`: SHA-384 48-byte raw (残余 0)
- `object_flags`: 0x0000=private, 0x0001=shareable, 0x0002=guest-memory
- `PIO/MMIO width`: 1/2/4/8 = 8/16/32/64-bit
- `boolean fields`: 0=false, 1=true (他値 → `INVALID_PARAMETER`)

---

## L.1.C. Object ID and Handle Namespace Rules

Object ID/handle は 64-bit 不透明値、0=無効。同一 namespace 内で再起動まで再利用不可。異なる namespace 間の cross-interpretation は `INVALID_PARAMETER`。

KSI object reference は ABI v1 では guest-physical base address をそのまま保持。

**主要 ID のライフサイクル:**

| ID | 発行者 | 消費者 | 生存期間 |
|---|---|---|---|
| `image_object_id` | boot artifact registry | PARTITION_CREATE/MEASURE/LOAD | boot 中 |
| `manifest_object_id` | boot artifact registry | PARTITION_MEASURE, KCI_VERIFY_MODULE | boot 中 |
| `memory_object_id` | microhypervisor | MEMORY_MAP, REGISTER_SHARED, VM_MAP | 解放まで |
| `shared_object_id` | MEMORY_REGISTER_SHARED | caller 監査、MEMORY_UNREGISTER_SHARED | 共有解除まで |
| `target_set_id` | KSI | KSI_REGISTER_POINTER | KSI 再初期化まで |
| `key_handle` | IKS | IKS 系 call | 破棄/再起動まで |
| `dek_handle` | SKS | SKS 系 call | 破棄/再起動まで |
| `device_id` | platform registry | VM_ASSIGN/RELEASE_DEVICE | boot 中 |

**Opaque ID 取得経路:** artifact/device は `DIAG_GET_ARTIFACT_LIST`/`DIAG_GET_DEVICE_LIST`。memory object は `MEMORY_ALLOCATE_OBJECT`。shared は `MEMORY_REGISTER_SHARED`。target set は `KSI_CREATE_TARGET_SET`。推測生成は禁止。

---

## L.1.D. Frozen Payload and Encoding Rules

| 対象 | 形式 |
|------|------|
| KSI patch | `{write_offset:u32, write_length:u32, replacement[4000]}` |
| ED25519 signature | 64-byte raw |
| ECDSA_P256 signature | 64-byte raw `r\|\|s` big-endian |
| RSA3072 signature | 384-byte RSASSA-PSS-SHA384 |
| X25519 peer key | 32-byte raw |
| ECDH_P256 peer key | SEC1 uncompressed 65-byte |
| IKS_DERIVE params | `{kdf_id:u32, salt_len:u32, info_len:u32, reserved:u32, bytes[3976]}` kdf_id=1: HKDF-SHA256 |
| SKS batch descriptor | `{source_gpa:u64, dest_gpa:u64, block_index:u64, byte_length:u32, reserved:u32}` |

**マニフェスト形式:** `fbvbs_signed_manifest_v1` = `{format_version:u32, sig_algorithm:u32, manifest_length:u32, sig_length:u32, bytes[]}` where `bytes = manifest_cbor || signature`。CBOR は RFC 8949 canonical、sig_algorithm=1: Ed25519。

**Manifest CBOR 必須キー (artifact-carrying role):** `component_type`, `target_cpu_vendor`, `required_features`, `target_os_generation`, `payload_hash` (SHA-384 48-byte), `payload_size`, `generation`, `security_epoch`, `dependencies`, `revocation_reference`, `timestamp`, `snapshot_id` (32-byte), `role`, `expires_at`。bootable artifact はさらに `entry_ip` 必須。trusted-service は `service_kind`, `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp`, `autostart` 必須。

---

## L.1.E. Fixed Executable Loader Rules

全 bootable executable artifact は **ELF64 little-endian**、固定 loader 規約:

- `ET_EXEC` または `ET_DYN` のみ受理
- `PT_LOAD` segment のみロード。`PT_INTERP`、動的リンカ、再配置、圧縮、自己展開を**禁止**
- `p_vaddr` に page-align 配置、`p_memsz - p_filesz` を 0 初期化
- permission は `p_flags` から R/W/X 機械的導出（実装裁量なし）
- `entry_ip` は ELF `e_entry` と一致必須
- trusted-service の `initial_sp` は manifest 値のみ（暗黙 stack 生成禁止）

同一 artifact bytes → 同一 guest memory image を保証。

---

## L.1.F. Fixed VM Exit Payload Layouts

| exit_reason | 構造 |
|---|---|
| 1 PIO | `{port:u16, width:u8, is_write:u8, count:u32, value:u64}` count=1 固定 |
| 2 MMIO | `{gpa:u64, width:u8, is_write:u8, reserved:u16+u32, value:u64}` |
| 3 External IRQ | `{vector:u32, reserved:u32}` |
| 4 EPT/NPT viol | `{gpa:u64, access_bits:u32, reserved:u32}` |
| 5 CR access | `{cr_number:u32, access_type:u32, value:u64}` |
| 6 MSR access | `{msr:u32, is_write:u32, value:u64}` |
| 7 Halt | 空 |
| 8 Shutdown | 空 |
| 9 Unclassified | `{fault_code:u32, reserved:u32, detail0:u64, detail1:u64}` |

---

## L.2. Call ID Space

| カテゴリ | 範囲 | 用途 |
|---------|------|------|
| 0x0xxx | パーティション管理 |
| 0x1xxx | メモリ管理 |
| 0x2xxx | KCI |
| 0x3xxx | KSI |
| 0x4xxx | IKS |
| 0x5xxx | SKS |
| 0x6xxx | UVS |
| 0x7xxx | bhyve VM |
| 0x8xxx | 監査・診断 |
| 0x9–0xF | 予約 |

---

## L.3. Partition Management (0x0xxx)

**0x0001 PARTITION_CREATE** `FreeBSD`
- 入力: `{kind:u16, flags:u16, vcpu_count:u32, memory_limit:u64, capability_mask:u64, image_object_id:u64}`
- 出力: `{partition_id:u64}`
- `kind=GUEST_VM/FREEBSD_HOST` は無効。trusted-service の manifest とパラメータ一致必須。→ Created
- エラー: INVALID_PARAMETER, PERMISSION_DENIED, NOT_FOUND, RESOURCE_EXHAUSTED, ALREADY_EXISTS, DEPENDENCY_UNSATISFIED, BUFFER_TOO_SMALL, MEASUREMENT_FAILED

**0x0002 PARTITION_DESTROY** `FreeBSD`
- 入力: `{partition_id:u64}` / 出力: 空
- Running は内部 quiesce 後破棄。GUEST_VM は `INVALID_PARAMETER`（VM_DESTROY を使用）→ Destroyed

**0x0003 PARTITION_GET_STATUS** `FreeBSD`
- 入力: `{partition_id:u64}` / 出力: `{state:u32, reserved:u32, measurement_epoch:u64}`

**0x0004 PARTITION_QUIESCE** `FreeBSD`
- Running/Runnable → Quiesced

**0x0005 PARTITION_RESUME** `FreeBSD`
- Quiesced → Runnable のみ（Faulted には PARTITION_RECOVER）

**0x0006 PARTITION_MEASURE** `FreeBSD`
- 入力: `{partition_id:u64, image_object_id:u64, manifest_object_id:u64}`
- 出力: `{measurement_digest_id:u64}`
- Created → Measured。UVS 事前承認必須

**0x0007 PARTITION_LOAD_IMAGE** `FreeBSD`
- 入力: `{partition_id:u64, image_object_id:u64, entry_ip:u64, initial_sp:u64}`
- Measured → Loaded。ELF64 loader 規約適用

**0x0008 PARTITION_START** `FreeBSD`
- Loaded → Runnable

**0x0009 PARTITION_RECOVER** `FreeBSD`
- 入力: `{partition_id:u64, recovery_flags:u64}`
- Faulted → Runnable（再測定+ゼロ化+復元）

**0x000A PARTITION_GET_FAULT_INFO** `FreeBSD`
- 出力: `{fault_code:u32, source_component:u32, detail0:u64, detail1:u64}`

---

## L.4. Memory Management (0x1xxx)

**0x1000 MEMORY_ALLOCATE_OBJECT** `FreeBSD`
- 入力: `{size:u64, object_flags:u32, reserved:u32}` / 出力: `{memory_object_id:u64}`

**0x1001 MEMORY_MAP** `FreeBSD`
- 入力: `{partition_id:u64, memory_object_id:u64, gpa:u64, size:u64, permissions:u32, reserved:u32}`
- machine frame の最終選択は HV

**0x1002 MEMORY_UNMAP** `FreeBSD`
- 入力: `{partition_id:u64, gpa:u64, size:u64}`

**0x1003 MEMORY_SET_PERMISSION** `信頼サービス`
- 入力: `{target_partition_id:u64, gpa:u64, size:u64, permissions:u32, reserved:u32}`
- FreeBSD は呼出不可

**0x1004 MEMORY_REGISTER_SHARED** `FreeBSD`
- 入力: `{memory_object_id:u64, size:u64, peer_partition_id:u64, peer_permissions:u32, reserved:u32}`
- 出力: `{shared_object_id:u64}`

**0x1005 MEMORY_RELEASE_OBJECT** `FreeBSD`
- map/shared なしの場合のみ解放可

**0x1006 MEMORY_UNREGISTER_SHARED** `FreeBSD`
- 関連 map/出力参照が残る間は解放不可

---

## L.5. KCI — Kernel Code Integrity (0x2xxx)

**0x2001 KCI_VERIFY_MODULE** `fbvbs.ko`
- 入力: `{module_object_id:u64, manifest_object_id:u64, generation:u64}`
- 出力: `{verdict:u32, reserved:u32}` (OK+verdict=1 のみ承認)
- 拒否は non-OK status。freebsd-module に entry_ip は不可

**0x2002 KCI_SET_WX** `fbvbs.ko`
- 入力: `{module_object_id:u64, gpa:u64, file_offset:u64, size:u64, permissions:u32, reserved:u32}`
- 検証済みコードの artifact bytes と GPA bytes を再照合し一致時のみ execute 付与

**0x2003 KCI_PIN_CR** `fbvbs.ko`
- 入力: `{cr_number:u32, reserved:u32, pin_mask:u64}`

**0x2004 KCI_INTERCEPT_MSR** `fbvbs.ko`
- 入力: `{msr_address:u32, enable:u32}`

---

## L.6. KSI — Kernel State Integrity (0x3xxx)

**0x3000 KSI_CREATE_TARGET_SET** `fbvbs.ko`
- 入力: `{target_count:u32, reserved:u32, target_object_ids[502]:u64}`
- 出力: `{target_set_id:u64}`

**0x3001 KSI_REGISTER_TIER_A** `fbvbs.ko`
- 入力: `{object_id:u64, gpa:u64, size:u64}` — 以後 write-enable 不可

**0x3002 KSI_REGISTER_TIER_B** `fbvbs.ko`
- 入力: `{object_id:u64, gpa:u64, size:u64, protection_class:u32, reserved:u32}`

**0x3003 KSI_MODIFY_TIER_B** `fbvbs.ko`
- 入力: `{object_id:u64, patch_length:u32, reserved:u32, patch[4008]:u8}`
- callsite は HV 観測 RIP で検証

**0x3004 KSI_REGISTER_POINTER** `fbvbs.ko`
- 入力: `{pointer_object_id:u64, target_set_id:u64}`

**0x3005 KSI_VALIDATE_SETUID** `fbvbs.ko`
- 入力: `{fsid:u64, fileid:u64, measured_hash[64]:u8, operation_class:u32, valid_mask:u32, ruid/euid/suid/rgid/egid/sgid:u32×6, caller_ucred_id:u64, jail_context_id:u64, mac_context_id:u64}`
- 出力: `{verdict:u32, reserved:u32}` (OK+verdict=1 のみ承認)
- ファイルなし setuid → fsid=0, fileid=0, hash=all-zero

**0x3006 KSI_ALLOCATE_UCRED** `fbvbs.ko`
- 入力: `{uid:u32, gid:u32, prison_object_id:u64, template_ucred_object_id:u64}`
- 出力: `{ucred_object_id:u64}` — 即 Tier B 保護適用

**0x3007 KSI_REPLACE_TIER_B_OBJECT** `fbvbs.ko`
- 入力: `{old_object_id:u64, new_object_id:u64, pointer_object_id:u64, replace_flags:u32, reserved:u32}`
- 大規模ルール set の原子的ページ置換用

**0x3008 KSI_UNREGISTER_OBJECT** `fbvbs.ko`
- 入力: `{object_id:u64}` — 参照残存中は解放不可

---

## L.7. IKS — Identity Key Service (0x4xxx)

**0x4001 IKS_IMPORT_KEY** `fbvbs.ko`
- 入力: `{key_material_page_gpa:u64, key_type:u32, allowed_ops:u32, key_length:u32, reserved:u32}`
- 出力: `{key_handle:u64}` — import 後に共有ページをゼロクリア

**0x4002 IKS_SIGN** `fbvbs.ko`
- 入力: `{key_handle:u64, hash_length:u32(=48), reserved:u32, hash[64]:u8}`
- 出力: `{signature_length:u32, reserved:u32, signature[4000]:u8}`

**0x4003 IKS_KEY_EXCHANGE** `fbvbs.ko`
- 出力: `{derived_secret_handle:u64}` — 生の共有秘密は返さない

**0x4004 IKS_DERIVE** `fbvbs.ko`
- 出力: `{derived_key_handle:u64}`

**0x4005 IKS_DESTROY_KEY** `fbvbs.ko`
- 二重破棄 → `NOT_FOUND`

---

## L.8. SKS — Storage Key Service (0x5xxx)

**0x5001 SKS_IMPORT_DEK** `fbvbs.ko`
- 入力: `{key_material_page_gpa:u64, volume_id:u64, key_length:u32, reserved:u32}`
- 出力: `{dek_handle:u64}`

**0x5002 SKS_DECRYPT_BATCH** `fbvbs.ko`
- 入力: `{dek_handle:u64, io_descriptor_page_gpa:u64, descriptor_count:u32, reserved:u32}`
- 出力: `{completed_count:u32, reserved:u32}` — レート制限対象

**0x5003 SKS_ENCRYPT_BATCH** `fbvbs.ko` (同上)

**0x5004 SKS_DESTROY_DEK** `fbvbs.ko` — アンマウント時

---

## L.9. UVS — Update Verification Service (0x6xxx)

**0x6001 UVS_VERIFY_MANIFEST_SET** `fbvbs.ko`
- 入力: `{root_manifest_gpa:u64, root_manifest_length:u32, manifest_count:u32, manifest_set_page_gpa:u64}`
- 出力: `{verdict:u32, failure_bitmap:u32, verified_manifest_set_id:u64}`
- freshness/freeze/mix-and-match/snapshot/role separation を評価。失敗時も同一構造で verdict=0, id=0

**0x6002 UVS_VERIFY_ARTIFACT** `fbvbs.ko`
- 入力: `{artifact_hash[64]:u8, verified_manifest_set_id:u64, manifest_object_id:u64}`
- 出力: `{verdict:u32, reserved:u32}`

**0x6003 UVS_CHECK_REVOCATION** `fbvbs.ko`
- 入力: `{object_id:u64, object_type:u32, reserved:u32}`
- 出力: `{revoked:u32, reserved:u32}` — `REVOKED` を返却 status に使用不可

---

## L.10. VM Management (0x7xxx)

**0x7001 VM_CREATE** `vmm.ko`
- 入力: `{memory_limit_bytes:u64, vcpu_count:u32, vm_flags:u32}`
- 出力: `{vm_partition_id:u64}` — caller は続けて MEASURE→LOAD→START

**0x7002 VM_DESTROY** `vmm.ko` — ゲストメモリゼロ化、IOMMU 解除

**0x7003 VM_RUN** `vmm.ko`
- 入力: `{vm_partition_id:u64, vcpu_id:u32, run_flags:u32}`
- 出力: `{exit_reason:u32, exit_length:u32, exit_payload[4032]:u8}`
- Runnable vCPU のみ。未分類 exit → fail-closed

**0x7004 VM_SET_REGISTER** `vmm.ko`
- 入力: `{vm_partition_id:u64, vcpu_id:u32, register_id:u32, value:u64}`
- Running 不可。CR3 → `PERMISSION_DENIED`

**0x7005 VM_GET_REGISTER** `vmm.ko` — CR3 は読取りのみ

**0x7006 VM_MAP_MEMORY** `vmm.ko` — Running/Faulted では無効

**0x7007 VM_INJECT_INTERRUPT** `vmm.ko`
- 入力: `{vm_partition_id:u64, vcpu_id:u32, vector:u32, delivery_mode:u32, reserved:u32}`
- Runnable/Blocked vCPU のみ

**0x7008 VM_ASSIGN_DEVICE** `vmm.ko` — IOMMU/ACS/reset 検査必須。Running/Faulted では無効

**0x7009 VM_RELEASE_DEVICE** `vmm.ko` — FLR 実行。Running では無効

**0x700A VM_GET_VCPU_STATUS** `vmm.ko`
- 出力: `{vcpu_state:u32, reserved:u32}`

---

## L.11. Audit & Diagnostics (0x8xxx)

**0x8001 AUDIT_GET_MIRROR_INFO** `fbvbs.ko`
- 出力: `{ring_gpa:u64, ring_size:u32, record_size:u32}`

**0x8002 AUDIT_GET_BOOT_ID** `fbvbs.ko`
- 出力: `{boot_id_hi:u64, boot_id_lo:u64}`

**0x8003 DIAG_GET_PARTITION_LIST** `fbvbs.ko`
- 出力: `{count:u32, reserved:u32, entries[4032]}` (最大 252 件)

**0x8004 DIAG_GET_CAPABILITIES** `fbvbs.ko`
- 出力: `{capability_bitmap0:u64, capability_bitmap1:u64}`

**0x8005 DIAG_GET_ARTIFACT_LIST** `fbvbs.ko` (最大 63 件)

**0x8006 DIAG_GET_DEVICE_LIST** `fbvbs.ko` (最大 252 件)

---

## L.12. Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | OK | 正常完了 |
| 1 | INVALID_PARAMETER | 引数不正 |
| 2 | INVALID_CALLER | 権限なし |
| 3 | PERMISSION_DENIED | ケイパビリティ不足 |
| 4 | RESOURCE_BUSY | リトライ可能 |
| 5 | NOT_SUPPORTED_ON_PLATFORM | HW 機能なし |
| 6 | MEASUREMENT_FAILED | 測定値不一致 |
| 7 | SIGNATURE_INVALID | 署名検証失敗 |
| 8 | ROLLBACK_DETECTED | 世代番号が古い |
| 9 | RETRY_LATER | 一時的不能 |
| 10 | REVOKED | 失効済み |
| 11 | GENERATION_MISMATCH | 世代番号不一致 |
| 12 | DEPENDENCY_UNSATISFIED | 依存未検証 |
| 13 | CALLSITE_REJECTED | callsite 不一致 |
| 14 | POLICY_DENIED | ポリシー違反 |
| 15 | INTERNAL_CORRUPTION | 致命的不整合 |
| 16 | INVALID_STATE | 不正状態 |
| 17 | NOT_FOUND | 対象不在 |
| 18 | ALREADY_EXISTS | 重複 |
| 19 | RESOURCE_EXHAUSTED | 資源枯渇 |
| 20 | BUFFER_TOO_SMALL | バッファ不足 |
| 21 | ABI_VERSION_UNSUPPORTED | 未対応 ABI |
| 22 | SNAPSHOT_INCONSISTENT | snapshot 不整合 |
| 23 | FRESHNESS_FAILED | freshness 失敗 |
| 24 | REPLAY_DETECTED | sequence 後退 |
| 25 | TIMEOUT | タイムアウト |

> `UNKNOWN` は内部ログ用のみ。外部 ABI 返却禁止。

---
---

*End of FBVBS v7 Specification*
