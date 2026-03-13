# FBVBS: FreeBSD Virtualization-Based Security
## Architecture, Requirements, and Assurance Specification

**対象 OS:** FreeBSD 15 系フォーク  
**対象 CPU:** x86_64  
**主対象環境:** サーバー、データセンター、高信頼ワークステーション  
**文書種別:** 要求仕様書、設計仕様書、実装契約書、検証要求書  
**日付:** 2026-03

---

# Abstract

本書は、FreeBSD カーネルが侵害された後でも、いくつかの中核的なセキュリティ不変条件を維持することを目的とした仮想化ベースの保護基盤 FBVBS の完全仕様である。ここでいう「完全仕様」とは、単なる構想説明ではなく、実装者、監査者、運用者、ならびに自動実装エージェントが、同一の設計判断、同一の責務分担、同一の保証境界、同一の検証要求に基づいて作業できる水準の文書を意味する。本書は、そのために必要な要求定義、脅威モデル、アーキテクチャ、コンポーネント境界、更新機構、監査機構、仮想化統合、暗号方針、品質基準、および残余リスクを、相互に矛盾しない形で定義する。

FBVBS は、FreeBSD に既に存在する Capsicum、Jail、MAC Framework、securelevel といった機構を「そのまま別のセキュアカーネルに移植する」ものではない。むしろ、FreeBSD を意図的に非信頼ホストとして扱い、最上位特権を持つ最小のマイクロハイパーバイザーが、コード整合性、カーネル重要状態、鍵素材、DMA 境界、および監査証跡を、FreeBSD の権限から切り離して保持する。その意味で FBVBS は、FreeBSD 自体を守る設計ではなく、FreeBSD 侵害後にも残るべき保護性質を、より狭い信頼境界の内側で維持する設計である。

本書では、従来案に含まれていた複数の不正確または過度に楽観的な主張を修正する。第一に、セキュリティイベントログを UART のみで論じることは不十分であるため、少なくとも FreeBSD ホスト侵害から独立した観測経路を持つ一次監査ログと、FreeBSD から可視であるが改ざん耐性を持たないミラーログとを明確に分離する。第二に、Intel HLAT を任意機能として扱うことは、本設計が必要とする翻訳整合性の強度と矛盾するため、Intel 実装では HLAT を必須とし、AMD 実装については NPT、ページテーブル更新トラップ、シャドウ翻訳経路、ならびに必要に応じて SEV-SNP の機構を組み合わせて、同等のセキュリティ目標を目指す構成を要求する。ただし、この同等性は実装と検証によって立証されなければならない。第三に、更新機構を `freebsd-update` に固定せず、署名付き成果物と署名付きマニフェストの検証に依存する、搬送手段非依存の更新モデルへ改める。第四に、暗号ライブラリについては、Ada/SPARK で記述された検証志向の限定的 primitive 実装候補を優先評価しつつ、それだけで TLS、SSH、IPsec のような全プロトコル群を完結させる前提を採らない現実的方針を採る。

また本書は、設計そのものと同じだけ、品質保証と検証の構造を重視する。高保証という言葉を、単に Ada/SPARK を採用したという事実だけに還元してはならない。要求からコード、証明、試験、カバレッジ、供給網、リリース成果物に至るまでの証拠構造が存在して初めて、高保証と呼ぶに値する。本書はそのための最低限の規律を明文化する。

---

# Part I. Scope, Intent, and Document Conventions

## 1. Purpose of this Document

本書の目的は、FBVBS を「実装可能であり、監査可能であり、将来的に認証対応も可能な設計仕様」として定義することである。従来の設計メモは、思想や方向性を示すには有用であったが、実装契約としては粗く、さらにいくつかの主要な点で、強い主張と実際の限界が十分に整合していなかった。たとえば、「FreeBSD カーネルが完全に侵害されてもセキュリティ機能が破壊されない」という表現は、保護不能であると既に認めているファイルディスクリプタテーブル、ソケット状態、平文処理データ、意味論的な正規コードパス悪用といった領域と衝突する。そのため本書では、保護対象を「中核不変条件」に限定し、それぞれについて必要な機構、前提条件、信頼境界、失敗条件、残余リスクを明示する。

本書は、読者として、人間の設計者だけでなく、自動コード生成エージェントも想定している。このため、アーキテクチャの説明は抽象的な理念に留めず、パーティション状態、メモリ所有権、更新成果物の形式、ハイパーコール ABI の原則、ログ記録形式、仮想マシン統合境界、テスト義務といった、実装に必要な拘束条件まで定義する。

## 2. Normative Language

本書では、要件の強さを明確に区別するため、「必須」、「推奨」、「任意」、「禁止」、「非目標」という語を用いる。「必須」は実装適合の条件であり、満たされなければ FBVBS v7 準拠を主張してはならない。「推奨」は高保証性や運用安全性の観点から強く望ましいが、代替根拠がある場合には例外が認められる。「任意」は存在してもよい拡張であり、本書の保証主張には自動的には含まれない。「禁止」は、たとえ実装可能であっても、保証境界や将来監査を著しく損ねるため採用してはならないものを指す。「非目標」は、本設計の意図的な適用外を意味する。

## 2.1. Conformance Profiles

本書では、単一の技術仕様と単一の運用成熟度を混同しないため、適合性を複数の水準で扱う。基本適合構成とは、本書に記載した機能要件、境界要件、更新要件、検証要件のうち、本仕様が中核保護性質として主張するもの、すなわち CPU ベンダごとの翻訳整合性要件、DMA 分離のための IOMMU 有効化、ならびに少なくとも一つの OOB 一次監査経路を含む必須要件を満たす構成を指す。高保証構成とは、基本適合構成に加えて、起動時検証、測定、ならびに関連する立証・監査要件を満たす構成を指す。

さらに本書では、高保証運用プロファイルという語を用いる。これは高保証構成に対して、HSM または同等の鍵保護、複数人承認、証跡保全、成果物配布統制、緊急失効手順などの運用管理要件を追加した状態を意味する。本文で「高保証構成」と記載する場合は主として技術要件を指し、「高保証運用プロファイル」と記載する場合は、それに対応する運用統制まで含むものとする。

## 2.2. Requirements Identification and Traceability

本書に含まれる要求は、実装、試験、レビュー、証拠と結び付けるため、明示的な requirements ID を持たなければならない。requirements ID は `FBVBS-REQ-XXXX` 形式とし、`XXXX` は 4 桁以上の連番とする。要求は、その本文が設計のどこに由来するかを失わないよう、章ごとにまとまった番号帯で管理する。

各 requirements ID は、少なくとも、要求本文、要求種別、根拠節、実装対象コンポーネント、検証方法、関連試験識別子、関連証拠識別子、ならびに状態を持たなければならない。要求種別は少なくとも `security`、`functional`、`interface`、`update`、`quality`、`operational` のいずれかとする。検証方法は少なくとも `analysis`、`test`、`proof`、`inspection`、`operational drill` のいずれか一つ以上の primary class を持たなければならない。requirements catalog では、これらの primary class に対する修飾付き表記、たとえば `compatibility test`、`panic-path test`、`design review`、`documentation review`、`coverage review`、`operational audit`、`crypto review board` のような詳細ラベルを用いてよい。ただし各詳細ラベルは、primary class へ機械的に正規化できなければならない。既定の正規化規則は、`* test`→`test`、`fault injection`→`test`、`fuzzing`/`fuzz campaign evidence`→`test`、`* campaign`→`test`、`* analysis`→`analysis`、`* inspection`→`inspection`、`* review`/`* audit`/`* review board`→`inspection`、`proof artifact review`→`proof`、`operational *`→`operational drill` とする。複合ラベルは語ごとに正規化して primary class 集合へ落としてよい。たとえば `boot path analysis` は `analysis`、`configuration inspection` は `inspection`、`runtime test` は `test`、`adversarial operational drill` は `operational drill`、`code review と proof artifact review` は `inspection, proof` に正規化される。これらのメタデータは、各要求行に明示してもよいし、requirements catalog 内の subsection metadata、既定値規則、識別子導出規則によって継承させてもよい。ただし、継承規則は文書内で明示され、機械的に一意に解釈できなければならない。関連試験識別子および関連証拠識別子は、個別列挙でも、`<prefix><requirement-number>` 規則でもよい。

本文中の叙述的説明は、そのままでは要求とはみなさない。実装、試験、証拠のトレーサビリティに入るのは、requirements ID が付与された要求、または固定 ABI、固定レイアウト、固定状態機械、固定カタログ、固定数値割当のように section granularity で凍結された規範付録のいずれかとする。したがって、最終版の本仕様書では、主要要求を付録の requirements catalog に列挙し、各章本文はその設計意図と意味論を説明し、固定 ABI や固定レジストリを与える付録はそれ自体が実装契約としての最終参照点となる。

## 3. Audience and Use

本書は、マイクロハイパーバイザー実装者、FreeBSD 側フロントエンド実装者、信頼サービス実装者、`bhyve` 統合担当者、更新・鍵管理担当者、セキュリティレビュー担当者、ならびに AI エージェントによる自動生成コードをレビューまたは監督する担当者を対象とする。したがって本書は、「なぜそうするのか」という設計理由と、「何をどう実装しなければならないか」という契約記述の両方を含む。

## 4. Terminology and Naming Discipline

本書では、独自用語や略語の無秩序な導入を避ける。従来案では HEKI、KDP、IKV、DKV などの略称を主要名称として扱っていたが、本書ではそれらを補助的な歴史的呼称に下げ、本文では説明的名称を使う。具体的には、Kernel Code Integrity Service、Kernel State Integrity Service、Identity Key Service、Storage Key Service という名称を用いる。必要がある場合のみ、括弧内に旧略称を一度だけ併記する。

「TCB」という語は、文脈を限定しないまま用いてはならない。本書でいう TCB は常に「ある保護性質を成立させるために信頼しなければならない最小構成要素」を意味し、単一で固定の全体 TCB を意味しない。たとえば、パーティション間メモリ分離の TCB と、秘密鍵非抽出性の TCB は一致しない。前者は主としてマイクロハイパーバイザーと CPU 仮想化機構と IOMMU に依存するが、後者には鍵を扱う信頼サービス自身と採用暗号実装が含まれる。

また、「保証」という語も限定付きで用いる。FBVBS は FreeBSD 全体の整合性や可用性を無条件に保証するものではない。本書で「保証」と表現するのは、定義済み前提条件の下で、特定の不変条件が維持されることに限る。

---

# Part II. Security Objectives, Non-Objectives, and Threat Model

## 5. Security Objectives

FBVBS の第一目標は、FreeBSD カーネル侵害後であっても、攻撃者が任意に到達してはならない資産と状態を、FreeBSD とは別の信頼境界に退避させることである。ここで重視されるのは、FreeBSD そのものを「完全に安全な OS に再構築する」ことではなく、FreeBSD が侵害されることを設計時に前提化した上で、その後も維持すべき境界を、より狭い TCB に集約することである。具体的には、次の五つの性質が中心となる。

第一に、パーティション間メモリ分離である。これは、FreeBSD と各信頼サービス、あるいはゲスト仮想マシン同士が、他方のメモリに CPU または DMA で到達できないことを意味する。第二に、カーネルコード整合性である。これは、FreeBSD カーネルコードおよび許可されたカーネルモジュールのコードページが、攻撃者により書き換えられないことを意味する。第三に、カーネル重要状態整合性である。これは、`securelevel`、Jail 制約、MAC 重要状態、資格情報構造体や主要関数テーブルなどが、定義済み更新経路を経ずに改ざんされないことを意味する。第四に、秘密鍵の非抽出性である。これは、TLS、SSH、IPsec などに用いる秘密鍵またはそれに準ずる高価値鍵が、FreeBSD メモリ空間から読み出され得ないことを意味する。第五に、監査証跡完全性である。これは、少なくとも一つの監査チャネルが FreeBSD の制御外で観測可能であり、FreeBSD 側からその記録を抹消または改ざんできないことを意味する。

これら五つの性質は互いに独立ではない。コード整合性が崩れれば、正規コードパス悪用の表面が増える。ログ完全性がなければ、保護違反が隠蔽される。鍵非抽出性が崩れれば、他の防御が残っていても認証基盤が破綻する。したがって本設計は、単一の万能機構ではなく、複数の性質を別々のサービスに分担させ、それらを最小のハイパーバイザーで強制する構造を採る。

## 6. Non-Objectives and Explicit Limits

FBVBS は、FreeBSD が処理する平文データの完全保護を目標としない。ディスク暗号鍵を FreeBSD の外へ退避させたとしても、一度ファイルシステムがマウントされ、平文が FreeBSD に返される以上、侵害後の FreeBSD はその平文を読める。したがって、Storage Key Service が提供するのは、主として未マウント時の鍵非抽出性、オフライン窃取耐性、侵害復旧時の鍵再生成不要性であり、オンライン平文保護ではない。

また、FBVBS は可用性を保護目標に含めない。FreeBSD 侵害後に攻撃者が意図的に停止、ハング、無限ループ、リソース枯渇、ログ洪水などを引き起こす可能性は残る。本設計はサービス拒否を完全には防がない。守るのは、停止してもなお残るべき境界と、停止の事実を監査に残すことである。

さらに、正規権限を持つ正規コードパスが、意味論的には望ましくない操作を実現するケースは、完全には防げない。たとえば、署名済みであり許可データベースにも載っているが、内部に脆弱性を持つ `setuid` バイナリを経由した権限昇格は、Kernel State Integrity Service による「直接改ざん防止」とは別問題である。この限界を曖昧にしてはならない。本書では、そのようなケースを「意味論的悪用」と呼び、緩和対象ではあっても完全境界ではないと位置づける。

## 7. Threat Model

本設計は、FreeBSD カーネルへの任意コード実行、または同等の権限での任意メモリ読書きが可能な攻撃者を対象とする。攻撃者はカーネルモジュールを挿入しようとするかもしれず、既存コードページを書き換えようとするかもしれず、資格情報、Jail 状態、MAC 状態、`sysent`、`vop_vector`、`cdevsw` といった高価値構造を直接改ざんしようとするかもしれない。また、Thunderbolt、USB4、PCI passthrough、SR-IOV などを通じた DMA を狙う可能性もある。さらに、ゲスト VM からホストへ逃げ出した攻撃者が、ホスト FreeBSD を踏み台に、鍵サービスやログ機構に横移動しようとする可能性も考慮する。

一方で、本設計は、SMM、悪意ある CPU マイクロコード、完全な物理侵入、電圧・クロックグリッチ、破壊的プロービングといった攻撃を対象外とする。これらを本バージョンのソフトウェア設計要求へ含めると、現実的な実装可能性が崩れ、同時に保証主張の誠実さも失われるからである。

## 8. Trust Assumptions

FBVBS は、起動時点でマイクロハイパーバイザー自身が真正なイメージであることを前提とする。このため、本書への適合を主張する構成では、DMA 分離を成立させるために IOMMU が存在し、かつ実際に有効化されていなければならない。高保証構成では、これに加えて UEFI Secure Boot 等の起動時検証、TPM 2.0 等による測定および必要に応じた証明が必要である。さらに、本書への適合を主張する構成では、BMC による host serial redirection、IPMI Serial-over-LAN、直接 UART 接続、あるいは専用ハードウェアロガーのいずれかによる一次監査ログ経路が存在し、かつ設定上も有効でなければならない。高保証構成ではその運用成立性まで立証しなければならない。単に「シリアルポートが存在する」だけでは、一次監査ログ経路が成立したとはみなさない。

---

# Part III. Overall Architecture

## 9. Architectural Thesis

FBVBS の設計思想は、モノリシックなセキュアカーネルをもう一つ導入することではない。仮にすべての保護機能を単一の大規模特権コンポーネントへ集約すれば、そのコンポーネントの欠陥がすべての保護性質を同時に無効化しうるため、保護対象面積の縮小という目的は達成されない。したがって本設計では、最上位特権に置く要素を、メモリ分離、CPU 遷移、IOMMU 制御、起動検証、一次監査ログ生成という最小の強制機構に限定し、ポリシー判断、鍵処理、更新判断は、それぞれ独立した信頼サービスへ分離する。

FreeBSD は、この構造の中で二つの重要な役割を持つ。一つは、既存アプリケーション互換性を維持するための汎用 OS としての役割であり、もう一つは、`bhyve` を含む制御プレーン、管理プレーン、デバイスモデル実装のホストとしての役割である。しかし、FreeBSD は保護対象そのものではなく、主要な保護性質に関して保護境界の外側に位置する。FreeBSD はシステム管理を行うが、最終的な書込み許可権、マッピング許可権、鍵読出権、DMA 許可権を持たない。

## 10. Logical Component Structure

システム全体は、第一層としてのマイクロハイパーバイザー、第二層としての信頼サービス群、第三層としての制限付き FreeBSD ホスト、第四層としてのゲスト仮想マシン群から成る。マイクロハイパーバイザーは CPU の最上位仮想化特権で動作し、各信頼サービスは独立したパーティション、すなわち独立した第二レベルページング構造と独立した CPU 実行状態を持つ。FreeBSD ホストは、これらとは別のパーティションとして動作し、通常のカーネル、ユーザーランド、`bhyve` デバイスモデル、`vmm` フロントエンド、ならびに FBVBS フロントエンドモジュールを含む。

信頼サービスは、本書では少なくとも五つに分ける。第一は Kernel Code Integrity Service であり、カーネルコードページとモジュール実行の整合性を扱う。第二は Kernel State Integrity Service であり、重要データ構造の更新制御と `setuid` 検証を扱う。第三は Identity Key Service であり、身元鍵の import、署名、鍵交換などを担当する。第四は Storage Key Service であり、ディスク鍵やアンロック素材を扱う。第五は Update Verification Service であり、起動前・ロード前に成果物とマニフェストの真正性、失効、世代番号、依存関係整合性を検証する。必要に応じて Audit Relay Service を追加し、帯域外ログと帯域内ミラーの整流と集約を担当させてもよいが、その場合も一次監査ログの一次生成主体はマイクロハイパーバイザー自身でなければならない。

ABI v1 の service identity は `SERVICE_KIND_KCI`、`SERVICE_KIND_KSI`、`SERVICE_KIND_IKS`、`SERVICE_KIND_SKS`、`SERVICE_KIND_UVS` の五つに限定する。trusted-service partition の `service_kind` は `PARTITION_MEASURE` 成功時に当該 manifest の `service_kind` から確定し、以後不変とする。測定前の trusted-service partition は `SERVICE_KIND_NONE` として診断表示される。Audit Relay Service は ABI v1 の service kind には含めず、実装する場合は内部拡張とし、外部 ABI 適合主張から除外する。`DIAG_GET_PARTITION_LIST` ではそのような内部拡張 partition を列挙してはならない。

## 11. Why the Host Must Be Deprivileged

FreeBSD を非信頼とする設計は、保護境界の一貫性を維持するための前提である。もし FreeBSD が鍵サービスのメモリを読み取ることができ、更新機構の承認者であり、同時にログ機構の唯一の観測者でもあるなら、攻撃者が FreeBSD を奪取した時点で FBVBS の設計目的は失われる。このため、FreeBSD に残す権限は、管理、利便、互換性に必要な最小限に留められる。FreeBSD はパーティション生成を要求できるが、自らが自由に第二レベルページテーブルを変更してはならない。FreeBSD はログミラーを読めるが、一次監査ログを書き換えてはならない。FreeBSD は鍵操作を要求できるが、鍵素材を受け取ってはならない。これが deprivileged host という概念の意味である。

---

# Part IV. Boot, Measurement, and Logging

## 12. Boot Sequence and Root of Trust

FBVBS は、起動連鎖の早い段階でマイクロハイパーバイザーをロードしなければならない。FreeBSD が先に Intel VMX root operation または AMD SVM のホスト側仮想化制御権を取得する構成は、本設計と両立しない。正しい順序は、ファームウェアがマイクロハイパーバイザーイメージを検証し、そのイメージが自身のコード、静的データ、初期設定、ならびに信頼サービスイメージのマニフェストを読み込み、測定し、許可されたものだけを実行可能にした後で、FreeBSD パーティションを起動する、というものである。ABI v1 では、FreeBSD より前に自動起動される trusted-service partition の生成入力は manifest により凍結されなければならない。少なくとも `service_kind`, `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp`, `autostart` は manifest から決定され、実装依存の既定値に委ねてはならない。

この起動時に検証されるべきものは、単なる署名だけではない。署名が有効でも、旧版で脆弱なコンポーネントへのロールバックを許せば意味がない。そのため本設計では、各成果物に単調増加世代番号またはそれに準ずる security epoch を持たせ、TPM NV 領域や同等の改ざん困難な version store を用いてロールバックを検出する方式を採用してよい。ただし、TPM ベース実装には NV 更新回数、運用手順、復旧手順の制約があるため、実装時に別途設計しなければならない。ハイパーバイザーは、自身より古い不許可世代のイメージをロードしてはならない。

## 13. Authoritative Out-of-Band Logging

本書でいう一次監査ログは、少なくとも FreeBSD ホストが侵害された場合でも観測・保全できる監査チャネルを意味する。この要件を満たすため、本設計では、ログチャネルを二つに分割する。第一のチャネルは、FreeBSD ホストから独立した OOB 観測チャネルであり、マイクロハイパーバイザーから直接出力される。このチャネルは、UART、BMC の host serial redirection、IPMI Serial-over-LAN、または専用ハードウェアロガーによって観測される。第二のチャネルは、FreeBSD から読めるが一次監査根拠とはならないミラーチャネルである。

ここで明確にしなければならないのは、「シリアルポートから本当に取得できるのか」という問いに対して、成立条件付きでしか肯定できないという事実である。実機サーバーでは、BMC がホスト UART を捕捉し、SOL やシリアルリダイレクションとして外部から参照できる場合が多い。また、古典的な RS-232 接続やシリアルコンソールサーバーも現実的な選択肢である。しかし、一般的なデスクトップや一部ノート PC のように、物理 UART が露出しておらず、BMC もなく、ファームウェア設定でもリダイレクトが無効な環境では、同一の主張は成立しない。したがって、本書では「一次監査ログは OOB 経路が提供される構成において取得可能である」と記述し、「常にシリアルから取得できる」と記述してはならない。

一次監査ログの記録形式は、テキストではなく、長さ付きの構造化バイナリレコードを基本とする。各レコードは少なくとも、単調増加シーケンス番号、ブート識別子、CPU 識別子、ソースコンポーネント識別子、重大度、イベントコード、ペイロード長、ペイロード、CRC32C を含まなければならない。CPU 識別子は固定ヘッダで明示してもよいし、同等の意味を持つ `timestamp_counter` と payload 先頭の固定サブヘッダを組み合わせて表現してもよいが、ABI v1 では固定ヘッダに含める。CRC32C は偶発的破損の検出に用いるものであり、単独で改ざん耐性を与えるものではない。より強い改ざん検知を要求する場合は、受信側での署名、HMAC、または外部アンカーへの連結を追加しなければならない。帯域が限られるため、ペイロードは固定長または上限付き可変長とし、巨大な文字列を直接流してはならない。人間可読性が必要な場合は、OOB 受信側ツールがイベントコードをデコードすればよい。

## 14. In-Band Mirror Logging for FreeBSD

一方、運用上は FreeBSD からもイベントを観測できなければならない。障害調査、運用監視、ローカル開発、テスト自動化の多くは、FreeBSD から `dmesg`、`syslog`、監視デーモン、あるいは専用ツールでログを参照できることを前提としている。そのためマイクロハイパーバイザーは、読み取り専用の共有リングバッファを FreeBSD に公開し、FreeBSD 側は `fbvbslogd` またはカーネルラッパーを通じてそれを取り込む。

ただし、このリングバッファはあくまでミラーであり、改ざん耐性を持たない。FreeBSD カーネルが侵害された場合、ログの読取り妨害、コピー改ざん、`syslog` への反映抑止などは起こりうる。このため、本書では FreeBSD 側のログを「non-authoritative mirror」と明示し、監査証跡の唯一の根拠としては用いない。

リングバッファのメモリ構造は固定しなければならない。先頭にはバージョン、総サイズ、レコードサイズ、書込みオフセット、読取り可能最大シーケンス番号、ブート識別子を配置し、その後ろに固定長スロットの配列を置く。ABI v1 の固定ヘッダレイアウトは Appendix C.1 に定義する。FreeBSD 側はこのバッファを読み取るだけであり、書込みポインタやシーケンス番号を更新してはならない。マイクロハイパーバイザーは、FreeBSD 側からの書込みを第二レベルページングで物理的に拒否する。

## 15. Early Boot and Panic-Time Caveats

ログに関して最も注意を要するのは、障害や異常が発生した局面ほど記録欠落が生じやすいことである。early boot と panic はその典型である。early boot 時には、ファームウェア、ブートローダ、マイクロハイパーバイザー、FreeBSD カーネル初期化の各段階で利用可能な出力経路が異なる場合がある。また panic 時には、割込み状態、ロック状態、ポーリング I/O の可否、リングバッファの整合性といった条件が悪化する。そのため、本書では「early boot と panic でもログは常に完全に記録される」と主張してはならない。代わりに、これらは設計上 best effort であり、高保証構成ではファームウェア、ブートローダ、マイクロハイパーバイザー、および FreeBSD の各段階において、同一の OOB 観測チェーンまたはそれと同等の経路が構成されていることを要求する。

---

# Part V. Microhypervisor Design

## 16. Scope of the Microhypervisor

マイクロハイパーバイザーは、FBVBS の最上位特権コンポーネントであるが、同時に最小でなければならない。小規模性は美的要請ではなく、監査可能性および証明可能性に直接関係する。したがって、その責務は、パーティション生成と破棄、CPU 状態遷移、第二レベルページング管理、IOMMU ドメイン制御、限定された CPU 制御ビットと MSR の強制、起動検証、ならびに一次監査ログ生成に限定される。暗号の高水準ポリシー、鍵ライフサイクル、ファイルシステム解釈、署名ポリシーの意味論、デバイス個別の挙動、`bhyve` デバイスモデルそのものは、マイクロハイパーバイザーの責務から除外する。

この分離は、後段の信頼サービスを弱くするものではない。高水準ロジックをマイクロハイパーバイザーへ集約するほど、証明対象とレビュー対象が肥大化し、最終的に信頼根拠が不明瞭となる。本設計では、ポリシーを分離することにより、障害時影響も局所化する。たとえば、Kernel State Integrity Service が異常停止しても、既に設定済みの read-only 保護そのものはマイクロハイパーバイザーが維持できる。その結果、新規変更機能は停止しうるが、既存保護が一斉に喪失する事態は回避される。

## 17. Implementation Language and Proof Boundary

FBVBS の一次実装経路は Ada 2022 と SPARK 2014 とする。これは単に C/C++ を避けるためではない。SPARK は、契約、サブタイプ制約、データ依存性、情報流れを静的に扱いやすくし、少なくとも実行時例外不在と一部の機能的性質を機械的に証明できる。マイクロハイパーバイザー本体、パーティション管理、ケイパビリティモデル、共有バッファ検証、第二レベルページテーブル操作ロジック、イベントルーティングの中核は SPARK 化されなければならない。本仕様では、最終実装へ収束しない「暫定フェーズ専用実装」や「使い捨て骨組み」を適合経路として認めない。

一方で、VMXON、VMLAUNCH、VMRESUME、VMPTRLD、`vmrun`、VMCB 制御といった低レベル命令ラッパー、初期ブートコード、コンテキスト保存の一部にはアセンブリが不可避である。また、FreeBSD フロントエンドや一部管理プレーンでは Rust を用いる合理性がある。本書では、それらを禁止しないが、明確に証明境界の外に置く。さらに、やむを得ず C を TCB 境界内へ残す場合でも、それは Ada/SPARK 実装へ収束する移行コードまたは極小のハードウェア境界に限られなければならない。その例外は「境界が明確であること」「安全性契約が文章化されていること」「MISRA C:2023 または同等の厳格サブセットと CERT C の両方に適合すること」「未定義動作不在と関数契約を静的解析または証明系で立証すること」「独立レビュー、カバレッジ、fault injection を通ること」を必須条件とする。

## 18. Partition Model and State Machine

各パーティションは、識別子、所有メモリ集合、第二レベルページング構造、CPU 実行状態、受信可能メッセージポート集合、送信可能ポート集合、リソース上限、ブート測定値、現在状態から成る。状態は、少なくとも `Created`、`Measured`、`Loaded`、`Runnable`、`Running`、`Quiesced`、`Faulted`、`Destroyed` を持つ。`Created` はメタデータのみ確保された状態を意味し、`Measured` はイメージ検証が完了した状態を意味し、`Loaded` はコードと初期データが配置済みである状態を意味し、`Runnable` は CPU 実行可能だがまだ未実行である状態、`Running` は実行中、`Quiesced` は一時停止中、`Faulted` は異常停止検出後、`Destroyed` は資源回収済みを意味する。

遷移は厳密に定義されなければならない。`Created` から `Loaded` へ直接進んではならず、必ず測定と署名検証を経由する。`Faulted` からの回復では、まず `Runnable` へ復帰可能状態を再構築し、その後に通常スケジューリングで `Running` へ進む。したがって、回復呼出そのものの事後状態は `Runnable` とする。回復には再測定、ゼロ化、必要であれば永続状態復元を伴う。`Destroyed` へ遷移したパーティションのメモリは、再割当の前にゼロ化されなければならない。これらは単なる実装上の配慮ではなく、監査可能なライフサイクル契約である。

### 18.1. Legal Partition Transitions

凍結済み ABI では、パーティション状態遷移は次の表に限定される。表に存在しない遷移を要求した呼出は `INVALID_STATE` で失敗しなければならない。

| 現在状態 | トリガ | 次状態 | 必須条件 | 備考 |
|---|---|---|---|---|
| なし | `PARTITION_CREATE` または `VM_CREATE` | `Created` | 資源確保成功 | `VM_CREATE` は guest VM のみ |
| `Created` | `PARTITION_MEASURE` | `Measured` | 指定成果物が検証済み | イメージとマニフェストの測定値を記録 |
| `Measured` | `PARTITION_LOAD_IMAGE` | `Loaded` | ロード先メモリ確保成功 | コードと初期データを配置 |
| `Loaded` | `PARTITION_START` | `Runnable` | 初期 CPU 状態構築成功 | 実行可能だが未実行 |
| `Runnable` | スケジューラ選択 | `Running` | vCPU 割当可能 | マイクロハイパーバイザー内部遷移 |
| `Running`/`Runnable` | `PARTITION_QUIESCE` | `Quiesced` | vCPU 停止成功または未実行化成功 | 実行一時停止または実行開始前停止 |
| `Quiesced` | `PARTITION_RESUME` | `Runnable` | 中断条件消滅 | `Faulted` からの回復には使わない |
| `Running`/`Runnable`/`Quiesced` | 致命障害検出 | `Faulted` | なし | 一次監査ログ必須 |
| `Faulted` | `PARTITION_RECOVER` | `Runnable` | 再測定、ゼロ化、必要状態復元成功 | 回復失敗時は `Faulted` 維持 |
| `Created`/`Measured`/`Loaded`/`Runnable`/`Running`/`Quiesced`/`Faulted` | `PARTITION_DESTROY` | `Destroyed` | 資源回収とゼロ化成功 | `Running` からの破棄要求は内部的に quiesce 後に処理 |

`Destroyed` は終端状態であり、`PARTITION_CREATE` 以外の呼出で再利用してはならない。`PARTITION_GET_STATUS` と `PARTITION_GET_FAULT_INFO` は状態遷移を起こしてはならない。`PARTITION_DESTROY` または `VM_DESTROY` 成功後、当該 partition ID は tombstone として保持され、ABI v1 では再起動まで `PARTITION_GET_STATUS` に対して `Destroyed` を返さなければならない。destroy 済み ID を他 call に用いた場合は `INVALID_STATE` とする。`PARTITION_KIND_GUEST_VM` に対しては `PARTITION_DESTROY` を用いてはならず、`VM_DESTROY` のみを許可する。

複数 vCPU を持つ VM partition では、外部可視の partition `state` は集約規則で決定する。少なくとも一つの vCPU が `Running` なら partition state は `Running`、それ以外で少なくとも一つの vCPU が `Runnable` または `Blocked` なら partition state は `Runnable`、`PARTITION_QUIESCE` 成功後に全 vCPU が停止状態で保持されている間は `Quiesced`、任意の vCPU fault により ABI v1 の VM-wide fault rule が発動した場合は `Faulted` とする。

初回 `Running` への遷移時の CPU 初期状態は凍結する。通常の partition entry では、`RIP` は `PARTITION_LOAD_IMAGE` の `entry_ip` で決定される。ABI v1 では `entry_ip=0` の場合、manifest 内 `entry_ip` を用いる。`entry_ip!=0` の場合、その値は manifest 内 `entry_ip` と一致しなければならず、不一致は `MEASUREMENT_FAILED` とする。`RSP` は同 call で指定した `initial_sp` とする。`RFLAGS` は `0x0000000000000002`、`CR0` は `0x80010033`、`CR4` は `0x000006f0`、汎用レジスタは `RIP` と `RSP` を除き 0、`XMM/YMM/ZMM` 状態は 0、`FS.base`/`GS.base` は 0、セグメントは flat 64-bit model、`CR3` は当該パーティションの第二レベル変換と整合する hypervisor 管理値とする。`RSI` のみ例外として bootstrap page GPA を保持してよい。caller はこれ以外の初期 CPU 状態に依存してはならない。

## 19. Capability and Ownership Model

本設計では、可否判定をソフトウェア上の条件分岐のみに委ねず、権限オブジェクトとハードウェアマッピングによって表現する。各パーティションは、自身のメモリに対する読書き実行権、特定ポートへの送信権、特定共有バッファのマップ権、特定操作の要求権を、明示的な capability として保持する。ここで本質的なのは、パーティション自身が capability を生成または拡張してはならないことである。capability は、マイクロハイパーバイザーが、起動時マニフェストまたは管理要求に基づき付与し、取り消し、監査する。boot 時に自動生成される trusted-service partition については、capability 初期値は対応 manifest の `capability_mask` で一意に決まり、autostart の有無は `autostart` bool で決定しなければならない。

メモリ所有権も同様に厳密でなければならない。ある物理ページは、同時に二つの信頼サービスの可変領域であってはならない。共有が必要な場合は、明示的な共有ページとして登録し、そのページごとに片方向または両方向のアクセス権を定義する。FreeBSD との共有は原則として読み取り専用ミラーか、一時的な入出力バッファに限定される。鍵サービスの内部ページ、署名検証用一時バッファ、更新マニフェスト検証ページなどを、FreeBSD が直接マップすることは禁止される。

## 20. Hypercall ABI Principles

ハイパーコール ABI は、人間が読む設計文書の中でも特に曖昧さを許してはならない部分である。各呼出は、呼出番号、呼出元パーティション、引数レジスタ、共有引数ページの物理アドレス、共有ページ長、同期呼出か非同期通知か、返却値、エラーコードを厳密に定義しなければならない。本文書では、呼出命令そのものは Intel では `VMCALL`、AMD では `VMMCALL` となるが、論理 ABI としては同一視する。

本バージョンでは、各 vCPU に対し一枚の shared command page を用意する方式を標準とする。マイクロハイパーバイザーは、このページが本当に呼出元パーティションに割り当てられた許可済み共有ページであること、長さが上限内であること、未使用フィールドがゼロ化されていること、パディング領域に秘密情報が残っていないことを検証した後にのみ要求を実行する。結果は同一ページまたは別の許可済み出力ページへ書き戻す。FBVBS ABI v1 における Appendix L の全呼出は同期呼出であり、非同期通知専用 call は定義しない。

各 caller パーティションは、起動時または `PARTITION_START` 成功時に、各 vCPU に対して 1 枚の command page を自動的に割り当てられる。この割当はマイクロハイパーバイザーが行い、page の GPA は Appendix D.4 の固定 bootstrap metadata page で公開しなければならない。したがって command page 数は常にその partition の `vcpu_count` と一致する。boot 時に自動起動される trusted-service partition では、この `vcpu_count` は manifest から決定されなければならない。別出力ページを用いる場合は、caller は `MEMORY_REGISTER_SHARED` で `peer_partition_id=0`（マイクロハイパーバイザー予約 ID）として writable shared object を登録した後、その GPA を `output_page_gpa` に設定する。サービス partition への応答転送が必要な場合も、最終的な output page 書込み主体はマイクロハイパーバイザーとする。

エラーコードは、人間可読文字列ではなく数値コードで返却され、FreeBSD 側または運用ツールが変換する。凍結済み ABI では、少なくとも `OK`、`INVALID_PARAMETER`、`INVALID_CALLER`、`PERMISSION_DENIED`、`RESOURCE_BUSY`、`NOT_SUPPORTED_ON_PLATFORM`、`MEASUREMENT_FAILED`、`SIGNATURE_INVALID`、`ROLLBACK_DETECTED`、`RETRY_LATER`、`INTERNAL_CORRUPTION`、`REVOKED`、`GENERATION_MISMATCH`、`DEPENDENCY_UNSATISFIED`、`CALLSITE_REJECTED`、`POLICY_DENIED`、`INVALID_STATE`、`NOT_FOUND`、`ALREADY_EXISTS`、`RESOURCE_EXHAUSTED`、`BUFFER_TOO_SMALL`、`ABI_VERSION_UNSUPPORTED`、`SNAPSHOT_INCONSISTENT`、`FRESHNESS_FAILED`、`REPLAY_DETECTED`、`TIMEOUT` を持たなければならない。安定外部 ABI では `UNKNOWN` を返してはならず、未分類失敗は必ず定義済みコードに写像しなければならない。

### 20.1. Trap and Register Convention

Intel の `VMCALL` と AMD の `VMMCALL` は、次の共通レジスタ規約を用いる。

| レジスタ | 呼出時 | 復帰時 |
|---|---|---|
| `RAX` | 共有コマンドページの guest-physical address | `status_code` |
| `RBX` | 0 でなければならない | `command_state` |
| `RCX` | 0 でなければならない | `actual_output_length` |
| `RDX` | 0 でなければならない | 0 |

`RAX` に渡される GPA は 4096 バイト境界にアラインされなければならない。`RBX`、`RCX`、`RDX` に非ゼロ値を入れた呼出は `INVALID_PARAMETER` として失敗しなければならない。`RAX` から `RDX` 以外の汎用レジスタは論理 ABI 上保存されるものとして扱う。呼出側は condition flags の値に依存してはならない。

### 20.2. Command Page Ownership and State Machine

各 vCPU は自身に割り当てられた command page を一枚だけ持ち、同時に一件を超える in-flight 要求を持ってはならない。command page の状態は `EMPTY`、`READY`、`EXECUTING`、`COMPLETED`、`FAILED` の五つに固定する。呼出側は `EMPTY`、`COMPLETED`、`FAILED` のいずれかの状態でのみ新要求を書き込んで `READY` に遷移させてよい。マイクロハイパーバイザーは trap 受理時に `READY` を `EXECUTING` に変更し、完了時に `COMPLETED` または `FAILED` に変更する。`EXECUTING` 中に同一 page で再度 trap を発行した場合は `RESOURCE_BUSY` で失敗しなければならない。

### 20.3. Caller Identity, Sequence, and Nonce

呼出元パーティション ID と呼出時 RIP は、caller が申告する値ではなく、マイクロハイパーバイザーが現在の vCPU 実行文脈から観測する値を正とする。したがって、ABI v1 の command page には caller-supplied partition identifier を置かない。callsite 検証を必要とするサービスは、マイクロハイパーバイザーが観測した RIP を内部メタデータとして受け取り、caller body 内の任意値を信頼してはならない。ABI v1 における許可 callsite table は、対応する `freebsd-kernel` または `freebsd-module` manifest に含まれる `caller_class` と `allowed_callsites` metadata からのみ構築しなければならない。`allowed_callsites` は load base からのオフセット列で記述され、マイクロハイパーバイザーは load 完了後に KASLR 再配置後の実アドレスへ機械的に変換して table を生成する。KLD 更新時には、新しい verified artifact と manifest から table を原子的に再計算し、旧 table を置換しなければならない。

`caller_sequence` は vCPU ごとの単調増加 64 ビット整数であり、同一 boot 内で後退または再利用してはならない。前回受理済み値以下の sequence を持つ呼出は `REPLAY_DETECTED` とする。`caller_nonce` は caller が監査相関のために与える 64 ビット値であり、認可判断には用いない。

### 20.4. Output and Buffer Rules

Appendix L の各 call は同期完了であり、復帰時には `command_state` が必ず `COMPLETED` または `FAILED` のいずれかでなければならない。応答本文は、`FBVBS_CMD_FLAG_SEPARATE_OUTPUT` が立っていない場合は同一 command page の `body` に書き込まれ、立っている場合は `output_page_gpa` が指す別共有ページに書き込まれる。別出力ページは caller が事前に登録した writable shared object に対応していなければならない。必要出力長が `output_length_max` を超える場合は `BUFFER_TOO_SMALL` とし、`actual_output_length` に必要最小長を返さなければならない。

### 20.5. Call Modes and Reserved Bits

ABI v1 では、`flags` のうち `FBVBS_CMD_FLAG_SEPARATE_OUTPUT` 以外の全ビットは予約とし、ゼロでなければならない。予約ビットが立っている要求は `INVALID_PARAMETER` として拒否しなければならない。非同期呼出、割込み駆動 completion、複数ページ scatter-gather 出力、caller-supplied partition identity は ABI v1 の範囲外とする。

## 21. CPU Control and Register Pinning

本設計では、FreeBSD が自らセキュリティに重要な CPU 制御ビットを解除できてはならない。少なくとも CR0.WP、CR4.SMEP、CR4.SMAP、CET 利用時の関連ビット、ならびに syscall エントリや一部の重要 MSR は、マイクロハイパーバイザーがインターセプトし、許可された値へピン留めする。これは防御の中心ではなく補助であるが、攻撃者が簡単に既存の CPU セーフティネットを外すことを防ぐ上で重要である。

パーティション遷移時には、汎用レジスタ、デバッグレジスタ、ベクタ状態、モデル固有の機微状態を必要に応じてクリアしなければならない。これは情報漏洩防止だけでなく、遷移境界を明示するためでもある。さらに、投機実行に関するマイクロアーキテクチャ状態のクリア、たとえば IBPB、VERW、必要な flush 類についても、構成依存の有効化方針を持たなければならない。

---

# Part VI. Kernel Translation Integrity Across Intel and AMD

## 22. Why Translation Integrity Is Mandatory

コードページを second-stage paging で read-only にしても、攻撃者がカーネル仮想アドレスに対応する物理ページそのものを差し替えられるなら、その保護は根本的に破られる。すなわち、コード整合性のためには、コードページに対する書込み禁止だけでなく、その仮想アドレスが「どの物理ページを指しているか」という翻訳整合性も同時に守らなければならない。従来案で HLAT を任意機能として扱っていた点は、この観点から不十分であった。本書では、Kernel Translation Integrity をコード整合性と同格の必須要件と位置づける。

## 23. Intel Path: HLAT Is Mandatory

Intel 実装においては、HLAT を必須とする。その理由は、Intel にはハイパーバイザー管理の線形アドレス変換機構として HLAT が存在し、これを用いることで、カーネルコード領域のアドレス解決をゲストの通常ページテーブル支配から切り離せるからである。したがって、Intel 実装が HLAT 非使用である場合、その実装は本書への適合を名乗ってはならない。

HLAT の存在は、Intel が AMD より本質的に「安全」であることを意味しない。ここで言えるのは、少なくともこの問題領域、すなわち「カーネル仮想アドレス解決をハイパーバイザー側でより直接に管理する」という目的において、Intel には公開された専用機構がある、ということである。その差を過大化して「Intel は AMD よりセキュリティ機能がある」と単純化するのは正確ではない。AMD には AMD なりの強み、たとえば SEV-SNP 系の保護様式が存在する。ただし、本設計が必要とする性質に関しては、Intel の HLAT は有利な出発点である。

## 24. AMD Path: Equivalent Objective Through Composite Mechanisms

AMD には、公開仕様上、HLAT と一対一に対応する単一機構は存在しない。したがって、本設計は AMD について「HLAT 相当がある」と記述してはならない。その代わり、本書は AMD 実装に対し、「NPT、ページテーブル更新トラップ、シャドウ翻訳経路、TLB 無効化監視、ならびに必要に応じて SEV-SNP の補助機構を組み合わせ、同一のセキュリティ目標を目指すこと」を要求する。これは設計要件であり、AMD ハードウェアが HLAT と等価な単一保証を与えるという意味ではない。

具体的には、AMD 実装は次を満たさなければならない。第一に、カーネルページテーブルページに対応する guest-physical page は NPT によって write-protect され、更新は VMM の fault handling 経路でのみ許可されなければならない。第二に、CR3 更新、ページテーブルエントリ更新、`INVLPG` 相当の無効化操作、NPT fault、ゲスト page fault の相互関係が、ハイパーバイザー側の翻訳整合モデルと同期されなければならない。第三に、カーネルコード領域に対応する翻訳については、ハイパーバイザーが所有するシャドウ翻訳経路またはそれと実質的に等価な管理構造を維持し、FreeBSD がその対応関係を任意に差し替えられないようにしなければならない。第四に、SEV-SNP を用いる構成では、RMP と VMPL を追加の分離・整合性強化として利用してよいが、それだけで HLAT と同一の保証様式が得られると主張してはならない。

## 25. Conformance Rule for AMD

本書は、AMD を「低保証のフォールバック」として扱わない。AMD 実装も Intel 実装と同格のセキュリティ目標を負う。ただし、その同格性は宣言のみでは成立しない。したがって、AMD 実装は、PFN 差し替え、PTE 改ざん、シャドウ同期 race、TLB invalidate race、複数コア同時更新といったテスト群を通じ、同等のセキュリティ目標が実際に満たされることを立証しなければならない。もしこの立証が不足しているなら、その実装は「FBVBS v7 完全適合」と表示してはならない。これは AMD を格下げするためではなく、根拠を欠く同格主張を禁止するための規則である。

---

# Part VII. Trusted Services

## 26. Kernel Code Integrity Service

Kernel Code Integrity Service は、旧来案で HEKI と呼ばれていたコンポーネントに対応する。本書では、このサービスの責務を三つに限定する。第一は、FreeBSD カーネルコードページおよび許可されたモジュールコードページの W^X 維持である。第二は、モジュールロード時の署名、失効、世代番号の検証である。第三は、Kernel Translation Integrity と整合する形で、コードが期待した物理ページに結び付いていることの確認である。

このサービスは、未署名モジュールを単に「警告付きで許可」してはならない。既定方針は不許可でなければならず、明示的に許可された署名、許可された世代番号、許可された対象プラットフォームに一致する場合に限り、コードページへ execute 権限が付与される。ABI v1 では、単に「ある module artifact が承認された」という事実だけでは不十分であり、execute 権限付与時に、対象 GPA 範囲の bytes が承認済み module artifact の対応範囲と一致することを KCI 側で再照合しなければならない。署名鍵は、Update Verification Service と共通の信頼根に属してよいが、鍵用途識別、失効処理、監査経路は区別されなければならない。

ここで注意すべきは、コード整合性が成立しても、既存コード断片の悪用、すなわち ROP や JOP が自動的に消滅するわけではないことである。本書は、この点を明示する。Kernel Code Integrity Service は、書込み型攻撃に対して強い境界を提供するが、制御フロー悪用に対しては CET、Shadow Stack、IBT、SMEP/SMAP のような補助機構を併用しなければならない。

## 27. Kernel State Integrity Service

Kernel State Integrity Service は、旧来案の KDP をより厳密に再定義したものである。本サービスの目的は、「重要な状態をすべて read-only にする」ことではない。むしろ、重要状態を三層に分類し、それぞれに適した更新規約を与えることである。第一層は、起動後不変であるべき状態であり、`sysent`、IDT、GDT、主要ディスパッチテーブル、関数テーブル、カーネルの読み取り専用定数などがこれに含まれる。第二層は、更新は必要だが、更新主体と更新条件を厳密に限定すべき状態であり、`ucred`、`prison`、`securelevel`、MAC 重要状態、Capsicum 関連状態、ファイアウォールの高価値ルールポインタなどがここに属する。第三層は、高頻度かつ広範囲に変化するため、本バージョンで完全保護対象にしない状態であり、一般 fd テーブル、一般ソケット状態、経路表、一般ネットワークキューなどが該当する。

本サービスが提供する最大の価値は、「任意アドレス書込み」や「単純なポインタ差し替え」に対して物理的な障壁を与えることである。たとえば `ucred` を read-only にしても、それを参照する `td->td_ucred` が自由に別アドレスへ差し替えられれば意味がない。したがって、本サービスはデータ本体だけでなく、参照ポインタの正当性も検証しなければならない。許可されるポインタ差し替えは、あらかじめ登録された正規オブジェクト集合の中への遷移に限られる。

一方で、本サービスが守れないものも明確にしなければならない。意味論的に正しいように見える API 呼出を悪用する攻撃、署名済みだが脆弱な `setuid` バイナリ経由の権限昇格、高頻度の Tier C 領域を経由したデータ窃取、FreeBSD が既に扱っている平文データの読取りは、本サービス単独では止められない。この限界を隠したまま「Kernel Data Protection」という名称だけを前面に出すと、文書が過大主張になる。本書ではそのような表現を避ける。

### 27.1 Controlled Update Path and Atomicity

Tier B に属する状態を更新する場合、本サービスは、まず自パーティション内の shadow copy に対して検証付き変更を行い、その後に最小時間だけ対象ページを書込み可能にし、コピーし戻した上で即座に read-only に戻す。複数 CPU コアが同時に当該ページへアクセスできる場合は、マイクロハイパーバイザーがそのページに対する他コア書込みを一時的に停止しなければならない。大きなルール集合やオブジェクト群については、ページ内更新ではなく、新ページを構成してポインタを原子的に付け替える方式を優先する。この方式は、競合窓を短くし、監査しやすくする。

### 27.2 Setuid and Privilege Elevation Validation

意味論的悪用に対する緩和として、本サービスは、少なくとも `execve(2)`、`fexecve(2)`、`setuid(2)` 系、および対応する `gid` 系呼出に関わる特権上昇イベントを検査する。ここで重視されるのは、データベース配布経路を `freebsd-update` に固定しないことである。許可データベースは、署名付き成果物として配布され、署名付きマニフェストにより真正性、対象プラットフォーム、依存版、世代番号が検証される限り、`freebsd-update`、`pkg`、オフライン媒体、構成管理システムのいずれの搬送手段でもよい。信頼判断は搬送経路ではなく、成果物そのものに対して行われる。

`execve` または `fexecve` により `setuid` ビットを持つバイナリが実行される場合、あるいは `setuid(2)` 系呼出によって資格情報変更が要求される場合、FreeBSD 側フロントエンドは、その vnode または `fsid+fileid` に基づくファイル識別子、測定ハッシュ、要求される資格情報遷移、呼出元資格情報、関連 Jail または MAC コンテキストを、本サービスへ送る。ABI v1 では、この資格情報遷移は単一 UID/GID 値ではなく、操作種別と `ruid/euid/suid/rgid/egid/sgid` の完全な要求後状態として表現しなければならない。パス情報は監査補助として扱ってよいが、主たる認可キーとして用いてはならない。本サービスは許可データベースと照合し、許可されたバイナリまたは識別子、許可されたハッシュ、許可された遷移であることを確認した上で、資格情報更新を承認する。ハッシュ不一致、世代番号不一致、署名失効、識別子不一致、権限遷移不一致があれば拒否される。これにより、典型的な exec 起点の単純昇格経路は抑制される。ただし、既に取得済みの特権付きファイル記述子の継承や、それに類する権限持越しの問題は別途扱わなければならない。

## 28. Identity Key Service

Identity Key Service は、TLS、SSH、IPsec、署名検証補助などに使う秘密鍵を、FreeBSD から見えないメモリへ格納し、サービス内でのみ暗号操作を完結させる。本サービスの核心は、単なる暗号 API の提供ではなく、「鍵素材がサービス境界を越えて出ない」という非抽出性である。したがって API は、`IMPORT_KEY`、`SIGN`、`KEY_EXCHANGE`、`DERIVE`、`DESTROY` など、狭く限定された操作集合を持つべきであり、鍵を外部へ返却する呼出は存在してはならない。

暗号ライブラリ方針については、過度な楽観も過度な悲観も適切でない。公開情報に基づく限り、Ada/SPARK で記述された検証志向の primitive 実装候補は存在するが、その多くは研究的または限定用途であり、「監査済み Ada/SPARK の完全な TLS/SSH/IPsec スタックが既に存在する」と結論づけることはできない。本設計では、まず狭い primitive、具体的にはハッシュ、KDF、署名 primitive、鍵ラップなどについて、Ada/SPARK の既存実装を優先的に評価する。その上で、フルプロトコル実装については、既存成熟実装を別の隔離パーティションに封じ込めるか、あるいは FreeBSD 既存スタックとの境界を慎重に定義する。

この方針は、Ada/SPARK に高保証性の目標を置きつつ、現実のプロトコル複雑性を無視しないことを意味する。もし外部 C ライブラリや Ada バインディングを利用するなら、それらは当該性質の TCB に含まれる。SPARK で一部を証明できたことをもって、全経路が形式的に安全であると主張してはならない。

## 29. Storage Key Service

Storage Key Service は、ディスク暗号鍵またはそれに準ずるアンロック素材を FreeBSD から隔離する。本サービスの価値は、マウント前とオフライン時に最も大きい。ディスクが未マウントであれば、鍵はサービス内にとどまり、FreeBSD から抽出できない。システムが停止してディスクだけが奪われた場合も、TPM 連携または同等の測定バインディングが有効なら、鍵の利用は制限される。

しかし、マウント後には限界がある。ファイルシステムが平文を FreeBSD に返す以上、攻撃者は FreeBSD を通じてその平文へ到達できる。このため、本サービスは「オンライン平文保護」ではなく、「未マウント時の鍵非抽出性」と「侵害復旧時に鍵ローテーションを強制しないこと」を主目的とする。この点は文書内で必ず明記しなければならない。BitLocker との比較を行う場合も、単純な優劣ではなく、「BitLocker は TPM シールを中心とし、FBVBS の Storage Key Service はオンライン時の鍵非抽出性を強めるが、オンライン平文保護そのものは両者とも本質的制約を受ける」と書くべきである。

## 30. Update Verification Service

Update Verification Service は、従来案で十分に独立して扱われていなかったが、実際には最重要サービスの一つである。なぜなら、分離設計がいかに適切であっても、更新経路が「悪意ある新バージョン」を許してしまえば、すべての防御は正規機能として崩壊するからである。本サービスは、マイクロハイパーバイザー、信頼サービスイメージ、FreeBSD カーネル、モジュール、`setuid` 許可データベース、ポリシー断片、失効リスト、マニフェストを対象とし、署名、世代番号、依存関係、対象 CPU ベンダ、必要機能、失効状態を検証する。

搬送手段は問わない。本サービスが見るのは、どのツールがファイルを運んできたかではなく、ファイルそのものと付随マニフェストが信頼できるかである。この設計により、`freebsd-update`、`pkg`、オフラインメディア、DevOps 配布基盤、イメージ更新などを横断して統一の信頼モデルを持てる。

---

# Part VIII. FreeBSD Integration

## 31. FreeBSD Front-End Role

FreeBSD 側には、`fbvbs` フロントエンドが必要である。本コンポーネントは、旧来案の `fbvbs.ko` に相当するが、本書では単なる「カーネルエージェント」としてではなく、非信頼の ABI 変換層と位置づける。フロントエンドの役割は、FreeBSD カーネル内部イベントを、FBVBS が理解する要求へ変換することである。たとえば、KLD ロード、`execve`、資格情報更新、Jail パラメータ変更、MAC 重要状態変更、鍵操作要求、VM 作成要求などがその対象となる。

本コンポーネントは侵害可能であると最初から想定される。このため、フロントエンドが侵害されたときの影響は、要求を送らない、誤った要求を送る、サービス拒否を起こす、といった範囲に閉じ込めなければならない。フロントエンドが信頼サービスメモリへ到達したり、自ら第二レベルページテーブルを書き換えたり、一次監査ログを書き換えたりできてはならない。

## 32. Integration Hooks in the FreeBSD Kernel

FreeBSD へどのフックを設けるかは実装互換性を左右する。本書では、少なくとも以下の系統に介入点が必要である。第一に、モジュールロード経路であり、KLD がロードされ execute 権限を要求する前に、署名検証と権限付与が行われなければならない。第二に、`execve`、`fexecve`、`setuid(2)` 系、および対応する `gid` 系の資格情報変更経路であり、典型的な特権上昇が検査されなければならない。第三に、Jail、MAC Framework における `mpo_cred_check_execve`, `mpo_cred_check_setuid`, `mpo_vnode_check_exec`, `mpo_proc_check_signal`、および Capsicum capability mode への遷移や rights 縮減導入点であり、本書で定義した不変条件に関係する変更が観測・制御できなければならない。第四に、鍵利用経路であり、TLS、SSH、IPsec 等が秘密鍵を直接所有しなくても動作する API ラッパーが必要である。第五に、`bhyve` と `vmm` 統合経路であり、VM 作成、メモリ登録、vCPU 実行、割込み注入がマイクロハイパーバイザー前提へ書き換えられなければならない。なお、FreeBSD の `mac(9)` が示すとおり、entry point checks だけで全攻撃経路を網羅できるとは限らないため、各不変条件について十分な介入点が存在することを個別に実証しなければならない。

このフック設計は、FreeBSD 上流追従に大きく影響するため、カーネル内部の多数箇所に散在したパッチではなく、比較的安定した集約ポイントを優先しなければならない。あわせて、`vmm(4)` と passthrough が要求する boot-time 設定や loader 段階の介入点も設計対象に含めなければならない。重視すべきなのは、将来保守性と差分最小化である。

---

# Part IX. Deep `bhyve` and `vmm` Integration

## 33. Why the `bhyve` Section Must Be Deep

従来案では、VM 管理を FreeBSD と `bhyve` に委譲すると記述していたが、その説明は詳細性を欠いていた。実際には、FBVBS において `bhyve` 統合は周辺事項ではなく、アーキテクチャ全体の整合性を左右する主要論点である。既存 `bhyve` は FreeBSD カーネル内の `vmm` 実装が Intel VMX root operation または AMD SVM のホスト側仮想化制御権に直接触れることを前提としているのに対し、FBVBS ではその制御権をマイクロハイパーバイザーが保持するからである。したがって、`bhyve` 統合は単なるラッパー差替えではなく、責務分担の再設計を伴う。

## 34. Control Plane and Execution Plane Separation

本設計では、`bhyve` ユーザーランドは制御プレーンおよびデバイスモデル層として残す。ここには VM 構成解析、PCI および virtio デバイスモデル、ACPI や fwcfg の生成、ブート ROM や UEFI ファームウェア連携、vCPU スレッド管理、管理 CLI が含まれる。一方、既存 `vmm.ko` が担っていた実行プレーン、すなわち実際の VM entry/exit、第二レベルページング、IOMMU ドメイン、割込み再マップ、root 特権依存のレジスタ制御は、マイクロハイパーバイザーへ移る。guest VM もパーティション一般の状態機械に従うが、`Measured` と `Loaded` は、単一の guest boot artifact に対する測定と配置として解釈する。ABI v1 では、その boot artifact は `component_type=guest-firmware` または `component_type=guest-boot-image` のいずれか一つでなければならず、同時に二つを要求してはならない。両者は artifact 分類名の違いにすぎず、CPU 初期状態の意味論は同一である。すなわち、ABI v1 の guest boot は常に Section 18 の一般 partition entry 規約、すなわち `RIP=entry_ip`, `RSP=initial_sp`, flat 64-bit model に従う。guest VM の生成後、FreeBSD 側は `PARTITION_MEASURE` にその `image_object_id` と対応 `manifest_object_id` を渡し、その後 `PARTITION_LOAD_IMAGE`、`PARTITION_START` を呼び出さなければならない。`VM_RUN` はこの一般パーティション起動列が完了した後にのみ許可される。`VM_SET_REGISTER` が初回 `VM_RUN` 前に呼ばれた場合は、指定レジスタ値が `PARTITION_LOAD_IMAGE` による既定初期値を上書きする。未指定レジスタは Section 18 の既定初期値を維持する。

FreeBSD 側には、`vmm` フロントエンド、あるいは `vmm` 互換層が残る。この層は `/dev/vmm` と `libvmmapi` の高レベル ABI を、少なくとも `VM_CREATE`, `VM_DESTROY`, `VM_RUN`, `VM_SET_REGISTER`, `VM_GET_REGISTER`, `VM_MAP_MEMORY`, `VM_INJECT_INTERRUPT`, `VM_ASSIGN_DEVICE`, `VM_RELEASE_DEVICE` に対応する意味論と、本仕様で定義した `register_id` 列挙に含まれるレジスタ集合について維持しつつ、実際の要求をマイクロハイパーバイザーに転送する。これにより、`bhyve` ユーザーランドの再利用性を最大化し、デバイスモデル全体を書き直すことを避ける。これ以外の既存 `vmm` 操作は ABI v1 の適合範囲外とし、必要なら明示的拡張としてのみ追加してよい。ただし、passthrough、タイミング、割込み制御、メモリ所有権、snapshot 可否などは、ほぼ再設計が必要である。

## 35. VM Lifecycle Under FBVBS

VM 作成時、`bhyve` または `bhyvectl` 相当の管理ソフトウェアは、従来どおり VM 名、メモリサイズ、CPU 数、デバイス構成、ブートメディア、passthrough デバイス等を定義する。しかし、最終的な VM パーティションの生成、物理メモリ割当、第二レベルページテーブルの初期化、vCPU 状態オブジェクトの生成は、マイクロハイパーバイザーが行う。ABI v1 では guest VM パーティションの生成は `VM_CREATE` のみが行ってよく、`PARTITION_CREATE(kind=PARTITION_KIND_GUEST_VM)` は `INVALID_PARAMETER` とする。FreeBSD は要求を記述するだけであり、物理的な分離を自ら実装してはならない。

VM 実行中には、各 vCPU スレッドが `VM_RUN` 相当のループに入り、マイクロハイパーバイザーから exit イベントを受け取る。exit のうち、第二レベルページ fault、翻訳整合性関連 trap、CPU 制御ビット変更、IOMMU fault のような低レベル、高頻度、安全境界に関わるものは、マイクロハイパーバイザー内で完結処理される。一方、PIO、MMIO、高水準デバイスエミュレーション、上位管理イベントなどは FreeBSD 側へ返送される。ここで要点となるのは、未分類 exit を無条件に FreeBSD 側へ委譲するような fail-open 挙動を禁止することである。分類できないものは fail-closed として扱い、少なくとも VM を停止し、一次監査ログに記録しなければならない。

VM 破棄時には、ゲストメモリがゼロ化され、IOMMU ドメインが解除され、割込み再マップ設定が解放され、デバイス割当が巻き戻されなければならない。ゲストメモリの再利用前ゼロ化は、別 VM への情報漏洩防止の観点から必須要件である。

### 35.1. vCPU State Machine

ABI v1 では、各 vCPU は `Created`、`Runnable`、`Running`、`Blocked`、`Faulted`、`Destroyed` のいずれかの状態を持つ。`VM_CREATE` 時に vCPU は `Created` として生成され、対応 VM が `PARTITION_START` を完了した時点で `Runnable` に遷移する。`VM_RUN` により `Runnable` は `Running` へ遷移する。exit 後の状態は固定規則で決定し、`PIO`、`MMIO`、`external interrupt`、`EPT/NPT violation`、`control register access`、`MSR access`、`shutdown` では `Runnable` に戻る。`halt` では `Blocked` に遷移する。`Blocked` は、外部イベントまたは割込み注入により再開可能な待機状態を外部 ABI に露出するための状態であり、halt wait に入った vCPU にのみ用いる。注入可能条件が成立すると `Runnable` に戻る。未分類 exit、内部不整合、または致命 fault では `Faulted` に遷移し、`PARTITION_RECOVER` 成功後に `Runnable` に戻る。破棄完了後は `Destroyed` とする。

`VM_RUN` は `Runnable` の vCPU に対してのみ有効である。`VM_INJECT_INTERRUPT` は `Runnable` または `Blocked` の vCPU に対してのみ有効である。`VM_SET_REGISTER` と `VM_GET_REGISTER` は `Running` 状態では許可されない。`VM_GET_VCPU_STATUS` は、現在の外部可視 vCPU 状態を返す凍結済み ABI とし、caller は `Blocked` と `Runnable` の判別をこの call に基づいて行わなければならない。`PARTITION_QUIESCE` 成功時、全 vCPU は scheduler から外され、外部可視には quiesced 相当停止状態となる。未分類 exit または致命 fault が任意の一つの vCPU で発生した場合、ABI v1 では VM partition 全体を `Faulted` とみなし、全 vCPU を `Faulted` 扱いにしなければならない。`PARTITION_RECOVER` は partition 単位で作用し、当該 VM に属する全 vCPU を既定初期状態へ再初期化した上で `Runnable` に戻す。`PARTITION_GET_FAULT_INFO` は fault を最初に検出した vCPU の情報を返し、`fault_detail0` に `vcpu_id` を格納する。表に存在しない遷移を要求した場合は `INVALID_STATE` とする。

## 36. Guest Memory Ownership and Mapping

FBVBS において、guest memory は二重に記述される。FreeBSD からは memseg や guest physical address 空間として見え、`bhyve` デバイスモデルはその抽象に基づいて動作する。しかし、実際にどの host physical page を、どの第二レベルページテーブルで、どの IOMMU ドメインに紐付けるかは、マイクロハイパーバイザーの責務である。この二層構造を曖昧にしてはならない。どちらが実オーナーで、どちらが記述子保持者かを明確に定義しなければ、passthrough 時の DMA 安全性も、snapshot 時の一貫性も、将来の crash dump 仕様も設計できない。

本設計では、FreeBSD は guest memory descriptor を保持するが、machine frame の最終割当権は持たない。FreeBSD が割当を要求したとしても、マイクロハイパーバイザーがそれを拒否、延期、整列変更してよい。これにより、ゲストメモリと信頼サービスメモリ、ならびに FreeBSD 自身のメモリとの混線を防げる。

## 37. Passthrough, DMA, and Interrupt Remapping

`bhyve` passthrough は、性能上有益である一方、FBVBS においては最も慎重な制御を要する機能の一つでもある。デバイスが DMA により任意メモリへ到達できるなら、CPU 側分離のみでは保護境界を維持できない。本設計では、passthrough デバイスの最終所有権はマイクロハイパーバイザーが持ち、FreeBSD は割当要求を出すだけとする。デバイスは、IOMMU group、ACS 特性、リセット能力、MSI/MSI-X の制御可能性、interrupt remapping の可否を検査した上でなければ VM に割り当ててはならない。

特に MSI/MSI-X は重要である。単に BAR を passthrough し、割込みも素通しにする設計は危険である。少なくとも MSI/MSI-X の再設定は制御下に置かれ、意図しないベクタや CPU への注入が起きないようにしなければならない。さらに、デバイス解除時には Function Level Reset または同等の安全なリセット手順を要求し、次の割当先へ状態が持ち越されないようにする。

## 38. Explicit Non-Goals in Virtualization

本バージョンでは、live migration と nested virtualization は非目標とする。これらは実装価値が低いからではなく、分離、測定、鍵保持、DMA 所有権、タイミング整合性、ログ一貫性に極めて大きな影響を与えるため、初版で正しく定義するには対象が広すぎるからである。snapshot についても、本版では将来拡張点としての設計余地を残すにとどめ、完全な実装要求には含めない。

---

# Part X. Update Model, Artifact Model, and Rollback Protection

## 39. Transport-Independent Update Architecture

従来案における `freebsd-update` への依存は、更新機能と信頼判断を混同していた。本設計では、その混同を解消する。更新は、「どう運ばれてきたか」ではなく、「何が運ばれてきたか」と「それを誰が承認したか」によって信頼される。したがって、`freebsd-update`、`pkg`、オフライン媒体、コンテナイメージ、構成管理システム、いずれを使ってもよい。ただし、最終的に適用されるのは、署名付き成果物と署名付きマニフェストの検証に合格したものだけである。

各成果物には、少なくとも、フォーマットバージョン、コンポーネント種別、対象 CPU ベンダと必要機能、対象 OS 世代、内容ハッシュ、サイズ、署名方式、署名値、世代番号、security epoch、依存関係、失効対象識別子を記述したマニフェストを付ける。このマニフェスト自体も署名されなければならない。ただし、単一マニフェストのみでは freshness、freeze 攻撃検出、mix-and-match 防止を十分に扱えないため、更新メタデータ集合は timestamp、snapshot、一貫性識別子、失効時刻、役割分離、またはそれと同等の機能を備えなければならない。ハイパーバイザーまたは Update Verification Service は、これらのメタデータを読み、対象環境に適合し、失効しておらず、整合的 snapshot view の中でロールバックされていない成果物のみをロードする。

## 40. Signature Hierarchy and Key Ceremony

署名鍵は、FBVBS 全体の中で最も高価値の資産の一つである。とりわけ、マイクロハイパーバイザー、Kernel Code Integrity Service、Update Verification Service の承認鍵が漏洩すると、設計上のすべての境界を「正規更新」として突破できる。したがって本設計では、ルート鍵をオフラインで管理し、オンライン発行用の中間鍵を分離し、各コンポーネント種別ごとに用途制約された署名鍵を持つ階層を推奨する。高保証運用プロファイルでは HSM または同等のハードウェア保護、および二者承認以上のリリース署名手順を必須とする。

鍵失効は、設計上の第一級機能である。失効リストまたは失効マニフェストは、通常成果物と同じく署名され、かつより新しい security epoch を持ちうる。マイクロハイパーバイザーは、失効済み鍵による署名を受理してはならず、必要であれば起動自体を拒否しなければならない。

---

# Part XI. Quality, Verification, and Engineering Discipline

## 41. Why a High-Assurance Design Needs More Than SPARK

高保証な設計であると主張する際、最も注意すべきなのは、言語選択のみで十分な保証が得られると誤解することである。Ada/SPARK は有力な基盤であるが、それだけでは航空、防衛、高信頼システムに見られる工程規律の代替にはならない。本設計では、DO-178C/ED-12C およびその形式手法補足 DO-333 を工程規律の参照モデルとして用い、Common Criteria や SESIP を脅威、境界、評価証拠整理の参照枠として用い、seL4 の実践を参照して「何をどこまで証明したか、何が証明対象外かを限定して主張する態度」を採用する。これは認証を装うためではなく、将来認証可能な証拠構造を初期段階から文書化するためである。

## 42. Mandatory Process Requirements

FBVBS v7 に適合する実装は、要求、設計、実装、試験、証拠の双方向トレーサビリティを維持しなければならない。すなわち、任意のセキュリティ要求から、それを実装するコード単位、関連する設計章、ならびに対応する証拠、たとえば証明スクリプト、レビュー記録、試験ケース、カバレッジ結果、リリース成果物へ辿れること、およびその逆方向に、各成果物がどの要求を満たすために存在するのか辿れることが必須である。

TCB 変更は、作者以外の独立レビュア一名以上の承認を必要とする。ここでいう TCB 変更には、Ada/SPARK コードだけでなく、Rust の `unsafe` ブロック、FFI 境界、アセンブリラッパー、ビルドスクリプト、署名検証パス、ハイパーコール ABI 変更、証明前提変更も含まれる。レビューは、単なるスタイル確認ではなく、要件適合、境界条件、失敗モード、証明との整合、ログ要件、ロールバック要件、性能影響を確認するものでなければならない。

## 43. Language-Specific Rules

SPARK 対象コードは、実行時例外不在を証明しなければならず、事前条件、事後条件、型不変条件、必要に応じてグローバル依存性を明記しなければならない。動的メモリ確保、再帰、暗黙例外伝播は TCB 内で禁止する。Rust を用いる場合は `no_std`、`panic=abort`、固定 toolchain、`Cargo.lock` 固定、`unsafe` の局所化と安全性契約文書化を必須とする。C を例外採用する場合は、許可済みサブセット、整数境界、エイリアス、メモリ所有権、未定義動作不在、コンパイラ前提、静的解析結果、ならびに関数ごとの契約を文書化し、少なくとも MISRA C:2023 または同等規律への適合証拠と、Frama-C/TrustInSoft/CBMC 等に類する証明または解析成果物を残さなければならない。アセンブリは、呼出規約、保存レジスタ、破壊レジスタ、前提状態、後続状態を文章で明記し、さらに逆アセンブルレビューを行わなければならない。

## 44. Test, Fuzzing, Fault Injection, and Coverage

テストは、単体試験だけでは不十分である。少なくとも、要求ベース統合試験、境界値試験、異常系試験、競合試験、長時間 soak 試験、負荷試験、fault injection、fuzzing が必要である。特に hypercall パーサ、IPC パーサ、更新マニフェストパーサ、署名ローダ、ログデコーダ、`bhyve` フロントエンド境界は継続的 fuzzing の対象とするべきである。fault injection では、ログバッファ溢れ、署名壊れ、ロールバック要求、部分的メモリ破壊、DMA fault、サービスクラッシュ、vCPU stuck、割込み嵐などを人工的に起こし、設計どおり fail-safe または fail-closed になることを確認する。

カバレッジについては、全コードに一律 MC/DC を要求するのは現実的でないが、少なくとも権限判定、状態遷移判定、隔離境界判定、更新承認判定の中核分岐については MC/DC を目標とする。MC/DC の適用が困難な場合は、その理由を記録した上で、decision coverage や condition coverage などの代替基準を明示しなければならない。証明が存在するからといって、テストを全面的に省略してはならない。証明は証明された性質に対してのみ有効であり、統合エラー、仕様誤り、外部依存、証明外コード、性能退化は別途確認が必要である。

## 45. Supply Chain and Reproducibility

供給網は、コードの中身と同じくらい重要である。したがって、リリース成果物は再現可能ビルドで生成され、SBOM を伴い、署名付き provenance を持たなければならない。依存関係は allowlist 化され、バージョン固定され、脆弱性監視対象とされる。ビルド環境は hermetic に近づけ、CI が勝手に外部ネットワークから依存物を取得するような構成は避けるべきである。これらは、マルウェア混入やビルド汚染に対する最後の防壁である。

---

# Part XII. Windows Comparison and Platform Positioning

## 46. Correcting the Windows Comparison

従来案に含まれていた「Windows に OS 固有保護はない」という趣旨の記述は、事実に反する。Windows には、VBS 系機構としての VBS、Memory Integrity/HVCI、Credential Guard に加え、App Control for Business（旧 WDAC。UMCI を含む）、Kernel DMA Protection、Protected Process Light/Protected Services、System Guard Secure Launch、ならびに適用範囲が限定された Kernel Data Protection など、層の異なる OS 統合保護が存在する。したがって、FBVBS を論じる際には、「Windows にない新機能を FreeBSD に足す」という単純な比較ではなく、「Windows は既に多層の OS 統合保護を持つ。FBVBS は FreeBSD に対し、別の構造で近い目標を実現しようとする」と書くべきである。

この比較から導かれる設計上の重要点は二つある。第一に、Windows の保護機構が存在するという事実は、FBVBS の価値を減らすものではない。むしろ、この種の保護が Windows など一部の現代 OS/プラットフォームにおいて重要な方向性であることを示す。第二に、Windows と同じ名称を表層的に借りるのではなく、自分たちの実装がどの脅威に対し、どの程度の保証を与え、どこで異なるのかを明示することが重要である。

## 47. Intel and AMD as Security Platforms

「なぜ Intel は AMD よりセキュリティ機能があるのか」という問いに対して、本書の立場は単純な優劣論ではない。CPU ベンダは、それぞれ異なる問題設定と時期に応じて機能を追加してきた。Intel には HLAT があり、実行制御の細粒度化については Intel MBEC と AMD GMET の双方が利用されうる。一方、AMD には SEV-SNP、RMP、VMPL のように、別の保護様式で強い意味を持つ機能がある。したがって、本書は「Intel が優れているから採用する」のではなく、「本設計が必要とする Kernel Translation Integrity の観点では、Intel は HLAT という直接的機構を持つ。一方 AMD では同じ目標を複合機構で目指す必要がある」と表現する。この違いは、ベンダの優劣ではなく、機構の揃い方の差である。

---

# Part XIII. Performance, Failure Modes, and Residual Risk

## 48. Performance Discipline

高保証性は、性能要件を軽視してよいことを意味しない。保護が強固であっても、運用に耐えなければ採用は困難である。本設計では、通常の syscall や通常の read-only 状態読取りについては、ほぼゼロ追加コストであることを目標とする。一方、`setuid` 検証、モジュール署名検証、鍵操作、VM exit 境界、DMA 再設定のような希少または高価値イベントについては、十数マイクロ秒から数百ミリ秒級の追加コストを許容する。ここで重要なのは、どの経路が高価で、どの経路が日常的に頻発するかを正しく識別することである。たとえば、`execve` のような元来高価な操作に十数マイクロ秒の検証を付加することは合理的であるが、通常の syscall に毎回ハイパーコールを挿入する設計は避けるべきである。

`bhyve` 統合では、PIO、MMIO、割込み注入、timer、passthrough 再設定が主要性能要因となる。このため、共有メモリキュー、イベントバッチ処理、不要な VM exit の回避、分類済み low-level exit のハイパーバイザー内完結が重要になる。

## 49. Failure Semantics

FBVBS は panic 禁止を原則とするが、これは「決して停止しない」という意味ではない。正確には、予期しない不整合を検出したときに、FreeBSD 全体またはすべての信頼サービスを無差別に巻き込んで止めるのではなく、当該サービスまたは当該 VM を隔離し、既存保護を可能な限り維持したまま、明示的なエラーとして扱うことを意味する。たとえば Kernel State Integrity Service が障害を起こした場合、Tier B 更新は停止するが、既に read-only で固定されている Tier A 保護まで同時に解除されてはならない。Identity Key Service が障害を起こした場合、新規鍵操作は停止するが、他サービスのメモリ境界は保持されるべきである。

各サービスは、永続復旧が必要な状態、再起動で足りる状態、単純な一時ビジー状態、呼出拒否で済む状態を区別し、`Result` 型または同等の明示的エラーで返却しなければならない。

## 50. Residual Risks

本設計の最大の残余リスクは三つある。第一は、AMD における Kernel Translation Integrity の実装と立証である。ここは設計上は要求を定められても、実装と検証は難度が高い。第二は、Tier C とした高頻度可変状態を起点とする論理攻撃である。これらは本バージョンで完全境界に含めないため、別の監視、隔離、最小権限設計で補う必要がある。第三は、複雑な既存プロトコル実装を隔離利用する場合の外部コード依存である。完全にゼロから Ada/SPARK で書かない以上、その依存が TCB へ入ることを正直に認めねばならない。

加えて、帯域外ログ経路の品質は、最終的にはハードウェア運用に依存する。設計が正しくても、BMC 設定が無効、ケーブル未接続、SOL 無効化、シリアル流量超過といった理由で、期待した監査証跡が得られない可能性は残る。この点もまた、ソフトウェアだけで解決できない残余リスクである。

---

# Part XIV. Conclusion

本書が定義する FBVBS v7 は、FreeBSD を単に「より安全なカーネル」にする試みではない。むしろ、FreeBSD を敢えて完全には信頼せず、その上にあるべき高価値資産と高価値状態を、より狭く、より監査可能で、より強制力のある境界へ移し替える試みである。そのために、本設計は、マイクロハイパーバイザーの責務を最小化し、信頼サービスを分割し、ログを一次監査チャネルとミラーチャネルに分け、更新を搬送手段から切り離し、Intel と AMD の機構差異を曖昧にせず、Windows の既存防御を正しく認識し、そして何より、高保証性を工程規律と証拠構造に結び付ける。

本書は、設計上採用し得た複数の近道を意図的に退けている。`freebsd-update` への固定、監査を欠く独自暗号、AMD への根拠不十分な同格主張、`bhyve` 節の簡略化、FreeBSD ミラーログを一次監査根拠として扱うこと、SPARK の採用のみを根拠として「形式検証済み」と断定する姿勢などがそれに当たる。高保証設計において特に警戒すべきなのは、攻撃者に先立って、設計文書自身が設計上の限界を覆い隠してしまうことである。

本仕様書は、実装を不必要に複雑化するための文書ではない。守るべきもの、守れないもの、必須機構、必須証拠、設計境界、未解決課題を先に明文化することで、実装を迷走させず、AI エージェントを含む複数の実装者が一貫した方向で作業できるようにすることを目的とする。実装が本書の規定に従い、さらに本書が要求する検証とレビューが満たされるなら、FBVBS は FreeBSD に対する仮想化ベース保護基盤として、少なくとも誠実で、監査可能で、将来発展可能な基礎を得る。

---

# Appendix A. Historical Name Mapping

旧来の略称と本書での説明的名称の対応は次のとおりである。HEKI は Kernel Code Integrity Service、KDP は Kernel State Integrity Service の一部機能概念、IKV は Identity Key Service、DKV は Storage Key Service に対応する。本書では、略称のみを前提とした記述は行わない。

# Appendix B. Acronym and Term Expansion

本書では独自略語を主要名称として使わない方針を採ったが、実装仕様として不可避な業界標準略語は残る。この付録は、それらを一括して定義する。

TCB は Trusted Computing Base の略であり、ある保護性質を成立させるために信頼しなければならない最小のコード、設定、鍵、ハードウェア機構の集合を指す。DMA は Direct Memory Access の略であり、CPU を介さずにデバイスが主記憶へアクセスする機構を指す。IOMMU は I/O Memory Management Unit の略であり、DMA の到達範囲を制御する。UART は Universal Asynchronous Receiver/Transmitter の略であり、シリアル通信に用いられるハードウェアである。OOB は Out-of-Band の略であり、本書では FreeBSD の信頼境界外に存在する監査経路を指す。SOL は Serial-over-LAN の略であり、BMC 経由でホストのシリアルコンソールを遠隔取得する機構を指す。

VT-x は Intel の仮想化拡張、AMD-V は AMD の仮想化拡張を指す。EPT は Extended Page Tables、NPT は Nested Page Tables の略であり、いずれも第二レベルアドレス変換機構である。HLAT は Hypervisor-Managed Linear Address Translation の略であり、Intel が公開している、ハイパーバイザー管理下の線形アドレス変換機構を指す。MBEC は Mode-Based Execute Control の略であり、Intel 側の実行権限細粒度化機構を指す。AMD 側の対応機能は GMET と呼ばれる。RMP は Reverse Map Table の略であり、SEV-SNP における物理ページ所有権整合性の管理機構を指す。VMPL は Virtual Machine Privilege Level の略であり、SEV-SNP guest における特権階層を指す。

W^X は Write XOR Execute の略記であり、あるページが同時に書込み可能かつ実行可能であってはならないという原則を意味する。PIO は Programmed I/O、MMIO は Memory-Mapped I/O の略であり、それぞれポート空間 I/O とメモリ写像 I/O を指す。MSI は Message Signaled Interrupts、MSI-X はその拡張である。SR-IOV は Single Root I/O Virtualization の略であり、一つの物理デバイスを複数の仮想機能へ分割して提供する仕組みである。ACS は Access Control Services の略であり、PCI Express 上でのトランザクション分離に関係する。

CRC32C は Castagnoli 多項式を用いる 32-bit cyclic redundancy check を指し、本書では主として伝送破損検出に用いる。SBOM は Software Bill of Materials の略であり、成果物に含まれる依存関係の部品表を意味する。provenance は成果物の生成経路、ビルド主体、署名主体を示す由来情報である。HSM は Hardware Security Module の略であり、署名鍵の保護と使用制御のための専用ハードウェアを指す。MC/DC は Modified Condition/Decision Coverage の略であり、安全性重視システムで用いられる高水準の分岐網羅指標である。

# Appendix C. Minimal Binary Log Record Layout

一次監査ログおよびミラーログの最小レコード構造は、実装互換性のため次の固定ヘッダを持つものとする。エンディアンは little-endian とし、すべて自然アラインメントで配置する。

```c
struct fbvbs_log_record_v1 {
    uint64_t sequence;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
    uint64_t timestamp_counter;
    uint32_t cpu_id;
    uint32_t source_component;
    uint16_t severity;
    uint16_t event_code;
    uint32_t payload_length;
    uint8_t  payload[220];
    uint32_t crc32c;
};
```

`payload_length` は 220 を超えてはならない。一次監査ログ経路でより大きなペイロードが必要な場合は、複数レコードに分割する。可変長構造としなかったのは、リングバッファ実装、DMA 安全性、部分破損検出、AI エージェントによる自動実装容易性を優先したためである。CRC32C は偶発的破損の検出に用いるものであり、レコード単独では暗号学的改ざん耐性を与えない。

## C.1. Frozen Mirror Ring Header Layout

FreeBSD 可視ミラーリングバッファの固定ヘッダは次のとおりとする。

```c
struct fbvbs_log_ring_header_v1 {
    uint32_t abi_version;
    uint32_t total_size;
    uint32_t record_size;
    uint32_t write_offset;
    uint64_t max_readable_sequence;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};
```

`abi_version` は 1 でなければならない。`record_size` は `sizeof(struct fbvbs_log_record_v1)` と一致しなければならない。`write_offset` はリング本体の先頭からのバイトオフセットであり、`record_size` の整数倍でなければならない。

# Appendix D. Frozen Shared Command Page Layout

共有コマンドページの先頭構造は次のとおりとする。ページサイズは 4096 バイトとし、残余領域に要求または応答本文を置く。ABI v1 では本付録の構造を凍結し、互換性を破る変更は `abi_version` を更新しなければならない。

```c
struct fbvbs_command_page_v1 {
    uint32_t abi_version;
    uint16_t call_id;
    uint16_t flags;
    uint32_t input_length;
    uint32_t output_length_max;
    uint64_t caller_sequence;
    uint64_t caller_nonce;
    uint32_t command_state;
    uint32_t actual_output_length;
    uint64_t output_page_gpa;
    uint64_t reserved0;
    uint8_t  body[4040];
};
```

`abi_version` は ABI v1 では 1 でなければならない。未対応版は `ABI_VERSION_UNSUPPORTED` とする。`flags` は Appendix D.1 で定義される。`command_state` は Appendix D.2 で定義される。`input_length` は `body` 先頭から有効な要求本文のバイト数を表し、固定長要求を持つ call ではその固定長と厳密一致しなければならない。可変長要求を持つ call では最小長以上かつ call 固有上限以下でなければならない。`input_length` より後ろの `body` 領域は 0 でなければならず、非ゼロなら `INVALID_PARAMETER` とする。`actual_output_length` は caller が 0 に初期化し、hypervisor が応答長を書き戻す。`output_page_gpa` は `FBVBS_CMD_FLAG_SEPARATE_OUTPUT` が立っている場合のみ有効であり、それ以外では 0 でなければならない。要求本文を持たない call では `input_length=0` とする。

`reserved0` と未使用領域は呼出前にゼロ化されなければならない。マイクロハイパーバイザーはこれを検証し、ゼロ化されていない場合は `INVALID_PARAMETER` とする。

ABI v1 では、`status_code = OK` の場合に限り `command_state=COMPLETED` を返してよく、`status_code != OK` の場合は必ず `command_state=FAILED` を返さなければならない。caller は `actual_output_length=0` であれば応答本文を無視しなければならない。`actual_output_length>0` の場合に限り、call contract が明示する固定エラー応答本文を読んでよい。固定エラー応答本文が定義されていない call では、失敗時 `actual_output_length=0` を必須とする。

## D.1. Command Flags

| ビット | 名称 | 意味 |
|---|---|---|
| 0 | `FBVBS_CMD_FLAG_SEPARATE_OUTPUT` | 応答本文を `output_page_gpa` が指す別共有ページへ書く |
| 1-15 | 予約 | 0 でなければならない |

## D.2. Command States

| 値 | 名称 | 意味 |
|---|---|---|
| 0 | `EMPTY` | 未使用または caller により再初期化済み |
| 1 | `READY` | caller が要求を書き終え、trap 可能 |
| 2 | `EXECUTING` | hypervisor が受理し処理中 |
| 3 | `COMPLETED` | 正常完了 |
| 4 | `FAILED` | エラー終了 |

## D.3. Output Page Rules

`output_page_gpa` は 4096 バイト境界にアラインされた共有 writable page を指さなければならない。別出力ページを用いる場合でも、出力長上限は `output_length_max` に従う。必要長がこれを超える場合は `BUFFER_TOO_SMALL` を返し、`actual_output_length` に必要最小長を書き戻す。

ABI v1 で一回の応答が 4096 バイトを超えてはならない call は、そのことを call contract に含める。列挙系 call は最大件数を固定することで page 内完結を保証する。`DIAG_GET_PARTITION_LIST` は最大 252 件、`DIAG_GET_ARTIFACT_LIST` は最大 63 件、`DIAG_GET_DEVICE_LIST` は最大 252 件を返してよい。これを超える構成を ABI v1 は対象外とする。

## D.4. Bootstrap Metadata Page

各パーティションには、読み取り専用の bootstrap metadata page を 1 枚公開しなければならない。caller はこの page を読むことで、自身の command page GPA 群を初期取得できる。ABI v1 では、この page の `vcpu_count` は当該 partition の生成時に確定した `vcpu_count` と一致しなければならない。boot 時 autostart trusted-service partition では manifest 内 `vcpu_count` が正本であり、post-boot に `PARTITION_CREATE(kind=PARTITION_KIND_TRUSTED_SERVICE)` された partition では `PARTITION_CREATE.vcpu_count` と manifest 内 `vcpu_count` が一致しなければならない。

```c
struct fbvbs_bootstrap_page_v1 {
    uint32_t abi_version;
    uint32_t vcpu_count;
    uint64_t command_page_gpa[252];
};
```

`abi_version` は 1 でなければならない。`vcpu_count` は有効な `command_page_gpa` 要素数を示し、ABI v1 では 252 を超えてはならない。未使用要素は 0 とする。bootstrap metadata page 自体の GPA は、Intel/AMD 共通に `RSI` レジスタで caller へ渡される固定ブート ABI とする。全 caller/partition entry で `RSI` は bootstrap page GPA を保持してよいものとし、通常 entry でもその内容に依存しなければ 0 以外であってよい。

# Appendix E. Final Verification of This Specification

本仕様書の最終検証として、以下の観点を文書全体に対して再確認した。第一に、一次監査ログと FreeBSD 可視ログが混同されていないことを確認した。第二に、Intel では HLAT を必須としつつ、AMD については「HLAT 相当がある」と虚偽に書かず、同等のセキュリティ目標を目指す複合機構として定義し、その同等性が要実証であることを明記した。第三に、更新機構を `freebsd-update` に固定せず、搬送手段非依存の署名付き成果物モデルに置き換え、同時に freshness と snapshot 一貫性の要件を追加した。第四に、Ada/SPARK に理想を置きながらも、既存の検証志向実装の現実的制約を認め、外部ライブラリ利用時にはそれを TCB に含めることを明記した。第五に、Kernel State Integrity Service が防げる攻撃と防げない攻撃とを明示的に分離した。第六に、`bhyve` 統合が表面的な一節に留まらず、制御プレーン、実行プレーン、DMA、割込み、所有権、boot-time 介入点、非目標にまで分解されていることを確認した。第七に、Windows 固有の防御機構を否定する誤った比較を除去し、各保護機構の層の違いを明確化した。第八に、本書で用いた主要略語について、本文または付録で必ず説明を与え、MBEC/GMET の区別も補った。第九に、共有コマンドページ、trap レジスタ規約、状態遷移、error code 集合、call_id 空間、各 hypercall の前提条件と失敗条件が凍結済み ABI として文書内で一意に解釈できることを確認した。第十に、requirements metadata が行内記述または section metadata 継承規則で一意に復元可能であることを確認した。

この検証の結果、本仕様書は、FBVBS v7 の凍結済み設計仕様、凍結済み ABI 仕様、ならびに実装契約書として完成している。本書は依然として本番宣言前の立証課題を持つが、それらは仕様未完成を意味しない。未解決なのは実装と検証の完了であり、仕様の空欄ではない。

# Appendix F. Proof Obligations Before Production Declaration

本書は、設計仕様としては実装に進むための十分な具体性を備えるが、本書に従って実装されたすべての構成が、直ちに本番運用に適すると主張するものではない。特に本番宣言の前には、設計上明示した仮定と未立証事項を、実装と試験によって閉じなければならない。

第一の立証課題は、AMD における翻訳整合性経路である。Intel では HLAT を用いる構成が明確であるのに対し、AMD では NPT、ページテーブル更新トラップ、シャドウ翻訳経路、TLB 無効化監視、必要に応じた SEV-SNP 補助機構を組み合わせる。したがって本番宣言の前には、PFN 差し替え、PTE 改ざん、TLB invalidate race、複数コア更新競合、異常な fault 順序、ならびに復旧経路まで含む実証が必要である。

第二の立証課題は、FreeBSD 介入点の十分性である。本書は `execve(2)`、`fexecve(2)`、`setuid(2)` 系、Jail、選択された MAC フック、Capsicum capability mode 遷移、および KLD ロード経路を対象に含めるが、実際の FreeBSD 版差分において、それらが本書で想定した不変条件を十分に観測・制御できるかは、コード読解と試験によって確認しなければならない。

第三の立証課題は、更新メタデータ集合の freshness と整合性である。本書は timestamp、snapshot、一貫性識別子、失効時刻、役割分離、またはそれと同等の機能を要求しているが、実装時には freeze 攻撃、mix-and-match 攻撃、期限切れメタデータ、分断環境での stale mirror、ならびにロールバック復旧手順を含めて、更新系が本当に fail-closed に振る舞うことを示す必要がある。

第四の立証課題は、一次監査ログ経路の運用実在性である。本書は UART、BMC、SOL、または専用ロガーのいずれかを前提とするが、これは設計紙面上で存在すると書けば足りるものではない。本番宣言の前には、対象ハードウェア、ファームウェア設定、BMC 設定、配線、収集サーバ、保存ポリシー、障害時の代替経路、ならびに過負荷時の欠落特性を、運用手順込みで確定しなければならない。

第五の立証課題は、暗号実装選定である。本書は Ada/SPARK の既存 primitive 候補を優先評価すると定めるが、どの実装を採用し、どの実装を TCB に含め、どの範囲を proof obligation とし、どの範囲を外部監査または既存実装の成熟度に依拠するかは、最終的に成果物レベルで決めなければならない。特に TLS、SSH、IPsec のような複雑なプロトコル経路は、primitive の選択と同一視してはならない。

第六の立証課題は、`bhyve` passthrough と IOMMU 統合である。本書は所有権、interrupt remapping、MSI/MSI-X 再設定、デバイスリセット、guest memory 所有権の原則を与えるが、実機ではデバイスごとの癖、ACS 不備、グルーピング制約、firmware の挙動差が存在する。本番宣言の前には、少なくともサポート対象デバイス群ごとに qualification matrix を作成し、非対応条件を明文化しなければならない。

# Appendix G. Requirements Catalog

本付録は、本仕様書に基づく実装、試験、レビュー、証拠収集のための最終的な要求一覧である。本文の設計叙述と矛盾する場合は、原則として本付録の要求本文を優先し、叙述側を修正する。

特に断りがない限り、各 subsection はその subsection 全体に適用される metadata 既定値を先頭に持つ。各 requirement 行に明示されていない requirement type、source sections、target components、status、test ID 接頭辞、evidence ID 接頭辞は、その subsection 既定値を継承する。

## G.1. Roots of Trust, Boot, and Platform Requirements

この subsection の既定 metadata は、requirement type=`security,functional,operational`、source sections=`8, 12-15, Appendix F`、target components=`microhypervisor, firmware integration, platform configuration`、status=`normative-frozen` とする。関連試験識別子は `T-BOOT-<requirement-number>`、関連証拠識別子は `E-BOOT-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0001`  マイクロハイパーバイザーは、FreeBSD より前にロードされなければならない。検証方法は boot trace の inspection と platform integration test とする。  
`FBVBS-REQ-0002`  Intel 構成では FreeBSD が VMX root operation を取得する前に、AMD 構成では FreeBSD が SVM のホスト側仮想化制御権を取得する前に、マイクロハイパーバイザーが有効化されなければならない。検証方法は boot path analysis と platform test とする。  
`FBVBS-REQ-0003`  FBVBS v7 適合を主張する構成では、DMA 分離を成立させるために IOMMU が存在し、かつ有効化されていなければならない。検証方法は configuration inspection と platform test とする。  
`FBVBS-REQ-0004`  ロールバック防止を主張する構成では、TPM NV 領域または同等の version store を用いて成果物世代を比較しなければならない。検証方法は update rollback test と inspection とする。  
`FBVBS-REQ-0005`  FBVBS v7 適合を主張する構成では、UART、BMC host serial redirection、IPMI Serial-over-LAN、または専用ロガーのいずれかによる一次監査ログ経路が実際に構成されていなければならない。高保証構成ではその運用成立性まで確認しなければならない。検証方法は operational drill と inspection とする。  
`FBVBS-REQ-0006`  高保証構成では、起動時検証および測定を満たし、起動連鎖の証拠を監査可能にしなければならない。検証方法は boot attestation test と evidence inspection とする。

## G.2. Logging and Audit Requirements

この subsection の既定 metadata は、requirement type=`security,interface,operational`、source sections=`13-15, Appendix C`、target components=`microhypervisor, log relay, FreeBSD mirror consumer, OOB logging path`、status=`normative-frozen` とする。関連試験識別子は `T-LOG-<requirement-number>`、関連証拠識別子は `E-LOG-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0100`  システムは、FreeBSD ホストから独立した一次監査ログと、FreeBSD 可視のミラーログを分離しなければならない。検証方法は design inspection と runtime test とする。  
`FBVBS-REQ-0101`  一次監査ログは、FreeBSD ホスト侵害時にも観測可能な OOB 経路を通じて取得できなければならない。検証方法は adversarial operational drill とする。  
`FBVBS-REQ-0102`  ミラーログは一次監査根拠として扱ってはならない。検証方法は documentation review とする。  
`FBVBS-REQ-0103`  一次監査ログレコードは、少なくとも sequence、boot identifier、CPU identifier、source component、severity、event code、payload length、payload、CRC32C を含まなければならない。検証方法は interface test と inspection とする。  
`FBVBS-REQ-0104`  CRC32C のみを根拠として改ざん耐性を主張してはならない。より強い改ざん検知を主張する場合は、署名、HMAC、または外部アンカー連結を追加しなければならない。検証方法は design inspection とする。  
`FBVBS-REQ-0105`  FreeBSD から見えるリングバッファは読み取り専用でなければならず、第二レベルページングにより書込みが拒否されなければならない。検証方法は runtime test と fault injection とする。  
`FBVBS-REQ-0106`  early boot と panic 時ログ完全性は best effort として扱い、完全取得を無条件に主張してはならない。検証方法は documentation review と panic-path test とする。  
`FBVBS-REQ-0107`  FreeBSD 可視ミラーログリングバッファは `fbvbs_log_ring_header_v1` 固定ヘッダを持ち、その後ろに `fbvbs_log_record_v1` 固定長スロット列を置かなければならない。検証方法は interface test と inspection とする。

## G.3. Microhypervisor and Partition Requirements

この subsection の既定 metadata は、requirement type=`functional,interface,security`、source sections=`16-20, Appendix D, Appendix L`、target components=`microhypervisor, partition manager, FreeBSD front-end`、status=`normative-frozen` とする。関連試験識別子は `T-PART-<requirement-number>`、関連証拠識別子は `E-PART-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0200`  マイクロハイパーバイザーの責務は、パーティション管理、CPU 状態遷移、第二レベルページング管理、IOMMU ドメイン制御、限定的 CPU 制御強制、起動検証、一次監査ログ生成に限定しなければならない。検証方法は architecture inspection とする。  
`FBVBS-REQ-0201`  新規 TCB ロジックは Ada/SPARK で実装しなければならない。C を含む例外を設ける場合は、境界、理由、安全性契約、適用サブセット、未定義動作不在の根拠、ならびに形式的解析または同等証拠を文書化しなければならない。検証方法は code review と proof artifact review とする。  
`FBVBS-REQ-0202`  パーティション状態は Created、Measured、Loaded、Runnable、Running、Quiesced、Faulted、Destroyed を少なくとも持ち、不正遷移を許してはならない。検証方法は state-machine test と inspection とする。  
`FBVBS-REQ-0203`  Destroyed パーティションのメモリは再割当前にゼロ化しなければならない。検証方法は memory reuse test とする。  
`FBVBS-REQ-0204`  capability はマイクロハイパーバイザーのみが付与、取消、監査でき、パーティション自身が生成または拡張してはならない。検証方法は proof、analysis、negative test とする。  
`FBVBS-REQ-0205`  hypercall ABI は固定形式で定義され、呼出番号、呼出元、長さ、返却コード、未使用領域ゼロ化条件を明示しなければならない。検証方法は interface test と fuzzing とする。  
`FBVBS-REQ-0206`  共有コマンドページの未使用領域がゼロ化されていない要求は `INVALID_PARAMETER` として拒否しなければならない。検証方法は negative interface test とする。  
`FBVBS-REQ-0207`  trap レジスタ規約は `RAX=command_page_gpa`、`RBX/RCX/RDX=0` を入力とし、返却時 `RAX=status_code`、`RBX=command_state`、`RCX=actual_output_length` を返す固定 ABI としなければならない。検証方法は interface test と trap-level inspection とする。  
`FBVBS-REQ-0208`  `abi_version` 不一致要求は `ABI_VERSION_UNSUPPORTED` で拒否しなければならない。検証方法は negative interface test とする。  
`FBVBS-REQ-0209`  `caller_sequence` は vCPU ごとに単調増加でなければならず、後退または再利用は `REPLAY_DETECTED` で拒否しなければならない。検証方法は replay test とする。  
`FBVBS-REQ-0210`  command page 状態機械は `EMPTY`、`READY`、`EXECUTING`、`COMPLETED`、`FAILED` に固定し、`EXECUTING` 中の再入は `RESOURCE_BUSY` としなければならない。検証方法は state-machine test と concurrency test とする。  
`FBVBS-REQ-0211`  partition lifecycle の合法遷移は Section 18.1 に列挙したものに限定し、表にない遷移は `INVALID_STATE` としなければならない。検証方法は lifecycle transition test と inspection とする。  
`FBVBS-REQ-0212`  `PARTITION_RESUME` は `Quiesced` から `Runnable` へのみ有効であり、`Faulted` 回復には `PARTITION_RECOVER` を用いなければならない。検証方法は negative lifecycle test とする。

## G.4. CPU Control and Translation Integrity Requirements

この subsection の既定 metadata は、requirement type=`security,functional`、source sections=`21-25`、target components=`microhypervisor, CPU virtualization path, IOMMU integration`、status=`normative-frozen` とする。関連試験識別子は `T-CPU-<requirement-number>`、関連証拠識別子は `E-CPU-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0300`  FreeBSD は CR0.WP、CR4.SMEP、CR4.SMAP、および構成依存の CET 関連制御を任意に解除できてはならない。検証方法は trap test と inspection とする。  
`FBVBS-REQ-0301`  Intel 構成では HLAT を必須とする。HLAT を用いない Intel 構成は FBVBS v7 適合を名乗ってはならない。検証方法は platform capability inspection と conformance review とする。  
`FBVBS-REQ-0302`  AMD 構成では HLAT 相当の単一保証を主張してはならず、NPT write-protect、fault handling、shadow translation、TLB 同期を含む複合経路を実装しなければならない。検証方法は design inspection と adversarial test とする。  
`FBVBS-REQ-0303`  AMD 構成で高保証を主張する場合、PFN 差し替え、PTE 改ざん、TLB invalidate race、複数コア更新競合に対する実証が完了していなければならない。検証方法は adversarial multiprocessor test とする。  
`FBVBS-REQ-0304`  SEV-SNP を用いる場合、RMP と VMPL は補強として利用してよいが、それのみを根拠として HLAT と同一保証を主張してはならない。検証方法は design review と documentation review とする。

## G.5. Kernel Code Integrity Requirements

この subsection の既定 metadata は、requirement type=`security,functional,interface`、source sections=`26, Appendix L`、target components=`Kernel Code Integrity Service, microhypervisor, FreeBSD front-end`、status=`normative-frozen` とする。関連試験識別子は `T-KCI-<requirement-number>`、関連証拠識別子は `E-KCI-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0400`  カーネルコードページおよび許可済みモジュールコードページは W^X を維持しなければならない。検証方法は memory protection test とする。  
`FBVBS-REQ-0401`  未署名モジュールは既定で不許可とし、署名、失効、世代番号、対象プラットフォームが許可条件を満たす場合のみ execute 権限を付与しなければならない。検証方法は module load test と negative test とする。  
`FBVBS-REQ-0402`  コード整合性を主張する構成では、Kernel Translation Integrity と整合する形でコードの物理ページ対応も保護しなければならない。検証方法は translation tamper test とする。

## G.6. Kernel State Integrity Requirements

この subsection の既定 metadata は、requirement type=`security,functional,interface`、source sections=`27, Appendix H, Appendix L`、target components=`Kernel State Integrity Service, microhypervisor, FreeBSD front-end`、status=`normative-frozen` とする。関連試験識別子は `T-KSI-<requirement-number>`、関連証拠識別子は `E-KSI-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0500`  Kernel State Integrity Service は、少なくとも起動後不変状態、制御付き更新状態、保護対象外の高頻度状態を区別しなければならない。検証方法は design inspection とする。  
`FBVBS-REQ-0501`  制御付き更新状態の変更は、検証済み shadow copy と最小時間の write-enable 区間を通じてのみ実行しなければならない。検証方法は concurrency test と analysis とする。  
`FBVBS-REQ-0502`  参照ポインタの更新は、登録済み正規オブジェクト集合に対する遷移のみを許可しなければならない。検証方法は negative test と proof または analysis とする。  
`FBVBS-REQ-0503`  `execve(2)`、`fexecve(2)`、`setuid(2)` 系、および対応する `gid` 系に関する典型的特権上昇は検査対象に含めなければならない。ABI v1 の承認入力は、操作種別と `ruid/euid/suid/rgid/egid/sgid` の完全な要求後状態を表現できなければならない。検証方法は syscall test と interface review とする。  
`FBVBS-REQ-0504`  特権上昇認可の主キーにパスを用いてはならず、vnode または `fsid+fileid` に基づく識別子を主としなければならない。検証方法は exec path variation test とする。  
`FBVBS-REQ-0505`  既存の特権付き file descriptor 継承など、exec 起点以外の権限持越し問題は別途残余リスクまたは補助対策として扱わなければならない。検証方法は documentation review とする。  
`FBVBS-REQ-0506`  Tier B 更新時の callsite 検証は caller 提供値ではなくマイクロハイパーバイザーが観測した RIP に基づかなければならない。検証方法は adversarial caller spoofing test とする。  
`FBVBS-REQ-0507`  `KSI_VALIDATE_SETUID` 相当の ABI は、少なくとも `fsid`、`fileid`、測定ハッシュ、要求 UID/GID 遷移、caller ucred 参照、Jail context、MAC context を入力に含めなければならない。検証方法は interface review と syscall/path test とする。  
`FBVBS-REQ-0508`  `CALLSITE_REJECTED` 判定は、マイクロハイパーバイザーが保持する許可 callsite table に対する完全一致 RIP 比較で行わなければならない。許可 table は対応 manifest の `allowed_callsites` metadata から KASLR 再配置後の実アドレスへ機械的に導出され、KLD 更新時には新 manifest に基づいて原子的に再計算されなければならない。検証方法は callsite relocation test と negative spoofing test とする。

## G.7. Key Service Requirements

この subsection の既定 metadata は、requirement type=`security,functional,interface`、source sections=`28-29, Appendix L`、target components=`Identity Key Service, Storage Key Service, FreeBSD front-end`、status=`normative-frozen` とする。関連試験識別子は `T-KEY-<requirement-number>`、関連証拠識別子は `E-KEY-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0600`  Identity Key Service は鍵素材をサービス境界外へ返却してはならない。検証方法は interface test と code inspection とする。  
`FBVBS-REQ-0601`  Identity Key Service の API は `IMPORT_KEY`、`SIGN`、`KEY_EXCHANGE`、`DERIVE`、`DESTROY` 等の狭い操作集合に限定しなければならない。検証方法は interface review とする。  
`FBVBS-REQ-0602`  外部暗号ライブラリを用いる場合、それを該当性質の TCB に含めなければならない。検証方法は dependency review と evidence review とする。  
`FBVBS-REQ-0603`  Storage Key Service は未マウント時の鍵非抽出性を主張してよいが、オンライン平文保護を主張してはならない。検証方法は documentation review と threat-model review とする。  
`FBVBS-REQ-0604`  `KEY_EXCHANGE` の返却値は生の共有秘密ではなく不透明ハンドルまたはサービス内部参照でなければならない。検証方法は interface test と code inspection とする。

## G.8. Update and Artifact Requirements

この subsection の既定 metadata は、requirement type=`update,security,interface`、source sections=`30, 39-40, Appendix L`、target components=`Update Verification Service, Kernel Code Integrity Service, microhypervisor`、status=`normative-frozen` とする。関連試験識別子は `T-UVS-<requirement-number>`、関連証拠識別子は `E-UVS-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0700`  更新搬送手段を `freebsd-update` に固定してはならない。検証方法は design inspection とする。  
`FBVBS-REQ-0701`  成果物には署名付きマニフェストが付随し、少なくとも format version、component type、target platform、hash、size、generation、security epoch、dependency、revocation reference を含まなければならない。検証方法は parser test と inspection とする。  
`FBVBS-REQ-0702`  更新メタデータ集合は freshness、freeze 攻撃検出、mix-and-match 防止、一貫性 snapshot view を扱えなければならない。検証方法は update adversarial test とする。  
`FBVBS-REQ-0703`  高保証運用プロファイルでは、署名鍵を HSM または同等保護で管理し、二者承認以上のリリース署名手順を要求しなければならない。検証方法は operational audit とする。  
`FBVBS-REQ-0704`  freshness 失敗、freeze 攻撃、期限切れメタデータ、stale mirror 検出時は `FRESHNESS_FAILED` を返さなければならない。検証方法は adversarial update test とする。  
`FBVBS-REQ-0705`  snapshot view 不整合、mix-and-match、役割分離違反検出時は `SNAPSHOT_INCONSISTENT` または `DEPENDENCY_UNSATISFIED` を返さなければならない。検証方法は adversarial metadata consistency test とする。

## G.9. FreeBSD Integration Requirements

この subsection の既定 metadata は、requirement type=`functional,security,interface`、source sections=`31-32`、target components=`FreeBSD front-end, FreeBSD kernel fork, integration hooks`、status=`normative-frozen` とする。関連試験識別子は `T-FBSD-<requirement-number>`、関連証拠識別子は `E-FBSD-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0800`  FreeBSD front-end は非信頼の ABI 変換層として扱い、その侵害時影響は誤要求、要求省略、サービス拒否に閉じ込めなければならない。検証方法は architecture review と adversarial test とする。  
`FBVBS-REQ-0801`  front-end は信頼サービスメモリ、第二レベルページテーブル、および一次監査ログに対する書換え能力を持ってはならない。検証方法は isolation test とする。  
`FBVBS-REQ-0802`  FreeBSD 介入点は、KLD ロード、資格情報変更、Jail、選択された MAC フック、Capsicum capability mode/rights 縮減導入点、鍵利用経路、`bhyve`/`vmm` 統合経路を少なくとも含まなければならない。検証方法は integration review と syscall/path test とする。  
`FBVBS-REQ-0803`  `mac(9)` の entry point checks だけで攻撃面を網羅したと主張してはならず、各不変条件に対して十分な介入点の存在を個別に実証しなければならない。検証方法は code audit と threat traceability review とする。  
`FBVBS-REQ-0804`  `vmm(4)` と passthrough が要求する boot-time 設定および loader 段階の介入点を設計対象に含めなければならない。検証方法は boot integration test とする。

## G.10. `bhyve` and Virtualization Requirements

この subsection の既定 metadata は、requirement type=`functional,security,interface`、source sections=`33-38, Appendix L`、target components=`microhypervisor, vmm front-end, bhyve userland`、status=`normative-frozen` とする。関連試験識別子は `T-VM-<requirement-number>`、関連証拠識別子は `E-VM-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-0900`  `bhyve` ユーザーランドは制御プレーンおよびデバイスモデル層として残し、実行プレーンの最終制御権はマイクロハイパーバイザーが保持しなければならない。検証方法は architecture inspection とする。  
`FBVBS-REQ-0901`  `/dev/vmm` と `libvmmapi` の高レベル ABI は、`VM_CREATE`, `VM_DESTROY`, `VM_RUN`, `VM_SET_REGISTER`, `VM_GET_REGISTER`, `VM_MAP_MEMORY`, `VM_INJECT_INTERRUPT`, `VM_ASSIGN_DEVICE`, `VM_RELEASE_DEVICE` に対応する本仕様書定義の意味論を維持しなければならない。ABI v1 の適合範囲外の既存操作は互換義務を負わず、必要なら明示的拡張としてのみ追加してよい。検証方法は compatibility test とする。  
`FBVBS-REQ-0902`  未分類 VM exit は fail-open で FreeBSD に委譲してはならず、fail-closed として停止・記録されなければならない。検証方法は exit classification test と fault injection とする。  
`FBVBS-REQ-0903`  guest memory は再利用前にゼロ化しなければならない。検証方法は memory reuse test とする。  
`FBVBS-REQ-0904`  passthrough デバイスは、IOMMU group、ACS、MSI/MSI-X 制御、interrupt remapping、reset 能力を満たした場合にのみ割り当ててよい。検証方法は device qualification test とする。  
`FBVBS-REQ-0905`  live migration と nested virtualization を本版の適合要件に含めてはならない。検証方法は documentation review とする。  
`FBVBS-REQ-0906`  VM 実行系 ABI は `Runnable` 状態の vCPU に対してのみ `VM_RUN` を許可し、その他状態では `INVALID_STATE` を返さなければならない。検証方法は VM lifecycle negative test とする。  
`FBVBS-REQ-0907`  vCPU 状態機械は少なくとも `Created`、`Runnable`、`Running`、`Blocked`、`Faulted`、`Destroyed` を持ち、`VM_RUN`、割込み待ち、fault、破棄要求に対する合法遷移を定義しなければならない。`Blocked` は外部イベントまたは割込み注入により再開可能な待機状態に限定しなければならない。検証方法は vCPU state-machine test と inspection とする。  
`FBVBS-REQ-0908`  ABI v1 は、各 vCPU の外部可視状態を返す `VM_GET_VCPU_STATUS` call を持たなければならない。検証方法は interface test と VM lifecycle test とする。  
`FBVBS-REQ-0909`  memory object と shared registration の寿命は、対応する release/unregister ABI により明示的に終了できなければならない。検証方法は resource lifecycle test とする。

## G.11. Quality and Supply-Chain Requirements

この subsection の既定 metadata は、requirement type=`quality,operational,security`、source sections=`41-45`、target components=`all TCB components, build system, CI, release pipeline`、status=`normative-frozen` とする。関連試験識別子は `T-QUAL-<requirement-number>`、関連証拠識別子は `E-QUAL-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-1000`  要求、設計、実装、試験、証拠の双方向トレーサビリティを維持しなければならない。検証方法は traceability audit とする。  
`FBVBS-REQ-1001`  TCB 変更は独立レビュア一名以上の承認を必要としなければならない。検証方法は review record audit とする。  
`FBVBS-REQ-1002`  SPARK 対象コードは実行時例外不在を証明しなければならない。検証方法は proof artifact review とする。  
`FBVBS-REQ-1003`  Rust TCB 部は `no_std`、`panic=abort`、固定 toolchain、`unsafe` 局所化、安全性契約文書化を満たさなければならない。検証方法は code inspection と build inspection とする。  
`FBVBS-REQ-1004`  hypercall parser、IPC parser、update parser、signature loader、log decoder、`bhyve` front-end 境界は fuzzing 対象に含めなければならない。検証方法は fuzz campaign evidence とする。  
`FBVBS-REQ-1005`  中核分岐は MC/DC を目標とし、困難な場合は代替基準と理由を記録しなければならない。検証方法は coverage review とする。  
`FBVBS-REQ-1006`  リリース成果物は再現可能ビルド、SBOM、署名付き provenance を持たなければならない。検証方法は supply-chain audit とする。

## G.12. Production Readiness Requirements

この subsection の既定 metadata は、requirement type=`operational,security,quality`、source sections=`Appendix F`、target components=`program governance, release authority, validation campaign`、status=`normative-frozen` とする。関連試験識別子は `T-PROD-<requirement-number>`、関連証拠識別子は `E-PROD-<requirement-number>` の導出規則で一意に決定する。

`FBVBS-REQ-1100`  本番宣言前に AMD 翻訳整合性経路の実証を完了しなければならない。検証方法は adversarial multiprocessor campaign とする。  
`FBVBS-REQ-1101`  本番宣言前に FreeBSD 介入点の十分性をコード読解と試験で実証しなければならない。検証方法は design review と integration campaign とする。  
`FBVBS-REQ-1102`  本番宣言前に更新 freshness、freeze 耐性、mix-and-match 耐性を実証しなければならない。検証方法は update adversarial campaign とする。  
`FBVBS-REQ-1103`  本番宣言前に一次監査ログ経路の実運用成立性を確認しなければならない。検証方法は operational drill とする。  
`FBVBS-REQ-1104`  本番宣言前に採用暗号実装の TCB 範囲、外部依存、証明範囲、監査根拠を確定しなければならない。検証方法は crypto review board と evidence audit とする。  
`FBVBS-REQ-1105`  本番宣言前にサポート対象 passthrough デバイス群ごとの qualification matrix を作成しなければならない。検証方法は device qualification report review とする。

# Appendix H. Protected Structure Catalog

## H.1. Purpose

v7 セクション 27 は Kernel State Integrity Service の三層分類（起動後不変、制御付き更新、保護対象外）を定義したが、個々の FreeBSD カーネル構造体の割当を列挙しなかった。本付録はその具体化であり、各構造体について、改竄時の攻撃効果、変更頻度、保護判定、実装インクリメント、判定根拠を示す。

## H.2. Tier A: 起動後不変（Immutable After Boot）

Tier A の構造体は、起動後に正当な変更が発生しない。第二レベルページングで read-only に設定し、以後 write-enable にする経路を持たない。

| 構造体 | 改竄時の攻撃効果 | 変更頻度 | 実装インクリメント | 根拠 |
|--------|----------------|---------|----------------------|------|
| `sysent[]`（syscall テーブル） | syscall フック。攻撃者が任意のカーネル関数を syscall エントリに差し替え可能 | ゼロ | 3 | コンパイル時定義。ランタイム変更の正当理由なし |
| IDT（Interrupt Descriptor Table） | 割り込みハイジャック。例外・割り込みハンドラを攻撃者制御コードに誘導 | ゼロ | 3 | ブート時設定後不変 |
| GDT（Global Descriptor Table） | セグメント記述子改竄。特権レベル境界の破壊 | ゼロ | 3 | ブート時設定後不変 |
| カーネル `.rodata` セクション | 定数改竄。文字列テーブル、エラーメッセージ、設定定数の書換え | ゼロ | 3 | 定義上不変 |
| `vop_vector`（VFS 操作テーブル） | ファイル操作リダイレクト。open/read/write を攻撃者制御関数に誘導 | ゼロ | 3 | コンパイル時定義。`.rodata` に配置されるべき |
| `cdevsw`（キャラクタデバイス操作テーブル） | デバイス操作リダイレクト | ゼロ（ドライバロード後） | 3 | KLD ロード時に登録後不変 |
| `filterops`（kqueue フィルタ操作テーブル） | イベント操作リダイレクト | ゼロ | 3 | コンパイル時定義 |
| カーネルテキスト領域の PTE（AMD のみ、静的コアカーネル範囲） | PFN スワップ。カーネルコードが指す物理ページを攻撃者制御ページに差替え | ゼロ | 4 | Intel は HLAT で保護。AMD は HLAT 相当の単一機構がないため、静的コアカーネル範囲の PTE 自体を不変化 |

**Tier A の実装:** マイクロハイパーバイザーが対象物理ページの第二レベルページテーブルエントリを read-only に設定する。write-enable に戻す hypercall は存在しない。KLD ロード時に `cdevsw` が新たに登録される場合は、Kernel Code Integrity Service が署名検証完了後に、新エントリを含むページを Tier A に追加登録する。AMD における KLD コード範囲の翻訳整合性は、Tier A の静的コアカーネル PTE 保護とは別に、Increment 4 で定義した AMD 翻訳整合性経路で扱う。

## H.3. Tier B: 制御付き更新（Controlled Update）

Tier B の構造体は、正当な変更が存在するが、変更頻度が低く、変更主体と条件を Kernel State Integrity Service が検証できる。第二レベルページングで read-only に設定し、変更時のみサービスが shadow copy 経由で更新する。

| 構造体 | 改竄時の攻撃効果 | 変更頻度 | 実装インクリメント | 根拠 |
|--------|----------------|---------|----------------------|------|
| `struct ucred`（資格情報） | 権限昇格。uid/gid 変更で root 取得 | 低（setuid/crget 時） | 3 | 権限昇格防止の核心 |
| `td->td_ucred` 等の ucred ポインタ | ポインタ差替え。偽 ucred への誘導で間接的権限昇格 | 低 | 3 | ucred 本体を保護してもポインタが自由なら迂回可能 |
| `struct prison`（Jail メタデータ） | Jail エスケープ。`pr_allow` 変更で全操作許可、`pr_path` 変更で chroot 脱出 | 極低（Jail 作成/破棄時） | 3 | Jail 境界は FreeBSD の主要分離機構 |
| `prison` ポインタ（`p->p_ucred->cr_prison` 等） | Jail ポインタ差替え。`prison0`（ホスト Jail）への誘導で Jail 脱出 | 極低 | 3 | prison 本体保護の補完 |
| `securelevel` 変数 | securelevel 迂回。不変ファイル変更、raw デバイスアクセス、ファイアウォール変更が可能に | 極低（手動変更のみ） | 3 | FreeBSD 固有の重要セキュリティ機構 |
| MAC ポリシー構造体（`mac_policy_list` 等） | MAC 無効化。強制アクセス制御の全ポリシーを無効化 | 極低（ポリシーロード時） | 3 | MAC Framework は FreeBSD の主要セキュリティ層 |
| Capsicum capability mode フラグ（`p_flag` 内 `P_CAPSICUM` 等） | サンドボックス脱出。capability mode からの離脱でグローバル名前空間アクセス復帰 | 極低（`cap_enter` は一方通行） | 3 | Capsicum はアプリケーション分離の基盤 |
| `pf` ルール構造体（`pf_krule` 等） | ファイアウォール無効化。全ポートの開放、アクセス制限の解除 | 極低（管理者が `pfctl` で変更時のみ） | 5 | サーバー環境のネットワーク境界 |
| `ipfw` ルール構造体 | 同上 | 極低 | 5 | 同上 |
| `p_textvp`（実行バイナリ vnode ポインタ） | Setuid 検証の基盤改竄。攻撃者が `p_textvp` を許可済みバイナリの vnode に差替えれば、Setuid 検証を迂回可能 | 極低（exec 時のみ） | 5 | Setuid 検証が依拠する識別情報 |

**Tier B の実装:** Kernel State Integrity Service は、パーティション内部に shadow copy を保持する。変更要求を受けると、(1) callsite 検証（呼出元アドレスが正規の発行箇所か確認）、(2) ポリシー検証（Setuid DB 照合、securelevel 整合性等）、(3) shadow copy 上で変更を実行、(4) 対象ページの第二レベルページングを一時的に write-enable、(5) shadow copy から対象ページへ memcpy、(6) 即座に read-only に戻す。複数 CPU コアが当該ページにアクセスする場合は、マイクロハイパーバイザーが他コアの書込みを一時停止する。`pf`/`ipfw` ルールのような大きな構造体は、新ページを確保→新ページを Tier B 登録→ルールポインタを原子的に切替え→旧ページを登録解除、という原子的置換方式を用いる。

## H.4. Tier C: 保護対象外（高頻度可変、本バージョンで非保護）

| 構造体 | 改竄時の攻撃効果 | 変更頻度 | 非保護の理由 |
|--------|----------------|---------|------------|
| `struct filedesc`（fd テーブル） | 他プロセスの open 済み fd を差込み、ucred チェックなしで読書き | 極高（全 open/close/dup） | 変更頻度が高すぎて第二レベルページング保護は性能破綻 |
| `struct file`（個別ファイル記述子） | `f_ops` 差替え等 | 高 | 同上 |
| `struct socket` | ソケットハイジャック | 高 | 同上 |
| `struct inpcb` | 接続パラメータ改竄 | 高 | 同上 |
| ルーティングテーブル（動的環境） | トラフィックリダイレクト | 中〜高 | 動的ルーティング環境では正当変更が高頻度 |
| スレッドスケジューリング構造体 | スケジューリング操作 | 極高 | カーネルの最高頻度操作 |
| ネットワークバッファ（mbuf 等） | 通信データ傍受/改竄 | 極高 | データパス上のバッファ |
| VFS キャッシュ | ファイルデータの一時的改竄 | 高 | キャッシュの性質上、頻繁な更新が不可避 |

**Tier C に対する補足:** これらの構造体は、攻撃者がカーネルの任意データ読書きを持つ場合の最終的な攻撃パスとなる。fd テーブル攻撃は最も直接的であり、他プロセスの open 済み fd のカーネルアドレスを発見して自プロセスの fd テーブルに挿入すれば、ucred チェックなしで読書きが成立する。この攻撃は高度な技術を要する（KASLR 下での fd アドレス発見が必要）ため、スクリプトキディレベルでは困難だが、国家レベルの攻撃者には実行可能である。将来のバージョンで fd テーブルへの補助的検出機構（異常パターン検知等）を検討する余地はあるが、本バージョンでは明示的限界として残す。

# Appendix I. Service Failure Impact Matrix

## I.1. Purpose

v7 セクション 49 は障害意味論の原則を定義したが、各サービス障害の具体的影響を列挙しなかった。本付録は、各信頼サービスが障害を起こした場合に、他のサービスと保護性質に与える影響を網羅的に示す。

## I.2. 前提

マルチサーバー設計により、各サービスは独立パーティションで動作する。あるサービスが障害を起こしても、マイクロハイパーバイザーが管理する第二レベルページング保護は維持される。したがって、障害サービスの「機能」は停止するが、既に設定済みの「分離」は維持される。

## I.3. 影響マトリクス

| 障害サービス | 停止する機能 | 維持される保護 | FreeBSD への影響 | 回復方法 |
|---|---|---|---|---|
| Kernel Code Integrity Service | 新規 KLD の署名検証と execute 権限付与。新規の CR/MSR インターセプト設定 | 既存コードページの W^X（第二レベルページングが維持）。既設定の CR ピニング（マイクロハイパーバイザーが維持） | 新規 KLD ロード不可。既存カーネルとモジュールは正常動作継続 | パーティション再起動。再起動後にイメージ再検証。既存 W^X 設定は破壊されないため、再起動中の追加リスクは「新規 KLD が検証なしで実行される」可能性のみ。ただし既定方針で未署名 KLD は execute 不可であるため、このリスクはサービス停止中の KLD ロード試行を FreeBSD 側で保留することで緩和される |
| Kernel State Integrity Service | Tier B の新規変更承認（ucred 変更、Setuid 検証、Jail パラメータ変更等） | 既存の Tier A read-only 保護。既存の Tier B read-only 保護（変更ができなくなるだけで、既設定値は維持） | setuid exec がブロックされる。Jail 作成/変更がブロックされる。securelevel 変更がブロックされる。通常の read 操作（ucred 参照等）は影響なし | パーティション再起動。保護テーブルを永続メモリから復元。復元中の Tier B 保護は第二レベルページングが維持するため、既存値は安全 |
| Identity Key Service | 新規鍵インポート、署名操作、鍵交換操作 | 他サービスのメモリ分離。他サービスの機能 | TLS ハンドシェイク不可。SSH ホスト認証不可。IPsec IKE 再ネゴシエーション不可。既存セッション（セッション鍵が FreeBSD 側にあるもの）は継続 | パーティション再起動。鍵素材を安全なストレージ（TPM シール等）から再ロード |
| Storage Key Service | 新規ボリュームマウント（鍵アンロック）。進行中の暗号操作 | 他サービスのメモリ分離。鍵素材はサービスパーティション内に残留（再起動まで抽出不可） | マウント済みボリュームの I/O が停止。新規マウント不可 | パーティション再起動。鍵素材を再ロード。マウント済みボリュームは再マウントが必要 |
| Update Verification Service | 成果物の署名/世代番号/依存関係検証 | 他サービスのメモリ分離。既に検証済みでロード済みの成果物は影響なし | 新規アップデートの適用不可。KLD の新規ロード不可（Kernel Code Integrity Service が Update Verification Service に依存する場合） | パーティション再起動。検証状態を再構築 |
| マイクロハイパーバイザー自体 | **全保護が崩壊** | なし | **全システム停止** | システム再起動のみ。マイクロハイパーバイザーの障害は設計の最悪シナリオであり、形式検証の最大の動機 |

## I.4. 重要な観察

マイクロハイパーバイザー以外のサービス障害では、**既設定の保護は維持される**。これは、第二レベルページングの read-only 設定がマイクロハイパーバイザーに管理されており、サービスが停止しても自動的に write-enable に戻らないためである。停止するのは「新規変更の承認」であり、「既存保護の維持」ではない。この性質がマルチサーバー設計の最大の利点である。

# Appendix J. Performance Budget

## J.1. Purpose

v7 セクション 48 はパフォーマンス原則を定義したが、数値目標を具体化しなかった。本付録は、主要操作の追加コスト目標を定義する。

## J.2. 基本コスト参照値

| 操作 | ベースコスト（FBVBS なし） | 備考 |
|------|--------------------------|------|
| 通常 syscall（getpid 等） | ~100-300ns | 最軽量 syscall |
| execve | ~1-5ms | ファイル読込、ELF パース、マッピング |
| open/close | ~1-10µs | VFS 層の処理 |
| fork | ~100µs-1ms | ページテーブルコピー |
| TLS ハンドシェイク | ~1-10ms | 鍵交換 + 署名 |
| ZFS 128KB sequential read | ~50-200µs | ディスク I/O 含む |
| VM exit（I/O） | ~1-3µs | VMCS 保存/復元 |

## J.3. FBVBS 追加コスト目標

| 操作 | 追加コスト目標 | IPC 回数 | 根拠 |
|------|--------------|---------|------|
| **通常 syscall（FBVBS 非関与）** | 実質ゼロに近いことを目標 | 0 | FBVBS は通常 syscall に介入しない。追加コストは第二レベルページング由来の小さな TLB 影響に限ることを目標とする |
| **Tier B 読取り（ucred 参照等）** | 追加 IPC なし（実質ゼロに近いことを目標） | 0 | Tier B は第二レベルページングで read-only。CPU は直接メモリ読取りし、VMCALL を要求しない |
| **Tier B 変更（ucred 更新、Jail 変更等）** | 数µs〜十数µs級を目標 | 1 | VMCALL → マイクロハイパーバイザー → Kernel State Integrity Service → shadow copy 更新 → ページ write-enable/copy/read-only サイクル → 返却 |
| **Setuid exec 検証** | 十数µs級を目標 | 1 | execve のベースコストに対して小さい割合に抑えることを目標とする。ハッシュ照合はメモリ内 DB ルックアップ |
| **KLD ロード（署名検証）** | 100ms〜サブ秒級を許容 | 2 | 署名検証（暗号演算）+ 世代番号検証 + EPT 設定。低頻度操作のため許容 |
| **TLS 署名（Identity Key Service）** | 数µs〜十数µs級を目標 | 1 | VMCALL → Identity Key Service → 署名演算 → 返却。TLS ハンドシェイク全体に対して小さい割合に抑えることを目標とする |
| **ZFS I/O（Storage Key Service、バッチ）** | < 10% を目標 | 1/バッチ | VMCALL コストを I/O コストで償却するにはバッチ化が必要であり、バッチサイズ調整で追加コストを抑える |
| **bhyve VM exit（ファストパス: EPT 違反等）** | サブµs級を目標 | 0 | マイクロハイパーバイザー内で完結。FreeBSD への転送なし |
| **bhyve VM exit（スローパス: I/O エミュレーション）** | 数µs級を目標 | 1 | マイクロハイパーバイザー → FreeBSD 転送 → デバイスモデル処理 → VMCALL → 再開。高頻度 exit では無視できないため、分類とバッチ化が重要 |
| **一次監査ログ書込み** | サブµs〜数µs/レコードを目標 | 0 | マイクロハイパーバイザー内のリングバッファ書込み + UART 出力（非同期）。通常操作には影響しない（セキュリティイベント時のみ） |
| **ミラーログ読取り（FreeBSD 側）** | 追加 IPC なし（実質ゼロに近いことを目標） | 0 | 共有リングバッファの直接読取り |

## J.4. 性能に関する禁止事項

通常の syscall に毎回 VMCALL を挿入する設計は禁止する。Tier B の読取り操作に VMCALL を要求する設計は禁止する。ログ書込みが通常 I/O パスの同期的ブロッカーとなる設計は禁止する。

# Appendix K. Implementation Roadmap

## K.1. Purpose

v7 は依存関係に基づく実装順序を明示していなかった。本付録は、最終実装へ直接収束する実装インクリメントを定義する。

各インクリメントは依存関係と検証順序を示す。途中インクリメントの完了は、FBVBS v7 の完全適合または高保証適合の達成を意味しない。特に Intel では Kernel Translation Integrity の要件上、HLAT 統合が完了するまで高保証適合は成立しない。さらに、各インクリメントは最終実装に残る成果物で構成されなければならず、「暫定フェーズ専用コード」や「使い捨て骨組み」を認めない。

## K.2. インクリメント定義

### Increment 1: マイクロハイパーバイザー基盤

**目標:** FreeBSD を deprivileged host として起動し、最低1つの信頼サービスパーティションを稼働させる。

**成果物:**
- Ada/SPARK マイクロハイパーバイザー: パーティション管理、第二レベルページング、IPC、VMCALL ハンドリング、一次監査ログ（UART）
- Intel VT-x 対応（AMD は Increment 4）
- 最小限のブートシーケンス: UEFI → マイクロハイパーバイザー → 空の信頼サービスパーティション → FreeBSD パーティション
- FreeBSD が VMX non-root で正常起動することの実証

**検証:**
- FreeBSD が信頼サービスパーティションのメモリにアクセスできないことの実証
- IPC ラウンドトリップ時間の計測
- GNATprove によるパーティション管理ロジックの実行時例外不在証明

### Increment 2: Kernel Code Integrity Service

**目標:** W^X 強制と KLD 署名検証。

**成果物:**
- Kernel Code Integrity Service パーティション（Ada/SPARK）
- fbvbs.ko 基盤（Rust）: VMCALL ラッパー、KLD ロードフック
- FreeBSD カーネル .text の W^X 設定
- MBEC/GMET を用いたユーザー/スーパーバイザー実行分離
- CR ピニング（CR0.WP, CR4.SMEP/SMAP）
- KLD 署名検証パイプライン

**検証:**
- カーネルコードページへの書込み試行が第二レベルページング違反を引き起こすことの実証
- 未署名 KLD のロード拒否の実証
- CR 変更試行がインターセプトされることの実証

### Increment 3: Kernel State Integrity Service

**目標:** Tier A/B 保護と Setuid 検証。

**成果物:**
- Kernel State Integrity Service パーティション（Ada/SPARK）
- Tier A 保護: sysent, IDT, GDT, .rodata, vop_vector, cdevsw, filterops
- Tier B 保護: ucred + ポインタチェーン, prison + ポインタチェーン, securelevel, MAC, Capsicum
- Setuid 検証ロジックと許可 DB ローダ
- shadow copy 更新機構
- マルチコア安全性（write-enable 区間の他コアブロック）

**検証:**
- Tier A 構造体への書込み試行が違反を引き起こすことの実証
- Tier B 構造体への直接書込み試行が違反を引き起こすことの実証
- ポインタ差替え試行が検出されることの実証
- Setuid 検証: 許可済みバイナリの exec が成功し、未許可バイナリの exec が拒否されることの実証
- マルチコア競合テスト

### Increment 4: Identity Key Service + Storage Key Service + AMD 対応

**目標:** 鍵隔離と AMD プラットフォーム対応。

**成果物:**
- Identity Key Service パーティション（Ada/SPARK）: IMPORT_KEY, SIGN, KEY_EXCHANGE, DERIVE, DESTROY
- Storage Key Service パーティション（Ada/SPARK）: ディスク鍵管理、レート制限、アクセスログ
- 暗号ライブラリ統合（Ada/SPARK primitive + 外部ライブラリの隔離利用方針確定）
- AMD SVM 対応: NPT、GMET、AMD 固有のパーティション管理
- AMD 翻訳整合性経路: NPT write-protect + ページテーブル更新トラップ + シャドウ翻訳

**検証:**
- Identity Key Service から鍵素材が外部に漏洩しないことの実証
- Storage Key Service のレート制限が機能することの実証
- AMD 翻訳整合性: PFN 差替え、PTE 改竄、TLB invalidate race、マルチコア更新競合テスト
- 暗号操作の定数時間性の実測

### Increment 5: bhyve 統合 + Kernel State Integrity Service 拡張

**目標:** 仮想マシンホスティングと保護対象拡張。

**成果物:**
- vmm.ko の VMCALL 化: VM 作成/破棄/実行/メモリ登録/割込み注入
- VM exit ルーティング: ファストパス（EPT 違反、CR/MSR）とスローパス（I/O、割込み）
- guest memory 所有権モデル: マイクロハイパーバイザーが最終割当権を保持
- IOMMU ドメイン管理: passthrough デバイスの DMA 分離
- Tier B 拡張: pf/ipfw ルール、p_textvp

**検証:**
- bhyve VM が正常に起動・動作することの実証
- VM エスケープ後に信頼サービスメモリにアクセスできないことの実証
- guest memory ゼロ化の実証
- passthrough デバイスの DMA が信頼サービスメモリに到達しないことの実証
- pf ルール改竄試行が検出されることの実証

### Increment 6: Update Verification Service + HLAT 統合

**目標:** 搬送手段非依存の更新検証と Intel HLAT 統合。

**成果物:**
- Update Verification Service パーティション（Ada/SPARK）
- 署名付きマニフェストの検証: フォーマット、署名、世代番号、依存関係、失効
- ロールバック防止: TPM NV 領域または同等の version store
- Intel HLAT 統合: カーネルテキスト領域の翻訳整合性
- A/B パーティショニング（マイクロハイパーバイザーの安全な更新）

**検証:**
- ロールバック攻撃（古いバージョンへの差替え）が検出されることの実証
- 署名不正の成果物が拒否されることの実証
- HLAT 有効時に PFN スワップ攻撃が防止されることの実証
- 更新失敗時のフォールバック動作の実証

### Increment 7: 品質保証と継続改善

**目標:** 形式検証完了、セキュリティ監査、認証準備。

**活動:**
- マイクロハイパーバイザーの GNATprove 証明完了
- 全 hypercall パーサ、IPC パーサ、更新パーサの継続的 fuzzing
- 中核分岐の MC/DC カバレッジ達成
- 再現可能ビルド + SBOM + 署名付き provenance の確立
- 独立セキュリティ監査の実施
- AMD 翻訳整合性の最終立証
- 本番宣言前の Appendix F 立証課題の完了

# Appendix L. Frozen Hypercall ABI Catalog

## L.1. Purpose

v7 セクション 20 は hypercall ABI の原則を定義し、Appendix D は共有コマンドページのレイアウトを定義した。本付録は、ABI v1 における call_id、要求本文、応答本文、前提条件、事後条件、許可エラーコードを凍結する。実装は本付録で定義された構造と意味論を変更してはならず、互換性を破る変更は ABI version を増やさなければならない。

## L.1.A. 共通規則

すべての call は同期呼出である。要求本文と応答本文は little-endian、自然アラインメント、padding 0 初期化を必須とする。成功時に返されるハンドル値 0 は常に無効であり、返してはならない。失敗時に無効値を明示する必要がある応答本文では、0 を sentinel として用いてよい。各 call table の「許可エラー」は、その call 固有の意味論に由来するエラー集合を示す。これに加えて、ABI 共通前処理に由来する `INVALID_PARAMETER`、`RESOURCE_BUSY`、`ABI_VERSION_UNSUPPORTED`、`REPLAY_DETECTED` は全 call で返してよい。

要求に含まれる partition ID、vCPU ID、ハンドル、オブジェクト ID が存在しない場合は `NOT_FOUND` とする。現在状態で許されない操作は `INVALID_STATE` とする。資源不足または上限超過は `RESOURCE_EXHAUSTED` とする。重複作成は `ALREADY_EXISTS` とする。出力バッファ不足は `BUFFER_TOO_SMALL` とする。世代が現在 version store より古いと判定された場合は `ROLLBACK_DETECTED` とする。

Appendix L の caller column は次の意味を持つ。`FreeBSD` は FreeBSD host partition 全体を意味する。`fbvbs.ko` は FreeBSD host partition 内で、`fbvbs.ko` に属する許可 callsite table 上の RIP からのみ発行できる操作を意味する。`vmm.ko` は FreeBSD host partition 内で、`vmm.ko` に属する許可 callsite table 上の RIP からのみ発行できる操作を意味する。`INVALID_CALLER` は、現在 partition が要求された caller class に属さない場合、または caller class が要求する許可 module/callsite table に一致しない場合に返さなければならない。KSI Tier B 更新のようにより細かい callsite policy を持つ操作では、partition/class 検査通過後の詳細不一致に `CALLSITE_REJECTED` を用いてよい。

## L.1.B. Frozen Enumerations

ABI v1 で外部可視な列挙値は次のとおり固定する。

| 名称 | 値 |
|---|---|
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
| `PARTITION_FLAG_AUTOSTART` | 0x0001 （ABI v1 では予約。0 でなければならない） |
| `MEM_PERM_R` | 0x0001 |
| `MEM_PERM_W` | 0x0002 |
| `MEM_PERM_X` | 0x0004 |
| `KSI_CLASS_UCRED` | 1 |
| `KSI_CLASS_PRISON` | 2 |
| `KSI_CLASS_SECURELEVEL` | 3 |
| `KSI_CLASS_MAC` | 4 |
| `KSI_CLASS_CAPSICUM` | 5 |
| `KSI_CLASS_FIREWALL` | 6 |
| `KSI_CLASS_P_TEXTVP` | 7 |
| `IKS_KEY_ED25519` | 1 |
| `IKS_KEY_ECDSA_P256` | 2 |
| `IKS_KEY_RSA3072` | 3 |
| `IKS_KEY_X25519` | 4 |
| `IKS_KEY_ECDH_P256` | 5 |
| `IKS_OP_SIGN` | 0x0001 |
| `IKS_OP_KEY_EXCHANGE` | 0x0002 |
| `IKS_OP_DERIVE` | 0x0004 |
| `CR_NUMBER_CR0` | 0 |
| `CR_NUMBER_CR3` | 3 |
| `CR_NUMBER_CR4` | 4 |
| `UVS_OBJECT_KEY` | 1 |
| `UVS_OBJECT_ARTIFACT` | 2 |
| `VM_FLAG_X2APIC` | 0x0001 |
| `VM_FLAG_NESTED_VIRT_DISABLED` | 0x0002 |
| `VM_RUN_FLAG_NONE` | 0x0000 |
| `VM_REG_RIP` | 1 |
| `VM_REG_RSP` | 2 |
| `VM_REG_RFLAGS` | 3 |
| `VM_REG_CR0` | 4 |
| `VM_REG_CR3` | 5 |
| `VM_REG_CR4` | 6 |
| `VM_DELIVERY_FIXED` | 1 |
| `VM_DELIVERY_NMI` | 2 |
| `CR_ACCESS_READ` | 1 |
| `CR_ACCESS_WRITE` | 2 |
| `FAULT_CODE_PARTITION_INTERNAL` | 1 |
| `FAULT_CODE_MEASUREMENT_FAILURE` | 2 |
| `FAULT_CODE_VM_EXIT_UNCLASSIFIED` | 3 |
| `CAP_BITMAP0_MBEC_OR_GMET` | bit 0 |
| `CAP_BITMAP0_HLAT` | bit 1 |
| `CAP_BITMAP0_CET` | bit 2 |
| `CAP_BITMAP0_AESNI` | bit 3 |

追加の固定値規則は次のとおりとする。

| 名称 | 値/形式 |
|---|---|
| `capability_mask` | `bit 0=partition manage`, `bit 1=memory map`, `bit 2=memory permission set`, `bit 3=shared memory register`, `bit 4=KCI access`, `bit 5=KSI access`, `bit 6=IKS access`, `bit 7=SKS access`, `bit 8=UVS access`, `bit 9=VM manage`, `bit 10=audit/diag` |
| `recovery_flags` | `bit 0=restore persistent state`, `bit 1=clear volatile caches`, `bit 2=enable extended remeasure checks`。ABI v1 では remeasure 自体は常に必須であり、bit2 は追加検査を有効化するだけで、省略可能な remeasure を意味してはならない |
| `partition state` numeric assignment | `Created=1`, `Measured=2`, `Loaded=3`, `Runnable=4`, `Running=5`, `Quiesced=6`, `Faulted=7`, `Destroyed=8` |
| `credential operation class` | `1=exec credential elevation`, `2=setuid-family`, `3=setgid-family` |
| `credential id mask` | `bit 0=ruid valid`, `bit 1=euid valid`, `bit 2=suid valid`, `bit 3=rgid valid`, `bit 4=egid valid`, `bit 5=sgid valid` |
| `measurement_epoch` | `PARTITION_MEASURE` または remeasure を伴う `PARTITION_RECOVER` 成功ごとに 1 以上で単調増加する 64-bit 値。未測定 `Created` 状態では 0、destroy tombstone でも直前値を保持する |
| `service_kind` | `PARTITION_KIND_TRUSTED_SERVICE` では、測定前は `SERVICE_KIND_NONE`、測定後は対応 `SERVICE_KIND_*` を返す。`PARTITION_KIND_FREEBSD_HOST` と `PARTITION_KIND_GUEST_VM` では常に `SERVICE_KIND_NONE` を返す |
| `verdict` | `0=denied`, `1=approved` |
| `failure_bitmap` | `bit 0=signature`, `bit 1=revocation`, `bit 2=generation`, `bit 3=rollback`, `bit 4=dependency`, `bit 5=snapshot`, `bit 6=freshness` |
| `exit_reason` | `1=PIO`, `2=MMIO`, `3=external interrupt`, `4=EPT/NPT violation`, `5=control register access`, `6=MSR access`, `7=halt`, `8=shutdown`, `9=unclassified fault` |
| `vcpu state` numeric assignment | `Created=1`, `Runnable=2`, `Running=3`, `Blocked=4`, `Faulted=5`, `Destroyed=6` |
| `memory_limit_bytes` | 当該 partition に現在 map 済みの page-aligned guest-physical bytes の総量上限。loaded executable segment、`MEMORY_MAP`/`VM_MAP_MEMORY` による map、bootstrap metadata page、各 vCPU command page、partition 自身へ map された shared page を含む。未 map object 予約容量は含まない。新規 map、load、自動 page 割当がこの上限を超える場合、当該操作は `RESOURCE_EXHAUSTED` で失敗しなければならない |
| `EPT/NPT access_bits` | `bit 0=read`, `bit 1=write`, `bit 2=execute` |
| boolean/enable fields | ABI v1 では `0=false`, `1=true` とし、他値は `INVALID_PARAMETER` |
| hash algorithm | ABI v1 で `payload_hash`, `artifact_hash`, `measured_hash` はすべて raw SHA-384 48-byte とする。固定長配列に格納する場合、残余バイトは 0 でなければならない |
| `PARTITION_CREATE.flags` | ABI v1 では 0 のみ有効。非ゼロは `INVALID_PARAMETER` |
| `MEMORY_ALLOCATE_OBJECT.object_flags` | ABI v1 では `0x0000=private`, `0x0001=shareable`, `0x0002=guest-memory` |
| `VM_FLAG_X2APIC` | guest x2APIC 公開を要求する。未対応プラットフォームでは `NOT_SUPPORTED_ON_PLATFORM` |
| `VM_FLAG_NESTED_VIRT_DISABLED` | nested virtualization を明示的に無効化する。ABI v1 既定でも無効だが、設定値の明示を許す |
| `vm_flags` | ABI v1 では `VM_FLAG_X2APIC` と `VM_FLAG_NESTED_VIRT_DISABLED` 以外の bit は予約であり、0 でなければならない |
| `run_flags` | ABI v1 では `VM_RUN_FLAG_NONE` のみ有効 |
| `allowed_ops` | ABI v1 では `IKS_OP_SIGN`, `IKS_OP_KEY_EXCHANGE`, `IKS_OP_DERIVE` の OR のみ有効。その他 bit は予約であり 0 でなければならない |
| `entry_ip` | 初期 guest virtual instruction pointer。0 は manifest 記録値を使う要求を意味し、非ゼロは manifest 記録値と一致しなければならない |
| `vcpu_id` | `0..vcpu_count-1` の密な整数。VM 作成後は recovery を含めて再利用・再番号付けしてはならない |
| `PIO/MMIO width` | `1=8-bit`, `2=16-bit`, `4=32-bit`, `8=64-bit` |
| `DIAG_GET_PARTITION_LIST.entries` | `count` 個の `struct { uint64_t partition_id; uint32_t state; uint16_t kind; uint16_t service_kind; }` を連続格納 |
| `capability_bitmap1` | ABI v1 では全ビット予約。0 を返さなければならない |
| `source_component` | `1=microhypervisor`, `2=Kernel Code Integrity Service`, `3=Kernel State Integrity Service`, `4=Identity Key Service`, `5=Storage Key Service`, `6=Update Verification Service`, `7=FreeBSD front-end`, `8=bhyve/vmm path` |
| `severity` | `0=debug`, `1=info`, `2=notice`, `3=warning`, `4=error`, `5=critical`, `6=alert` |
| `event_code` | `1=boot complete`, `2=partition fault`, `3=policy deny`, `4=signature reject`, `5=rollback detect`, `6=DMA deny`, `7=VM exit fail-closed`, `8=service restart` |

## L.1.C. Object ID and Handle Namespace Rules

ABI v1 における object ID および handle は、原則として 64 ビットの不透明値であり、0 は無効とする。caller は値のビット配置や並び順に意味を見出してはならない。ただし Kernel State Integrity Service に渡す object reference 群については、ABI v1 では guest-physical base address を object reference として用いる。

| 名称 | 発行主体 | 消費主体 | 生存期間 |
|---|---|---|---|
| `image_object_id` | boot artifact registry | `PARTITION_CREATE`, `PARTITION_MEASURE`, `PARTITION_LOAD_IMAGE` | 対応成果物が boot 中有効な間 |
| `manifest_object_id` | boot artifact registry | `PARTITION_MEASURE`, `KCI_VERIFY_MODULE` | 対応マニフェストが boot 中有効な間 |
| `module_object_id` | boot artifact registry | `KCI_VERIFY_MODULE` | 検証対象モジュール成果物が boot 中有効な間 |
| `measurement_digest_id` | partition manager | `PARTITION_MEASURE` 応答受領側の監査・相関処理 | 同一 boot 中有効 |
| `verified_manifest_set_id` | Update Verification Service | `UVS_VERIFY_ARTIFACT` | 同一 boot 中、失効または再起動まで |
| `memory_object_id` | microhypervisor memory-object allocator | `MEMORY_MAP`, `MEMORY_REGISTER_SHARED`, `VM_MAP_MEMORY`, `MEMORY_RELEASE_OBJECT` | 解放または再起動まで |
| `shared_object_id` | `MEMORY_REGISTER_SHARED` | caller 監査用および別出力ページ管理、`MEMORY_UNREGISTER_SHARED` | 共有解除または再起動まで |
| `object_id` | FreeBSD front-end | KSI register 系 call | guest-physical object が有効な間 |
| `pointer_object_id` | FreeBSD front-end | `KSI_REGISTER_POINTER` | guest-physical pointer object が有効な間 |
| `target_set_id` | Kernel State Integrity Service | `KSI_REGISTER_POINTER` | KSI 再初期化または再起動まで |
| `caller_ucred_object_id` | FreeBSD front-end | `KSI_VALIDATE_SETUID` | guest-physical ucred object が有効な間 |
| `jail_context_id` | FreeBSD front-end | `KSI_VALIDATE_SETUID` | guest-physical jail-related object が有効な間 |
| `mac_context_id` | FreeBSD front-end | `KSI_VALIDATE_SETUID` | guest-physical MAC context object が有効な間 |
| `prison_object_id` | FreeBSD front-end | `KSI_ALLOCATE_UCRED` | guest-physical prison object が有効な間 |
| `template_ucred_object_id` | FreeBSD front-end | `KSI_ALLOCATE_UCRED` | guest-physical template ucred object が有効な間 |
| `ucred_object_id` | Kernel State Integrity Service | `KSI_ALLOCATE_UCRED` 応答受領側 | guest-physical ucred object が有効な間 |
| `key_handle`, `derived_key_handle`, `derived_secret_handle` | Identity Key Service | IKS 系 call | 明示破棄またはサービス再起動まで |
| `dek_handle` | Storage Key Service | SKS 系 call | 明示破棄またはサービス再起動まで |
| `device_id` | platform device registry | `VM_ASSIGN_DEVICE`, `VM_RELEASE_DEVICE` | 同一 boot 中、物理デバイスが利用可能な間 |

同一 namespace 内では、値は再起動まで再利用してはならない。発行主体が異なる namespace は相互に独立であり、`key_handle` を `memory_object_id` として解釈することは常に `INVALID_PARAMETER` とする。

KSI object reference 群については、ABI v1 では `object_id` と `pointer_object_id` は対応 object の guest-physical base address をそのまま保持しなければならない。したがって `object_id` は `guest_physical_address` と一致しなければならず、不一致は `INVALID_PARAMETER` とする。`pointer_object_id` も登録対象 pointer object の guest-physical base address と一致しなければならない。

ABI v1 で caller が opaque ID を取得する frozen 経路は次のとおりとする。`image_object_id`、`manifest_object_id`、`module_object_id` は `DIAG_GET_ARTIFACT_LIST` の返却する `fbvbs_artifact_catalog_v1` から取得する。`device_id` は `DIAG_GET_DEVICE_LIST` の返却する `fbvbs_device_catalog_v1` から取得する。`memory_object_id` は `MEMORY_ALLOCATE_OBJECT` の返却値として取得する。`shared_object_id` は `MEMORY_REGISTER_SHARED` の返却値として取得し、不要になったときは `MEMORY_UNREGISTER_SHARED` で解放しなければならない。`target_set_id` は `KSI_CREATE_TARGET_SET` の返却値として取得する。KSI object reference 群は FreeBSD front-end が直前に guest virtual-to-physical 変換して得る。`PARTITION_MEASURE` と `KCI_VERIFY_MODULE` は、対応する artifact と manifest_object_id の組を caller が明示入力し、その組に対して事前に `UVS_VERIFY_MANIFEST_SET` と `UVS_VERIFY_ARTIFACT` で `verdict=1` を返していることを前提条件とする。artifact catalog の internal binding は補助キャッシュにすぎず、ABI 判定の正本は caller が渡した `(artifact object id, manifest object id)` の組と UVS 承認記録の一致にある。`UVS_VERIFY_ARTIFACT` は `manifest_object_id` を明示入力として受け取り、承認対象を verified manifest set 内の単一 manifest に束縛しなければならない。UVS 承認記録は `(verified_manifest_set_id, artifact_hash, manifest_object_id)` の三つ組により内部保存され、`UVS_VERIFY_ARTIFACT` 成功時に生成されなければならない。caller が opaque ID を推測生成してはならない。

artifact catalog では、manifest と image/module の対応を `related_index` で固定する。`object_kind=2` の manifest entry の `related_index` は対応する image または module entry の index を指す。`object_kind=1` または `3` の entry の `related_index` は対応する manifest entry の index を指す。無効 index は `INVALID_PARAMETER` とする。

```c
struct fbvbs_artifact_catalog_v1 {
    uint32_t count;
    uint32_t reserved0;
    struct {
        uint64_t object_id;
        uint32_t object_kind; /* 1=image, 2=manifest, 3=module */
        uint32_t related_index;
        uint8_t  payload_hash[48];
    } entries[];
};

struct fbvbs_device_catalog_v1 {
    uint32_t count;
    uint32_t reserved0;
    struct {
        uint64_t device_id;
        uint16_t segment;
        uint8_t  bus;
        uint8_t  slot_function;
    } entries[];
};
```

## L.1.D. Frozen Payload and Encoding Rules

ABI v1 の可変長バイト列フィールドは、次の固定規則に従う。

| 対象 | 形式 |
|---|---|
| `KSI_MODIFY_TIER_B.patch` | `struct { uint32_t write_offset; uint32_t write_length; uint8_t replacement[4000]; }`。`patch_length` は `8 + write_length` と一致しなければならない |
| `IKS_SIGN.signature` | `ED25519` は 64-byte raw、`ECDSA_P256` は 64-byte raw `r||s` big-endian、`RSA3072` は RSASSA-PSS-SHA384 の 384-byte signature |
| `IKS_KEY_EXCHANGE.peer_public_key` | `X25519` は 32-byte raw、`ECDH_P256` は SEC1 uncompressed 65-byte |
| `IKS_KEY_EXCHANGE.derive_flags` | ABI v1 では 0 のみ有効 |
| `IKS_DERIVE.params` | `struct { uint32_t kdf_id; uint32_t salt_length; uint32_t info_length; uint32_t reserved0; uint8_t bytes[3976]; }`。`kdf_id=1` は HKDF-SHA256、`bytes = salt || info` |
| `IKS_IMPORT_KEY.key_material_page_gpa` | `ED25519` は 32-byte raw secret scalar、`ECDSA_P256` は SEC1 DER-encoded EC private key、`RSA3072` は PKCS#8 DER private key、`X25519` は 32-byte raw secret scalar、`ECDH_P256` は SEC1 DER-encoded EC private key |
| `SKS_*_BATCH.io_descriptor_page_gpa` | 4096-byte page containing `descriptor_count` 個の `struct { uint64_t source_gpa; uint64_t destination_gpa; uint64_t logical_block_index; uint32_t byte_length; uint32_t reserved0; }` |
| `SKS_IMPORT_DEK.key_material_page_gpa` | 先頭 `key_length` byte に raw DEK を格納し、残余は 0 とする |
| `VM_RUN.exit_payload` | `exit_reason` ごとに L.1.F の固定サブ構造を用いる |
| `UVS_VERIFY_MANIFEST_SET.manifest_set_page_gpa` | `count/reserved0/manifest_gpa[count]` 形式の metadata set index page を格納する page |

`fbvbs_signed_manifest_v1` は次の論理形式に従う: `struct { uint32_t format_version; uint32_t signature_algorithm; uint32_t manifest_length; uint32_t signature_length; uint8_t bytes[]; }`。`bytes` は `manifest_cbor || signature` とし、`manifest_cbor` は RFC 8949 canonical CBOR、`signature_algorithm` は ABI v1 では `1=Ed25519`、`signature` は raw 64-byte Ed25519 signature とする。metadata set page は `struct { uint32_t count; uint32_t reserved0; uint64_t manifest_gpa[count]; }` により複数 manifest を列挙し、その先頭要素は root role でなければならない。`UVS_VERIFY_MANIFEST_SET` の `root_manifest_gpa` は metadata set page の先頭 `manifest_gpa[0]` と一致し、`root_manifest_length` はその manifest の長さ、`manifest_count` は page header の `count` と一致しなければならない。不一致は `INVALID_PARAMETER` または `SNAPSHOT_INCONSISTENT` とする。

`manifest_cbor` は ABI v1 で canonical CBOR map でなければならない。metadata role が `targets` または artifact-carrying role の場合は `component_type`, `target_cpu_vendor`, `required_features`, `target_os_generation`, `payload_hash`, `payload_size`, `generation`, `security_epoch`, `dependencies`, `revocation_reference`, `timestamp`, `snapshot_id`, `role`, `expires_at` を含まなければならない。さらに bootable executable artifact、すなわち `hypervisor`, `trusted-service`, `freebsd-kernel`, `guest-firmware`, `guest-boot-image` では `entry_ip` を必須とする。`freebsd-module`, `setuid-db`, `policy-fragment` では `entry_ip` は存在してはならない。`freebsd-kernel` または `freebsd-module` が制限 caller class として hypercall 発行主体になる場合は、追加 key `caller_class` と `allowed_callsites` を必須とする。`root`, `snapshot`, `timestamp`, `revocation` role では、その role に必要な key に加えて `timestamp`, `snapshot_id`, `role`, `expires_at`, `generation`, `security_epoch`, `dependencies`, `revocation_reference` を含まなければならないが、`component_type`, `payload_hash`, `payload_size`, `entry_ip`, `caller_class`, `allowed_callsites` は存在してはならない。省略、不定順整数表現、重複 key は `INVALID_PARAMETER` または `SIGNATURE_INVALID` として扱う。

ABI v1 では、bootable executable artifact を `hypervisor`, `trusted-service`, `freebsd-kernel`, `guest-firmware`, `guest-boot-image` の五種類に限定する。これらは `entry_ip` を必須とし、後述の固定 loader 規約に従ってロードされなければならない。`freebsd-module` は署名検証対象の code artifact ではあるが bootable executable artifact ではなく、`entry_ip` は存在してはならない。`component_type=trusted-service` の manifest には、`service_kind`, `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp`, `autostart` を追加必須 key とする。`autostart` は boolean とし、`true` のときのみ boot 時自動生成・自動起動対象となる。`vcpu_count` は 1 以上 252 以下の unsigned integer、`memory_limit_bytes` と `capability_mask` と `initial_sp` は unsigned 64-bit integer とする。

各 key の許可値と符号化規則は次のとおり固定する。artifact-carrying manifest における `component_type` は `hypervisor`, `trusted-service`, `freebsd-kernel`, `freebsd-module`, `guest-firmware`, `guest-boot-image`, `setuid-db`, `policy-fragment` のいずれかの text。`target_cpu_vendor` は `intel`, `amd`, `any` のいずれか。`required_features` は text 配列であり、各要素は `hlat`, `mbec`, `gmet`, `sev-snp`, `iommu`, `cet`, `aesni` のいずれか。`dependencies` は配列であり、各要素は `struct { text component_type; bytes payload_hash; int minimum_generation; }` に対応する CBOR map。`revocation_reference` は UTF-8 text で、失効リスト識別子を表す。`role` は `root`, `targets`, `snapshot`, `timestamp`, `revocation` のいずれか。`snapshot_id` は 32-byte bytes、artifact-carrying manifest の `payload_hash` は SHA-384 の 48-byte bytesとする。bootable executable artifact manifest の `entry_ip` は unsigned 64-bit integer とする。`component_type=trusted-service` のときは追加 key `service_kind` を必須とし、その値は `kci`, `ksi`, `iks`, `sks`, `uvs` のいずれかの text でなければならない。さらに `memory_limit_bytes`, `capability_mask`, `vcpu_count`, `initial_sp`, `autostart` を必須とする。`caller_class` は `fbvbs.ko` または `vmm.ko` の text とし、`allowed_callsites` は unsigned 64-bit integer 配列で、各要素は 해당 artifact の load base からの callsite offset を表す。trusted time source はマイクロハイパーバイザー起動時に確立された monotonic secure clock とし、`timestamp` と `expires_at` は Unix epoch seconds としてこの clock に対して評価する。ABI v1 では許容 clock skew は 300 秒、信頼時刻が利用不能な場合は `FRESHNESS_FAILED` とする。offline 構成でも secure clock が利用可能でありさえすれば検証してよい。

## L.1.E. Fixed Executable Loader Rules

ABI v1 の bootable executable artifact は、すべて ELF64 little-endian とし、固定 loader 規約に従う。`PARTITION_LOAD_IMAGE`、boot 時 trusted-service 自動起動、guest boot artifact 配置は、この規約から逸脱してはならない。

- 受理形式は `ET_EXEC` または `ET_DYN` の ELF64 のみとする
- `PT_LOAD` segment だけをロード対象とし、`PT_INTERP`、動的リンカ要求、実行時再配置、圧縮、自己展開ローダ、実装依存 fixup を禁止する
- 各 `PT_LOAD` segment は `p_vaddr` に従って page-align で配置し、file 部分をコピーし、`p_memsz - p_filesz` を 0 で初期化する
- segment の permission は `p_flags` から `R/W/X` を機械的に導出し、追加実装裁量を与えてはならない
- 重複 segment、非 canonical 仮想アドレス、page size 不整合、manifest `payload_size` 不一致、manifest `payload_hash` 不一致は `MEASUREMENT_FAILED` または `INVALID_PARAMETER` とする
- `entry_ip` は ELF header `e_entry` と一致しなければならず、`PARTITION_LOAD_IMAGE.entry_ip!=0` の場合はその値とも一致しなければならない
- `initial_sp` は guest VM では caller 指定値から与え、trusted-service では manifest `initial_sp` からのみ与える。`PARTITION_LOAD_IMAGE.initial_sp` は guest VM では非ゼロ必須、trusted-service では 0 または manifest 値との一致のみを許容し、loader が暗黙既定 stack を生成してはならない

この loader 規約により、同一 artifact bytes は同一の guest virtual memory image、同一の page permission、同一の initial instruction pointer を生成しなければならない。

## L.1.F. Fixed VM Exit Payload Layouts

`VM_RUN.exit_payload` は `exit_reason` に応じて次の固定構造を取る。

`exit_length` は選択された固定構造の厳密なサイズと一致しなければならない。空 payload の場合は 0 とする。`exit_length` より後ろの `exit_payload` バイト列は caller が無視しなければならず、hypervisor は 0 で埋めなければならない。

| `exit_reason` | 構造 |
|---|---|
| `1=PIO` | `struct { uint16_t port; uint8_t width; uint8_t is_write; uint32_t count; uint64_t value; }`。ABI v1 では `count` は常に 1 とし、string/repeated PIO は対象外 |
| `2=MMIO` | `struct { uint64_t guest_physical_address; uint8_t width; uint8_t is_write; uint16_t reserved0; uint32_t reserved1; uint64_t value; }` |
| `3=external interrupt` | `struct { uint32_t vector; uint32_t reserved0; }` |
| `4=EPT/NPT violation` | `struct { uint64_t guest_physical_address; uint32_t access_bits; uint32_t reserved0; }` |
| `5=control register access` | `struct { uint32_t cr_number; uint32_t access_type; uint64_t value; }` |
| `6=MSR access` | `struct { uint32_t msr; uint32_t is_write; uint64_t value; }` |
| `7=halt` | 空 |
| `8=shutdown` | 空 |
| `9=unclassified fault` | `struct { uint32_t fault_code; uint32_t reserved0; uint64_t detail0; uint64_t detail1; }` |

## L.2. Call ID 空間の構造

call_id は 16 ビット整数とし、上位 4 ビットをカテゴリ、下位 12 ビットを操作番号とする。

| カテゴリ | 範囲 | 用途 |
|---------|------|------|
| 0x0xxx | 0x0000-0x0FFF | パーティション管理 |
| 0x1xxx | 0x1000-0x1FFF | メモリ管理 |
| 0x2xxx | 0x2000-0x2FFF | Kernel Code Integrity Service |
| 0x3xxx | 0x3000-0x3FFF | Kernel State Integrity Service |
| 0x4xxx | 0x4000-0x4FFF | Identity Key Service |
| 0x5xxx | 0x5000-0x5FFF | Storage Key Service |
| 0x6xxx | 0x6000-0x6FFF | Update Verification Service |
| 0x7xxx | 0x7000-0x7FFF | bhyve VM 管理 |
| 0x8xxx | 0x8000-0x8FFF | 監査・診断 |
| 0x9xxx | 0x9000-0x9FFF | 予約（将来拡張） |
| 0xAxxx | 0xA000-0xAFFF | 予約（将来拡張） |
| 0xBxxx | 0xB000-0xBFFF | 予約（将来拡張） |
| 0xCxxx | 0xC000-0xCFFF | 予約（将来拡張） |
| 0xDxxx | 0xD000-0xDFFF | 予約（将来拡張） |
| 0xExxx | 0xE000-0xEFFF | 予約（将来拡張） |
| 0xFxxx | 0xF000-0xFFFF | 予約（将来拡張） |

## L.3. パーティション管理（0x0xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x0001 | PARTITION_CREATE | FreeBSD | `struct { uint16_t kind; uint16_t flags; uint32_t vcpu_count; uint64_t memory_limit_bytes; uint64_t capability_mask; uint64_t image_object_id; }` | `struct { uint64_t partition_id; }` | `image_object_id` は将来測定・ロードされる対象成果物を指す予約束縛であり、`PARTITION_MEASURE` と `PARTITION_LOAD_IMAGE` は同一 `image_object_id` を使わなければならない。`kind=PARTITION_KIND_GUEST_VM` および `kind=PARTITION_KIND_FREEBSD_HOST` は無効であり、guest VM は `VM_CREATE`、FreeBSD host はブート時の固定 system partition とする。`kind=PARTITION_KIND_TRUSTED_SERVICE` では caller は trusted-service image artifact を指す `image_object_id` を必須指定しなければならず、対応 manifest は artifact catalog の `related_index` 規則から一意に導出される。`vcpu_count` は 1 以上 252 以下でなければならず、導出された対応 manifest の `vcpu_count`, `memory_limit_bytes`, `capability_mask` とすべて一致しなければならない。不一致は `INVALID_PARAMETER` または `MEASUREMENT_FAILED` とする。成功時状態は `Created` | `INVALID_PARAMETER`, `PERMISSION_DENIED`, `NOT_FOUND`, `RESOURCE_EXHAUSTED`, `ALREADY_EXISTS`, `DEPENDENCY_UNSATISFIED`, `BUFFER_TOO_SMALL`, `MEASUREMENT_FAILED` |
| 0x0002 | PARTITION_DESTROY | FreeBSD | `struct { uint64_t partition_id; }` | 空 | `Running` 状態では内部 quiesce 完了後に破棄。`PARTITION_KIND_GUEST_VM` に対しては無効であり `INVALID_PARAMETER` とする。成功時状態は `Destroyed` | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY`, `TIMEOUT`, `INTERNAL_CORRUPTION` |
| 0x0003 | PARTITION_GET_STATUS | FreeBSD | `struct { uint64_t partition_id; }` | `struct { uint32_t state; uint32_t reserved0; uint64_t measurement_epoch; }` | 状態照会のみ | `INVALID_PARAMETER`, `NOT_FOUND`, `BUFFER_TOO_SMALL` |
| 0x0004 | PARTITION_QUIESCE | FreeBSD | `struct { uint64_t partition_id; }` | 空 | `Running` または `Runnable` から `Quiesced` へ | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY`, `TIMEOUT` |
| 0x0005 | PARTITION_RESUME | FreeBSD | `struct { uint64_t partition_id; }` | 空 | `Quiesced` から `Runnable` へのみ有効。`Faulted` 回復には使わない | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x0006 | PARTITION_MEASURE | FreeBSD | `struct { uint64_t partition_id; uint64_t image_object_id; uint64_t manifest_object_id; }` | `struct { uint64_t measurement_digest_id; }` | `Created` から `Measured`。成果物とマニフェストは既検証でなければならず、後続 `PARTITION_LOAD_IMAGE` の `image_object_id` はここで測定したものと一致しなければならない。`kind=PARTITION_KIND_TRUSTED_SERVICE` では `manifest_object_id` は `PARTITION_CREATE.image_object_id` から artifact catalog の `related_index` 規則で導出される manifest と一致しなければならない | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `MEASUREMENT_FAILED`, `SIGNATURE_INVALID`, `REVOKED`, `GENERATION_MISMATCH`, `ROLLBACK_DETECTED`, `DEPENDENCY_UNSATISFIED`, `SNAPSHOT_INCONSISTENT`, `FRESHNESS_FAILED`, `BUFFER_TOO_SMALL` |
| 0x0007 | PARTITION_LOAD_IMAGE | FreeBSD | `struct { uint64_t partition_id; uint64_t image_object_id; uint64_t entry_ip; uint64_t initial_sp; }` | 空 | `Measured` から `Loaded`。`image_object_id` は直前に測定済みの object と一致しなければならない。bootable executable artifact の配置は Appendix L.1.E の固定 ELF64 loader 規約に従う。`entry_ip=0` の場合は manifest 記録値を用い、`entry_ip!=0` の場合は manifest 記録値および ELF `e_entry` と一致しなければならない。guest VM では `initial_sp` は非ゼロでなければならない。trusted-service では `initial_sp=0` または manifest `initial_sp` との一致のみを許容する。不一致は `MEASUREMENT_FAILED` または `INVALID_PARAMETER` | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `MEASUREMENT_FAILED`, `RESOURCE_EXHAUSTED`, `DEPENDENCY_UNSATISFIED` |
| 0x0008 | PARTITION_START | FreeBSD | `struct { uint64_t partition_id; }` | 空 | `Loaded` から `Runnable`。初回実行そのものは hypervisor scheduler が行う | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x0009 | PARTITION_RECOVER | FreeBSD | `struct { uint64_t partition_id; uint64_t recovery_flags; }` | 空 | `Faulted` から `Runnable`。再測定、ゼロ化、必要状態復元を伴う | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `MEASUREMENT_FAILED`, `RESOURCE_BUSY`, `TIMEOUT`, `INTERNAL_CORRUPTION` |
| 0x000A | PARTITION_GET_FAULT_INFO | FreeBSD | `struct { uint64_t partition_id; }` | `struct { uint32_t fault_code; uint32_t source_component; uint64_t fault_detail0; uint64_t fault_detail1; }` | `Faulted` 状態の診断情報を返す | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `BUFFER_TOO_SMALL` |

## L.4. メモリ管理（0x1xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x1000 | MEMORY_ALLOCATE_OBJECT | FreeBSD | `struct { uint64_t size; uint32_t object_flags; uint32_t reserved0; }` | `struct { uint64_t memory_object_id; }` | 共有または guest memory 用 object を割当てる | `INVALID_PARAMETER`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `BUFFER_TOO_SMALL` |
| 0x1001 | MEMORY_MAP | FreeBSD | `struct { uint64_t partition_id; uint64_t memory_object_id; uint64_t guest_physical_address; uint64_t size; uint32_t permissions; uint32_t reserved0; }` | 空 | caller は memory object を指定するだけであり、machine frame の最終選択は hypervisor が行う | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `RESOURCE_BUSY` |
| 0x1002 | MEMORY_UNMAP | FreeBSD | `struct { uint64_t partition_id; uint64_t guest_physical_address; uint64_t size; }` | 空 | 指定範囲の map を解除 | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x1003 | MEMORY_SET_PERMISSION | 信頼サービス | `struct { uint64_t target_partition_id; uint64_t guest_physical_address; uint64_t size; uint32_t permissions; uint32_t reserved0; }` | 空 | capability に基づく権限変更。FreeBSD は呼び出してはならない | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `INVALID_STATE` |
| 0x1004 | MEMORY_REGISTER_SHARED | FreeBSD | `struct { uint64_t memory_object_id; uint64_t size; uint64_t peer_partition_id; uint32_t peer_permissions; uint32_t reserved0; }` | `struct { uint64_t shared_object_id; }` | 双方に明示 capability が必要 | `INVALID_PARAMETER`, `NOT_FOUND`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `ALREADY_EXISTS`, `BUFFER_TOO_SMALL` |
| 0x1005 | MEMORY_RELEASE_OBJECT | FreeBSD | `struct { uint64_t memory_object_id; }` | 空 | object がどの partition にも map されず、shared registration も持たないときにのみ解放可 | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x1006 | MEMORY_UNREGISTER_SHARED | FreeBSD | `struct { uint64_t shared_object_id; }` | 空 | 対応 shared registration を解除する。関連 map または出力参照が残る間は解放してはならない | `INVALID_PARAMETER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |

## L.5. Kernel Code Integrity Service（0x2xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x2001 | KCI_VERIFY_MODULE | fbvbs.ko | `struct { uint64_t module_object_id; uint64_t manifest_object_id; uint64_t generation; }` | `struct { uint32_t verdict; uint32_t reserved0; }` | 承認時のみ後続 `KCI_SET_WX` が許可される。`generation` は対象 manifest の `generation` 値と一致しなければならない。ABI v1 では `freebsd-module` manifest に `entry_ip` を持たせてはならず、検証対象は module artifact bytes と manifest metadata の一致のみである。失敗時応答本文は 0 長とする。ABI v1 では `status=OK` かつ `verdict=1` のみを承認とし、拒否は必ず non-OK status で表す | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `SIGNATURE_INVALID`, `REVOKED`, `GENERATION_MISMATCH`, `ROLLBACK_DETECTED`, `DEPENDENCY_UNSATISFIED`, `SNAPSHOT_INCONSISTENT`, `FRESHNESS_FAILED`, `BUFFER_TOO_SMALL` |
| 0x2002 | KCI_SET_WX | fbvbs.ko | `struct { uint64_t module_object_id; uint64_t guest_physical_address; uint64_t file_offset; uint64_t size; uint32_t permissions; uint32_t reserved0; }` | 空 | 検証済みコードページに限る。`module_object_id` は直前に `KCI_VERIFY_MODULE` で承認済みのものと一致しなければならない。KCI は `file_offset..file_offset+size` の artifact bytes を `guest_physical_address..+size` に配置された bytes と照合し、一致時のみ execute 権限を付与してよい | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `INVALID_STATE`, `NOT_FOUND`, `MEASUREMENT_FAILED` |
| 0x2003 | KCI_PIN_CR | fbvbs.ko | `struct { uint32_t cr_number; uint32_t reserved0; uint64_t pin_mask; }` | 空 | 許可 CR のみ。`pin_mask` は指定 CR の監視対象 bit を 1 で表す | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `NOT_SUPPORTED_ON_PLATFORM` |
| 0x2004 | KCI_INTERCEPT_MSR | fbvbs.ko | `struct { uint32_t msr_address; uint32_t enable; }` | 空 | ポリシー許可済み MSR のみ | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `NOT_SUPPORTED_ON_PLATFORM` |

## L.6. Kernel State Integrity Service（0x3xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x3000 | KSI_CREATE_TARGET_SET | fbvbs.ko | `struct { uint32_t target_count; uint32_t reserved0; uint64_t target_object_ids[502]; }` | `struct { uint64_t target_set_id; }` | pointer 遷移先として許可される object 集合を生成 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `RESOURCE_EXHAUSTED`, `BUFFER_TOO_SMALL` |
| 0x3001 | KSI_REGISTER_TIER_A | fbvbs.ko | `struct { uint64_t object_id; uint64_t guest_physical_address; uint64_t size; }` | 空 | 以後 write-enable 不可 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `ALREADY_EXISTS`, `PERMISSION_DENIED` |
| 0x3002 | KSI_REGISTER_TIER_B | fbvbs.ko | `struct { uint64_t object_id; uint64_t guest_physical_address; uint64_t size; uint32_t protection_class; uint32_t reserved0; }` | 空 | Tier B shadow 管理対象に登録。`protection_class` は `KSI_CLASS_UCRED`、`KSI_CLASS_PRISON`、`KSI_CLASS_SECURELEVEL`、`KSI_CLASS_MAC`、`KSI_CLASS_CAPSICUM`、`KSI_CLASS_FIREWALL`、`KSI_CLASS_P_TEXTVP` のいずれか | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `ALREADY_EXISTS`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED` |
| 0x3003 | KSI_MODIFY_TIER_B | fbvbs.ko | `struct { uint64_t object_id; uint32_t patch_length; uint32_t reserved0; uint8_t patch[4008]; }` | 空 | callsite は hypervisor 観測 RIP で検証。caller body 内の RIP は存在しない | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `CALLSITE_REJECTED`, `POLICY_DENIED`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x3004 | KSI_REGISTER_POINTER | fbvbs.ko | `struct { uint64_t pointer_object_id; uint64_t target_set_id; }` | 空 | 許可ターゲット集合へのみ遷移可能にする | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `ALREADY_EXISTS`, `RESOURCE_EXHAUSTED` |
| 0x3005 | KSI_VALIDATE_SETUID | fbvbs.ko | `struct { uint64_t fsid; uint64_t fileid; uint8_t measured_hash[64]; uint32_t operation_class; uint32_t valid_mask; uint32_t requested_ruid; uint32_t requested_euid; uint32_t requested_suid; uint32_t requested_rgid; uint32_t requested_egid; uint32_t requested_sgid; uint64_t caller_ucred_object_id; uint64_t jail_context_id; uint64_t mac_context_id; }` | `struct { uint32_t verdict; uint32_t reserved0; }` | パスは認可主キーに使わない。`measured_hash` は先頭 48 byte に raw SHA-384 を格納し、残余 16 byte は 0 とする。ファイルを伴わない `setuid(2)`/`setgid(2)` 系では `fsid=0`, `fileid=0`, `measured_hash` 全体 0 を用いる。`operation_class` は `credential operation class` に従い、`valid_mask` は要求後状態として意味を持つ ID スロットを示す。ABI v1 では `status=OK` かつ `verdict=1` のみを承認とし、拒否は必ず non-OK status で表す。失敗時応答本文は 0 長とする | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `SIGNATURE_INVALID`, `GENERATION_MISMATCH`, `REVOKED`, `POLICY_DENIED`, `BUFFER_TOO_SMALL` |
| 0x3006 | KSI_ALLOCATE_UCRED | fbvbs.ko | `struct { uint32_t uid; uint32_t gid; uint64_t prison_object_id; uint64_t template_ucred_object_id; }` | `struct { uint64_t ucred_object_id; }` | 管理下 ucred を割当てて即 Tier B 保護を適用 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `RESOURCE_EXHAUSTED`, `POLICY_DENIED`, `BUFFER_TOO_SMALL` |
| 0x3007 | KSI_REPLACE_TIER_B_OBJECT | fbvbs.ko | `struct { uint64_t old_object_id; uint64_t new_object_id; uint64_t pointer_object_id; uint32_t replace_flags; uint32_t reserved0; }` | 空 | 新規保護済み object へ原子的に pointer を切替え、旧 object を retire 候補にする。大規模 rule set の page replacement 用 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `POLICY_DENIED`, `RESOURCE_BUSY` |
| 0x3008 | KSI_UNREGISTER_OBJECT | fbvbs.ko | `struct { uint64_t object_id; }` | 空 | retire 済み object を保護集合から外す。参照が残る間は解放不可 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |

## L.7. Identity Key Service（0x4xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x4001 | IKS_IMPORT_KEY | fbvbs.ko | `struct { uint64_t key_material_page_gpa; uint32_t key_type; uint32_t allowed_ops; uint32_t key_length; uint32_t reserved0; }` | `struct { uint64_t key_handle; }` | import 後に共有ページ上の鍵素材をゼロクリア | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `BUFFER_TOO_SMALL` |
| 0x4002 | IKS_SIGN | fbvbs.ko | `struct { uint64_t key_handle; uint32_t hash_length; uint32_t reserved0; uint8_t hash[64]; }` | `struct { uint32_t signature_length; uint32_t reserved0; uint8_t signature[4000]; }` | 鍵用途制約に従う。ABI v1 では `hash_length` は 48 のみ有効であり、raw SHA-384 を意味する。残余 16 byte は 0 でなければならない | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `POLICY_DENIED`, `BUFFER_TOO_SMALL` |
| 0x4003 | IKS_KEY_EXCHANGE | fbvbs.ko | `struct { uint64_t key_handle; uint32_t peer_public_key_length; uint32_t derive_flags; uint8_t peer_public_key[3992]; }` | `struct { uint64_t derived_secret_handle; }` | 生の共有秘密は返さず、不透明ハンドルのみ返す | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `POLICY_DENIED`, `BUFFER_TOO_SMALL` |
| 0x4004 | IKS_DERIVE | fbvbs.ko | `struct { uint64_t key_handle; uint32_t parameter_length; uint32_t reserved0; uint8_t params[3992]; }` | `struct { uint64_t derived_key_handle; }` | 導出鍵も不透明ハンドルとして返す | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `POLICY_DENIED`, `BUFFER_TOO_SMALL` |
| 0x4005 | IKS_DESTROY_KEY | fbvbs.ko | `struct { uint64_t key_handle; }` | 空 | 二重破棄は `NOT_FOUND` | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND` |

## L.8. Storage Key Service（0x5xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x5001 | SKS_IMPORT_DEK | fbvbs.ko | `struct { uint64_t key_material_page_gpa; uint64_t volume_id; uint32_t key_length; uint32_t reserved0; }` | `struct { uint64_t dek_handle; }` | import 後に共有ページをゼロクリア | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `BUFFER_TOO_SMALL` |
| 0x5002 | SKS_DECRYPT_BATCH | fbvbs.ko | `struct { uint64_t dek_handle; uint64_t io_descriptor_page_gpa; uint32_t descriptor_count; uint32_t reserved0; }` | `struct { uint32_t completed_count; uint32_t reserved0; }` | 出力は別共有ページのみ。レート制限対象 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `RESOURCE_BUSY`, `RETRY_LATER`, `BUFFER_TOO_SMALL` |
| 0x5003 | SKS_ENCRYPT_BATCH | fbvbs.ko | `struct { uint64_t dek_handle; uint64_t io_descriptor_page_gpa; uint32_t descriptor_count; uint32_t reserved0; }` | `struct { uint32_t completed_count; uint32_t reserved0; }` | 上と同じ | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `RESOURCE_BUSY`, `RETRY_LATER`, `BUFFER_TOO_SMALL` |
| 0x5004 | SKS_DESTROY_DEK | fbvbs.ko | `struct { uint64_t dek_handle; }` | 空 | アンマウント時に破棄 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND` |

## L.9. Update Verification Service（0x6xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x6001 | UVS_VERIFY_MANIFEST_SET | fbvbs.ko | `struct { uint64_t root_manifest_gpa; uint32_t root_manifest_length; uint32_t manifest_count; uint64_t manifest_set_page_gpa; }` | `struct { uint32_t verdict; uint32_t failure_bitmap; uint64_t verified_manifest_set_id; }` | freshness、freeze、mix-and-match、snapshot 一貫性、role separation を含めて metadata set 全体を評価する。ABI v1 では `status=OK` かつ `verdict=1` のみを承認とし、拒否は必ず non-OK status で表す。失敗時応答本文も同一構造を用い、`verdict=0`, `verified_manifest_set_id=0` とし、`actual_output_length=16` を返す | `INVALID_PARAMETER`, `INVALID_CALLER`, `SIGNATURE_INVALID`, `REVOKED`, `GENERATION_MISMATCH`, `ROLLBACK_DETECTED`, `DEPENDENCY_UNSATISFIED`, `SNAPSHOT_INCONSISTENT`, `FRESHNESS_FAILED`, `BUFFER_TOO_SMALL` |
| 0x6002 | UVS_VERIFY_ARTIFACT | fbvbs.ko | `struct { uint8_t artifact_hash[64]; uint64_t verified_manifest_set_id; uint64_t manifest_object_id; }` | `struct { uint32_t verdict; uint32_t reserved0; }` | manifest set と artifact の一致確認。`manifest_object_id` は verified manifest set 内の単一 manifest を一意に指し、その manifest が指定 `artifact_hash` と一致するときにのみ承認してよい。`artifact_hash` は先頭 48 byte に raw SHA-384 を格納し、残余 16 byte は 0 とする。ABI v1 では `status=OK` かつ `verdict=1` のみを承認とし、拒否は必ず non-OK status で表す。失敗時応答本文は 0 長とする | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `SIGNATURE_INVALID`, `REVOKED`, `GENERATION_MISMATCH`, `ROLLBACK_DETECTED`, `DEPENDENCY_UNSATISFIED`, `SNAPSHOT_INCONSISTENT`, `FRESHNESS_FAILED`, `BUFFER_TOO_SMALL` |
| 0x6003 | UVS_CHECK_REVOCATION | fbvbs.ko | `struct { uint64_t object_id; uint32_t object_type; uint32_t reserved0; }` | `struct { uint32_t revoked; uint32_t reserved0; }` | 鍵または成果物の失効確認。成功時 `status=OK` で `revoked` は 0 または 1。ABI v1 では `REVOKED` を本 call の返却 status として用いてはならない | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `BUFFER_TOO_SMALL` |

## L.10. bhyve VM 管理（0x7xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x7001 | VM_CREATE | vmm.ko | `struct { uint64_t memory_limit_bytes; uint32_t vcpu_count; uint32_t vm_flags; }` | `struct { uint64_t vm_partition_id; }` | 成功時 `Created` 状態の VM パーティションを返す。`vcpu_count` は 1 以上 252 以下でなければならない。`memory_limit_bytes` は Appendix L.1.B の定義に従う map 済み総バイト上限であり、bootstrap metadata page と `vcpu_count` 枚の command page を収容できる値でなければならない。caller は続けて `PARTITION_MEASURE`、`PARTITION_LOAD_IMAGE`、`PARTITION_START` を実行しなければならない | `INVALID_PARAMETER`, `INVALID_CALLER`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `BUFFER_TOO_SMALL` |
| 0x7002 | VM_DESTROY | vmm.ko | `struct { uint64_t vm_partition_id; }` | 空 | guest memory ゼロ化、IOMMU domain 解除。`Created`, `Measured`, `Loaded`, `Runnable`, `Running`, `Quiesced`, `Faulted` から有効 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY`, `TIMEOUT` |
| 0x7003 | VM_RUN | vmm.ko | `struct { uint64_t vm_partition_id; uint32_t vcpu_id; uint32_t run_flags; }` | `struct { uint32_t exit_reason; uint32_t exit_length; uint8_t exit_payload[4032]; }` | `Runnable` の vCPU に限る。復帰後の vCPU 状態は Section 35.1 の固定 exit-to-state 規則に従う。未分類 exit は fail-closed | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY`, `TIMEOUT`, `INTERNAL_CORRUPTION`, `BUFFER_TOO_SMALL` |
| 0x7004 | VM_SET_REGISTER | vmm.ko | `struct { uint64_t vm_partition_id; uint32_t vcpu_id; uint32_t register_id; uint64_t value; }` | 空 | 実行中 vCPU には適用しない。ABI v1 では `VM_REG_RIP`, `VM_REG_RSP`, `VM_REG_RFLAGS`, `VM_REG_CR0`, `VM_REG_CR4` のみ caller 設定可であり、`VM_REG_CR3` は `PERMISSION_DENIED` とする | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `PERMISSION_DENIED` |
| 0x7005 | VM_GET_REGISTER | vmm.ko | `struct { uint64_t vm_partition_id; uint32_t vcpu_id; uint32_t register_id; }` | `struct { uint64_t value; }` | 実行中 vCPU には適用しない。`VM_REG_CR3` は読取りのみ許可 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `BUFFER_TOO_SMALL` |
| 0x7006 | VM_MAP_MEMORY | vmm.ko | `struct { uint64_t vm_partition_id; uint64_t memory_object_id; uint64_t guest_physical_address; uint64_t size; uint32_t permissions; uint32_t reserved0; }` | 空 | frame 最終選択権は hypervisor にある。`Created`, `Measured`, `Loaded`, `Runnable`, `Quiesced` で有効、`Running` と `Faulted` では無効 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_EXHAUSTED`, `PERMISSION_DENIED` |
| 0x7007 | VM_INJECT_INTERRUPT | vmm.ko | `struct { uint64_t vm_partition_id; uint32_t vcpu_id; uint32_t vector; uint32_t delivery_mode; uint32_t reserved0; }` | 空 | 注入可能状態でのみ有効 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY` |
| 0x7008 | VM_ASSIGN_DEVICE | vmm.ko | `struct { uint64_t vm_partition_id; uint64_t device_id; }` | 空 | IOMMU group、ACS、interrupt remapping、reset 能力を満たす場合のみ。`device_id` は platform device registry が列挙した opaque ID。`Created`, `Measured`, `Loaded`, `Runnable`, `Quiesced` で有効、`Running` と `Faulted` では無効 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `PERMISSION_DENIED`, `POLICY_DENIED`, `NOT_SUPPORTED_ON_PLATFORM`, `RESOURCE_BUSY` |
| 0x7009 | VM_RELEASE_DEVICE | vmm.ko | `struct { uint64_t vm_partition_id; uint64_t device_id; }` | 空 | Function Level Reset または同等手順を実行。`Created`, `Measured`, `Loaded`, `Runnable`, `Quiesced`, `Faulted` で有効、`Running` では無効 | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `INVALID_STATE`, `RESOURCE_BUSY`, `TIMEOUT` |
| 0x700A | VM_GET_VCPU_STATUS | vmm.ko | `struct { uint64_t vm_partition_id; uint32_t vcpu_id; uint32_t reserved0; }` | `struct { uint32_t vcpu_state; uint32_t reserved0; }` | 現在の外部可視 vCPU 状態を返す。`Blocked` は外部イベントまたは割込み注入により再開可能な待機状態を意味する | `INVALID_PARAMETER`, `INVALID_CALLER`, `NOT_FOUND`, `BUFFER_TOO_SMALL` |

## L.11. 監査・診断（0x8xxx）

| call_id | 名称 | 呼出元 | 要求本文 | 応答本文 | 前提条件/意味論 | 許可エラー |
|---------|------|--------|----------|----------|-----------------|------------|
| 0x8001 | AUDIT_GET_MIRROR_INFO | fbvbs.ko | 空 | `struct { uint64_t ring_gpa; uint32_t ring_size; uint32_t record_size; }` | read-only ミラー情報 | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |
| 0x8002 | AUDIT_GET_BOOT_ID | fbvbs.ko | 空 | `struct { uint64_t boot_id_hi; uint64_t boot_id_lo; }` | 現在 boot 識別子 | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |
| 0x8003 | DIAG_GET_PARTITION_LIST | fbvbs.ko | 空 | `struct { uint32_t count; uint32_t reserved0; uint8_t entries[4032]; }` | 出力は `count` 個の `struct { uint64_t partition_id; uint32_t state; uint16_t kind; uint16_t service_kind; }` を連続格納する固定列形式 | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |
| 0x8004 | DIAG_GET_CAPABILITIES | fbvbs.ko | 空 | `struct { uint64_t capability_bitmap0; uint64_t capability_bitmap1; }` | MBEC/GMET、HLAT、CET、AES-NI 等 | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |
| 0x8005 | DIAG_GET_ARTIFACT_LIST | fbvbs.ko | 空 | `struct { uint32_t count; uint32_t reserved0; uint8_t entries[4032]; }` | `fbvbs_artifact_catalog_v1` と同形式の固定 artifact catalog を返す | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |
| 0x8006 | DIAG_GET_DEVICE_LIST | fbvbs.ko | 空 | `struct { uint32_t count; uint32_t reserved0; uint8_t entries[4032]; }` | `fbvbs_device_catalog_v1` と同形式の固定 device catalog を返す | `INVALID_CALLER`, `PERMISSION_DENIED`, `BUFFER_TOO_SMALL` |

## L.12. エラーコード

ABI v1 で外部返却に許可されるエラーコード数値割当:

| コード | 名称 | 説明 |
|--------|------|------|
| 0 | OK | 正常完了 |
| 1 | INVALID_PARAMETER | 引数不正（長さ超過、アラインメント不良、未ゼロ化フィールド等） |
| 2 | INVALID_CALLER | 呼出元パーティションがこの操作の権限を持たない |
| 3 | PERMISSION_DENIED | ケイパビリティ不足 |
| 4 | RESOURCE_BUSY | 対象リソースが他操作で使用中。リトライ可能 |
| 5 | NOT_SUPPORTED_ON_PLATFORM | 必要なハードウェア機能が存在しない |
| 6 | MEASUREMENT_FAILED | イメージ測定値が期待値と不一致 |
| 7 | SIGNATURE_INVALID | 署名検証失敗 |
| 8 | ROLLBACK_DETECTED | 成果物の世代番号が現在の version store より古い |
| 9 | RETRY_LATER | 一時的な処理不能。リトライ可能 |
| 10 | REVOKED | 鍵または成果物が失効済み |
| 11 | GENERATION_MISMATCH | 世代番号不一致 |
| 12 | DEPENDENCY_UNSATISFIED | 依存する成果物が未検証または未ロード |
| 13 | CALLSITE_REJECTED | callsite 検証失敗（呼出元アドレスが正規発行箇所でない） |
| 14 | POLICY_DENIED | ポリシー検証失敗（Setuid 不許可等） |
| 15 | INTERNAL_CORRUPTION | サービス内部の致命的不整合。サービス再起動が必要 |
| 16 | INVALID_STATE | 現在状態では許可されない操作 |
| 17 | NOT_FOUND | 対象 ID、ハンドル、オブジェクト、パーティションが存在しない |
| 18 | ALREADY_EXISTS | 重複作成または重複登録 |
| 19 | RESOURCE_EXHAUSTED | 資源上限超過または容量不足 |
| 20 | BUFFER_TOO_SMALL | 出力先が必要長より小さい |
| 21 | ABI_VERSION_UNSUPPORTED | `abi_version` が未対応 |
| 22 | SNAPSHOT_INCONSISTENT | 更新メタデータ集合の snapshot view が不整合 |
| 23 | FRESHNESS_FAILED | 期限切れ、freeze 攻撃、stale metadata 等で freshness 失敗 |
| 24 | REPLAY_DETECTED | `caller_sequence` の後退または再利用を検出 |
| 25 | TIMEOUT | 規定時間内に停止、回復、I/O 完了などが達成できない |

`UNKNOWN` は内部ログ用分類としてのみ用いてよく、外部 ABI の返却値として用いてはならない。