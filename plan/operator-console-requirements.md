# FBVBS オペレーターコンソール (OCS) 要件定義書

- 文書バージョン: 1.1
- 対象システム: FBVBS マイクロハイパーバイザー (ABI v1)
- 保証目標: CC EAL5+
- 対応言語: 日本語 (JA) / 英語 (EN)

---

## 0. コンテキスト節約サマリー (AIエージェント向け)

### 0.1 最短読取手順

1. 全体制約を確認する: 1章, 3.2, 5.5
2. VCD と ABI 契約を確認する: 2.3, 11章
3. セキュリティと劣化動作を確認する: 8章, 12章, 13.5
4. 実装と検証の着地点を確認する: 10章, 14章

### 0.2 章別クイックマップ

| 章 | 目的 | 実装時の主参照 | 検証時の主参照 |
|----|------|----------------|----------------|
| 1 | OCS の存在理由と絶対制約 | シェル化禁止、UART 直接所有禁止 | 要件逸脱の有無 |
| 2 | OCS/VCD のアーキテクチャ契約 | VCD 構造、attach 条件、権限 | リング不変条件、owner 整合 |
| 3 | コンソールモデル定義 | 認可境界、提供機能の閉集合 | 非機能追加の抑止 |
| 4 | メッセージ規約 | FBVnnnS 形式、重大度 | 監査相関、機械可読性 |
| 5 | コマンド仕様と対象ポリシー | 制御対象、禁止対象、break-glass | 許可/拒否テスト |
| 6 | パーサー受理規則 | 文字集合、CRLF、短縮形閉集合 | トークナイズ境界テスト |
| 7 | i18n 方針 | EN/JA 切替、非翻訳要素 | 文言整合、UTF-8 表示 |
| 8 | セキュリティ要件 | 入力検証、DoS、防御動作 | 異常入力、監査項目検証 |
| 9 | UART 詳細 | RX/TX 振る舞い、行編集 | 端境ケース検証 |
| 10 | ビルド統合と構成識別 | OCS 有効/無効条件 | 構成差分の証跡確認 |
| 11 | 追加 ABI | 新規定数、call ID、返却規則 | API 契約テスト |
| 12 | エラー処理と回復 | メッセージ ID、回復経路 | 失敗分類と復旧手順 |
| 13 | 運用シナリオ | 起動順、障害調査、緊急運用 | 手順の再現性 |
| 14 | 実装フェーズ | 作業分割、必須検証項目 | 受入れ判定 |
| 15 | 想定課題 | 運用上の制約と緩和策 | 残余リスク管理 |

---

## 1. 概要と動機

FBVBS マイクロハイパーバイザーを FreeBSD ホストなしで独立運用する場合、
オペレーターがシステムを監視・制御する手段が必要である。

IBM メインフレーム (z/VM CP コンソール、PR/SM SE コンソール) に倣い、
UART シリアル経由の**固定コマンドセット型オペレーターコンソール**を
トラステッドサービスパーティションとして実装する。

これはシェルではない。任意のプログラム実行、パイプ、スクリプト、
ファイルシステムアクセスは一切提供しない。

本機能はビルド時に含めるかを選択可能な**オプショナル機能**である。

本章以降で定義する OCS は次を満たす。

1. OCS は UART ハードウェアを直接所有しない。
2. OCS は VCD (Virtual Console Device) のみを介して I/O する。
3. OCS 内認証は導入しない。物理アクセス/BMC SOL/IPMI SOL を信頼境界とする。
4. no-host 構成では、OCS 故障時の最終回復手段は外部管理経路または再起動である。

---

## 2. アーキテクチャ

### 2.1 パーティション階層における位置づけ

```
ハイパーバイザー (VMX root) ── COM1 UART を直接所有
├── オペレーターコンソール (TRUSTED_SERVICE / SERVICE_KIND_OCS)
├── KCI (Kernel Code Integrity Service)
├── KSI (Kernel State Integrity Service)
├── IKS (Identity Key Service)
├── SKS (Storage Key Service)
├── UVS (Update Verification Service)
└── ゲスト VM
```

OCS は `PARTITION_KIND_TRUSTED_SERVICE` として動作し、
新しいサービス種別 `SERVICE_KIND_OCS (6U)` を割り当てる。

16 個のパーティションスロットのうち 1 つを消費する。
独自の EPT（第 2 レベルページテーブル）を持ち、
他の全パーティションからメモリ分離される。

### 2.2 通信経路

```
物理 UART (COM1, 0x3F8)
     │
     ▼
[ハイパーバイザー]  ← VMX root、UART ハードウェアを所有
     │
 仮想コンソール     ← 新規: 共有メモリ上のリングバッファペア
 デバイス (VCD)
     │
     ▼
[OCS パーティション] ← トラステッドサービス、VMX non-root
     │
 コマンドページ     ← 既存 ABI による呼び出し
     │
     ▼
[ハイパーバイザー]   ← 診断/管理コールをディスパッチ
```

OCS パーティションは UART ハードウェアに直接アクセスしない。

### 2.3 仮想コンソールデバイス (VCD)

ハイパーバイザーと OCS パーティションの間に共有メモリ上の
リングバッファペアを設ける。

C レイアウトは flexible array member を使わず、固定長で定義する。

```c
#define FBVBS_VCD_RX_RING_SIZE 256U
#define FBVBS_VCD_TX_RING_SIZE 2048U
#define FBVBS_VCD_RING_MAGIC   0x56434431U /* "VCD1" */

struct fbvbs_vcd_ring_header {
    volatile uint32_t write_index;
    volatile uint32_t read_index;
    uint32_t size;
    uint32_t magic;
};

struct fbvbs_vcd_rx_ring_page {
    struct fbvbs_vcd_ring_header header;
    uint8_t buffer[FBVBS_VCD_RX_RING_SIZE];
};

struct fbvbs_vcd_tx_ring_page {
    struct fbvbs_vcd_ring_header header;
    uint8_t buffer[FBVBS_VCD_TX_RING_SIZE];
};

struct fbvbs_vcd_control_block {
    bool active;
    uint8_t reserved0[3];
    uint32_t corruption_count;
    uint64_t owner_partition_id;
    uint64_t rx_ring_gpa;
    uint64_t tx_ring_gpa;
};
```

- **RX リング (256B):** producer はハイパーバイザー、consumer は OCS。
- **TX リング (2048B):** producer は OCS、consumer はハイパーバイザー。
- ここでいう 256B / 2048B は割当サイズである。実効格納可能バイト数は
   それぞれ 255B / 2047B であり、空・満判定のために 1 スロットを常に空ける。
- `fbvbs_vcd_control_block` はハイパーバイザー内部状態であり、共有領域ではない。

#### 2.3.1 VCD リング契約 (ABI レベル)

1. **SPSC (single-producer/single-consumer):**
   RX は「HV 書込 / OCS 読取」、TX は「OCS 書込 / HV 読取」のみ許可する。
2. **インデックス範囲:**
   `0 <= write_index < size` かつ `0 <= read_index < size`。
3. **size 固定値:**
   RX は `size == FBVBS_VCD_RX_RING_SIZE`、TX は `size == FBVBS_VCD_TX_RING_SIZE`。
4. **empty 判定:** `write_index == read_index`。
5. **full 判定:** `((write_index + 1U) % size) == read_index`。
6. **wraparound:**
   インデックス更新は必ず `next = (index + 1U) % size` を用いる。
7. **更新順序 (memory ordering):**
   producer は `buffer` 書込完了後に `write_index` を store-release で更新する。
   consumer は `write_index` を load-acquire で観測してから `buffer` を読む。
   consumer は消費後 `read_index` を store-release で更新する。
8. **初期状態:**
   attach 成功時にハイパーバイザーが `read_index=0`、`write_index=0`、
   `size=固定値`、`magic=FBVBS_VCD_RING_MAGIC` を設定する。
9. **可読・空き量の定義:**
   `used = (write_index + size - read_index) % size`、
   `free = (size - 1U) - used`。
10. **容量の定義:**
   この文書でいう `size` は割当長であり、実効格納可能バイト数は `size - 1U` である。

#### 2.3.2 VCD attach 契約

1. attach 可能 caller は `PARTITION_KIND_TRUSTED_SERVICE` かつ
   `SERVICE_KIND_OCS` かつ `FBVBS_CAP_OCS_ACCESS` を持つパーティションのみ。
2. `rx_ring_gpa` と `tx_ring_gpa` はともに `FBVBS_PAGE_SIZE` 境界に整列し、
   それぞれ少なくとも 1 ページの RW マッピング可能領域でなければならない。
3. `rx_ring_gpa != tx_ring_gpa` でなければならない。
4. 2 つのリング領域は重複してはならない。
5. `active=false` のときのみ attach は成功する。
6. 既に `active=true` かつ owner が同一の場合、再 attach は `ALREADY_EXISTS`。
7. 既に `active=true` かつ owner が異なる場合、再 attach は `PERMISSION_DENIED`。
8. attach 失敗時、既存 active 状態と owner は変更してはならない。
9. attach 成功時、`owner_partition_id` は caller の `partition_id` と一致しなければならない。
   ハイパーバイザーは VCD 操作ごとに `owner_partition_id` を参照し、
   owner 不整合を検出した場合は `active=false` へ遷移して `FBV110W` を記録する。

#### 2.3.3 マッピング権限

1. RX/TX リングページは owner OCS パーティションとハイパーバイザーのみがアクセス可能。
2. 他パーティションにはマップしてはならない。
3. ページ権限は双方 RW・NX とする（インデックス更新のため双方書込が必要）。
4. どのフィールドを誰が更新してよいかは 2.3.1 の SPSC 契約で拘束する。

### 2.4 OCS が UART に直接アクセスしない理由

1. PIO パススルーが不要になり、攻撃面が縮小する。
2. 監査ログ経路との競合を防ぎ、OCS が監査レコードを抑制できなくなる。
3. プライマリ監査ログシンクがハイパーバイザー排他制御下にある原則を維持する。

### 2.5 ハイパーバイザー側の追加実装

#### 2.5.1 UART RX パス

現在のハイパーバイザーは TX 機能のみを持つ。以下を追加する。

- `fbvbs_serial_rx_ready()`: LSR bit 0 (Data Ready) を確認。
- `fbvbs_serial_getchar()`: RBR レジスタからバイトを読み出し。
- いずれも `freestanding_runtime.c` 内に `#ifdef FBVBS_OPERATOR_CONSOLE` ガード付きで追加。

#### 2.5.2 ポーリング方式

攻撃面と複雑性を最小化するため、割り込みではなくポーリングを採用する。

ハイパーバイザーのプリエンプションタイマー出口ハンドラ
（既存既定値 `FBVBS_DEFAULT_PREEMPTION_TICKS`、約 10ms 相当）から呼び出す。

```c
#ifdef FBVBS_OPERATOR_CONSOLE
    fbvbs_vcd_poll_uart(state);
#endif
```

`fbvbs_vcd_poll_uart(state)` の 1 回あたり処理上限は次の固定値とする。

1. UART RX から最大 16 バイトを RX リングへ投入。
2. TX リングから最大 64 バイトを取り出して UART へ送出。

#### 2.5.3 UART 多重化

UART は 3 ストリームを扱う: 監査ログ、起動コンソール、OCS コンソール。

- **監査ログレコード**は `AUDIT seq=...` 形式で出力され、優先順位は最上位。
- **OCS コンソール出力**は `CONS ` 接頭辞で区別。
- **コンソール入力**は RX 専用経路であり、出力と競合しない。
- 行単位アトミック性を維持する（行途中の混在を禁止）。

---

## 3. コンソールモデル

### 3.1 シェルとの根本的な違い

| 性質 | シェル | OCS |
|------|--------|-----|
| コマンドセット | 拡張可能、任意のプログラム | 固定、列挙済み、閉じた集合 |
| パイプ/リダイレクト | あり | なし |
| 変数/スクリプト | あり | なし |
| ファイルシステムアクセス | あり | 一切なし |
| パス指定 | あり | 不可能（パスの概念がない） |
| 任意のコード実行 | あり | なし |
| 出力形式 | 自由テキスト | メッセージ ID 付き構造化出力 |
| 認証 | ログイン + 権限 | 物理シリアル接続 = 認可 |
| コマンド引数 | 任意の文字列 | 列挙済み識別子、数値 ID |

### 3.2 認可モデル

物理シリアルコンソールへのアクセスが認可を構成する。
これはメインフレームの HMC/SE コンソールと同じ信頼境界モデルである。

ユーザー名・パスワード認証は実装しない。

1. UART は物理 RS-232、BMC SOL、IPMI SOL からのみアクセスされる。
2. OCS 内に秘密情報を保持しない。
3. 物理アクセス前提を保証ケースに含める。

ただし、**全てのオペレーター操作は監査ログに記録する**。

---

## 4. プロンプトとメッセージ形式

### 4.1 プロンプト

```
FBVBS>
```

プロンプトは言語設定に依存せず常に ASCII とする。

### 4.2 メッセージ形式

全てのコンソールメッセージは次の形式を使用する。

```
FBVnnns メッセージ本文
```

- `FBV` — 固定接頭辞
- `nnn` — 3 桁メッセージ番号 (000-999)
- `s` — 重大度接尾辞

| 接尾辞 | 名称 | 意味 |
|--------|------|------|
| `I` | 情報 | 通常の運用フィードバック |
| `W` | 警告 | 異常だが致命的ではない |
| `E` | エラー | コマンド失敗または運用エラー |
| `A` | 要対処 | オペレーター対応が必要 |
| `S` | 重大 | システム整合性が危険 |

### 4.3 出力例

英語:
```
FBV001I SYSTEM READY - BOOT ID 0123456789ABCDEF FEDCBA9876543210
FBV010I PARTITION 0003 STATE RUNNING KIND TRUSTED_SERVICE SERVICE KSI
FBV050E PARTITION 0005 STATE FAULTED FAULT_CODE 0003 DETAIL 00000000 00000000
FBV100W COMMAND REJECTED - PARTITION 9999 NOT FOUND
```

日本語:
```
FBV001I システム準備完了 - 起動ID 0123456789ABCDEF FEDCBA9876543210
FBV010I 区画 0003 状態 実行中 種別 信頼サービス サービス KSI
FBV050E 区画 0005 状態 障害発生 障害コード 0003 詳細 00000000 00000000
FBV100W コマンド拒否 - 区画 9999 が見つかりません
```

---

## 5. コマンド一覧

### 5.1 概要

本仕様は「受理構文」を単位として **15 構文**を定義する。

1. `DISPLAY SYSTEM`
2. `DISPLAY CAPABILITIES`
3. `DISPLAY CONSOLE`
4. `DISPLAY PARTITIONS`
5. `DISPLAY PARTITION <partition_id>`
6. `DISPLAY FAULTINFO <partition_id>`
7. `DISPLAY ARTIFACTS`
8. `DISPLAY DEVICES`
9. `QUIESCE PARTITION <partition_id>`
10. `RESUME PARTITION <partition_id>`
11. `RECOVER PARTITION <partition_id> [FLAGS <hex_flags>]`
12. `SET LANGUAGE EN`
13. `SET LANGUAGE JA`
14. `HELP`
15. `HELP <command>`

この集合は固定であり、拡張しない。

### 5.2 照会系コマンド

既定要求ケーパビリティ: `FBVBS_CAP_AUDIT_DIAG`

注記: `DISPLAY CONSOLE` のみ `FBVBS_CAP_OCS_ACCESS` を要求する。

#### DISPLAY SYSTEM

- 構文: `DISPLAY SYSTEM` (短縮形: `D SYS`)
- ABI コール: `AUDIT_GET_BOOT_ID` (0x8002), `DIAG_GET_CAPABILITIES` (0x8004)
- 出力:

英語:
```
FBV001I SYSTEM READY
FBV002I BOOT ID 0123456789ABCDEF FEDCBA9876543210
FBV003I ABI VERSION 0001
FBV004I CPU CAPS MBEC HLAT CET AESNI
FBV005I PLATFORM CAPS IOMMU MEASURED_BOOT HOST_DEPRIV FOUNDATION
```

日本語:
```
FBV001I システム準備完了
FBV002I 起動ID 0123456789ABCDEF FEDCBA9876543210
FBV003I ABIバージョン 0001
FBV004I CPU機能 MBEC HLAT CET AESNI
FBV005I 基盤機能 IOMMU 測定起動 ホスト権限縮退 基盤準備完了
```

#### DISPLAY CAPABILITIES

- 構文: `DISPLAY CAPABILITIES` (短縮形: `D CAP`)
- ABI コール: `DIAG_GET_CAPABILITIES` (0x8004)
- 出力:

```
FBV020I CAPABILITY BITMAP0 000000000000000F
FBV021I   BIT 0 MBEC/GMET     : YES
FBV022I   BIT 1 HLAT           : YES
FBV023I   BIT 2 CET            : YES
FBV024I   BIT 3 AES-NI         : YES
FBV025I CAPABILITY BITMAP1 000000000000001F
FBV026I   BIT 0 IOMMU          : YES
FBV027I   BIT 1 MEASURED BOOT  : YES
FBV028I   BIT 2 HOST DEPRIV    : YES
FBV029I   BIT 3 FOUNDATION     : YES
FBV030I   BIT 4 HIGH ASSURANCE : YES
```

#### DISPLAY CONSOLE

- 構文: `DISPLAY CONSOLE` (短縮形: `D CONS`)
- ABI コール: `OCS_VCD_STATUS` (0x8008)
- 要求ケーパビリティ: `FBVBS_CAP_OCS_ACCESS`
- 出力:

英語:
```
FBV031I CONSOLE CHANNEL HEALTH
FBV032I RX AVAILABLE 00000000
FBV033I TX FREE      00000000
```

日本語:
```
FBV031I コンソールチャネル状態
FBV032I RX 利用可能量 00000000
FBV033I TX 空き量     00000000
```

- `OCS_VCD_STATUS` が `INVALID_STATE (16)` を返す場合は
   `FBV107W VCD COMMUNICATION ERROR (STATUS 16)` を出力する。

#### DISPLAY PARTITIONS

- 構文: `DISPLAY PARTITIONS` (短縮形: `D PARTS`)
- ABI コール: `DIAG_GET_PARTITION_LIST` (0x8003)
- 出力:

英語:
```
FBV010I PARTITION LIST (3 ENTRIES)
FBV011I ID   STATE     KIND             SERVICE
FBV012I 0001 RUNNING   TRUSTED_SERVICE  KCI
FBV012I 0002 RUNNING   TRUSTED_SERVICE  KSI
FBV012I 0003 RUNNING   FREEBSD_HOST     NONE
```

日本語:
```
FBV010I 区画一覧 (3 件)
FBV011I ID   状態     種別             サービス
FBV012I 0001 実行中   信頼サービス     KCI
FBV012I 0002 実行中   信頼サービス     KSI
FBV012I 0003 実行中   FreeBSDホスト    なし
```

#### DISPLAY PARTITION n

- 構文: `DISPLAY PARTITION <partition_id>` (短縮形: `D PART <id>`)
- ABI コール: `DIAG_GET_PARTITION_LIST` (0x8003), `PARTITION_GET_STATUS` (0x0003)
- 出力:

英語:
```
FBV015I PARTITION 0001
FBV016I   STATE      : RUNNING
FBV017I   KIND       : TRUSTED_SERVICE
FBV018I   SERVICE    : KCI
FBV019I   EPOCH      : 0000000000000001
```

日本語:
```
FBV015I 区画 0001
FBV016I   状態       : 実行中
FBV017I   種別       : 信頼サービス
FBV018I   サービス   : KCI
FBV019I   エポック   : 0000000000000001
```

#### DISPLAY FAULTINFO n

- 構文: `DISPLAY FAULTINFO <partition_id>` (短縮形: `D FAULT <id>`)
- ABI コール: `PARTITION_GET_FAULT_INFO` (0x000A)
- 備考: `FAULTED` 状態のパーティションに対してのみ有効。
- 出力:

英語:
```
FBV050I FAULT INFO FOR PARTITION 0005
FBV051I   FAULT CODE      : 00000003
FBV052I   SOURCE COMPONENT: 00000001
FBV053I   DETAIL0         : 0000000000000000
FBV054I   DETAIL1         : 0000000000000000
```

日本語:
```
FBV050I 区画 0005 の障害情報
FBV051I   障害コード        : 00000003
FBV052I   発生元コンポーネント: 00000001
FBV053I   詳細0             : 0000000000000000
FBV054I   詳細1             : 0000000000000000
```

#### DISPLAY ARTIFACTS

- 構文: `DISPLAY ARTIFACTS` (短縮形: `D ART`)
- ABI コール: `DIAG_GET_ARTIFACT_LIST` (0x8005)
- 出力:

英語:
```
FBV060I ARTIFACT CATALOG (4 ENTRIES)
FBV061I OBJ_ID           KIND     HASH (FIRST 16 BYTES)
FBV062I 00000000000003E8 IMAGE    A1B2C3D4E5F60718...
FBV062I 00000000000003E9 MANIFEST 1122334455667788...
```

日本語:
```
FBV060I 成果物カタログ (4 件)
FBV061I OBJ_ID           種類     ハッシュ (先頭16バイト)
FBV062I 00000000000003E8 イメージ A1B2C3D4E5F60718...
FBV062I 00000000000003E9 マニフェスト 1122334455667788...
```

#### DISPLAY DEVICES

- 構文: `DISPLAY DEVICES` (短縮形: `D DEV`)
- ABI コール: `DIAG_GET_DEVICE_LIST` (0x8006)
- 出力:

英語:
```
FBV070I DEVICE CATALOG (2 ENTRIES)
FBV071I DEV_ID           SEG:BUS:SLOT.FN VND:DEV  ACS FLR MSIX QUAL
FBV072I 0000000000000001 0000:01:00.0    8086:1533 Y   Y   Y    Y
FBV072I 0000000000000002 0000:02:00.0    10DE:1CB3 N   Y   N    N
```

日本語:
```
FBV070I デバイスカタログ (2 件)
FBV071I DEV_ID           SEG:BUS:SLOT.FN VND:DEV  ACS FLR MSIX 適格
FBV072I 0000000000000001 0000:01:00.0    8086:1533 Y   Y   Y    Y
FBV072I 0000000000000002 0000:02:00.0    10DE:1CB3 N   Y   N    N
```

### 5.3 制御系コマンド

要求ケーパビリティ: `FBVBS_CAP_PARTITION_MANAGE`

#### 5.3.1 管理対象ポリシー (QUIESCE/RESUME/RECOVER 共通)

OCS が制御系コマンドで操作できる対象を以下に固定する。

| 対象区画 | 既定動作 | 返却ステータス | OCS メッセージ |
|---|---|---|---|
| `PARTITION_KIND_GUEST_VM` | 許可 | ABI 実行結果を返す | 成功時 `FBV080I/FBV082I/FBV085I`、失敗時対応エラー |
| OCS 自身 (`SERVICE_KIND_OCS`) | 禁止 | `PERMISSION_DENIED (3)` | `FBV103E ... FAILED - PERMISSION_DENIED` |
| `TRUSTED_SERVICE` かつ `KCI/KSI/IKS/SKS/UVS` | 禁止 | `PERMISSION_DENIED (3)` | `FBV103E ... FAILED - PERMISSION_DENIED` |
| `PARTITION_KIND_FREEBSD_HOST` | 既定禁止 | `PERMISSION_DENIED (3)` | `FBV109A HOST BREAK-GLASS REQUIRED` |

`FREEBSD_HOST` を OCS から操作する条件は次の両方を満たす場合のみとする。

1. ビルド時に `FBVBS_ENABLE_OCS_HOST_BREAK_GLASS` を有効化している。
2. 実行時にハイパーバイザー管理フラグ `ocs_break_glass_armed == 1`。

`ocs_break_glass_armed` は OCS コマンドで変更してはならない。
このフラグは「FREEBSD_HOST を対象とした 1 回の制御コマンド試行後」に必ず 0 に戻す。
`ocs_break_glass_armed` の初期値は 0 である。`FBVBS_ENABLE_OCS_HOST_BREAK_GLASS`
を有効化した構成でも、ハイパーバイザーの起動構成
`host_break_glass_boot_armed` が明示的に 1 の場合にのみ起動時に 1 にできる。

補足:

- 対象区画が存在しない場合は `NOT_FOUND (17)`。
- 対象区画は存在するが状態遷移条件を満たさない場合は `INVALID_STATE (16)`。
- 上記禁止ポリシーに違反した場合は ABI 実行前に拒否し、`PERMISSION_DENIED (3)` を返す。

#### QUIESCE PARTITION n

- 構文: `QUIESCE PARTITION <partition_id>` (短縮形: `Q PART <id>`)
- ABI コール: `PARTITION_QUIESCE` (0x0004)
- 出力:

英語:
```
FBV080I PARTITION 0003 QUIESCE INITIATED
```
```
FBV081E PARTITION 0003 QUIESCE FAILED - INVALID_STATE
```

日本語:
```
FBV080I 区画 0003 静止処理を開始しました
```
```
FBV081E 区画 0003 の静止に失敗 - 不正な状態
```

#### RESUME PARTITION n

- 構文: `RESUME PARTITION <partition_id>` (短縮形: `RES PART <id>`)
- ABI コール: `PARTITION_RESUME` (0x0005)
- 出力:

英語:
```
FBV082I PARTITION 0003 RESUME INITIATED
```

日本語:
```
FBV082I 区画 0003 の再開を開始しました
```

#### RECOVER PARTITION n

- 構文: `RECOVER PARTITION <partition_id> [FLAGS <hex_flags>]` (短縮形: `REC PART <id>`)
- ABI コール: `PARTITION_RECOVER` (0x0009)
- 回復フラグ既定値: `FBVBS_RECOVERY_RESTORE_PERSISTENT | FBVBS_RECOVERY_CLEAR_VOLATILE` (0x03)
- 出力:

英語:
```
FBV085I PARTITION 0005 RECOVER INITIATED FLAGS 0000000000000003
```

日本語:
```
FBV085I 区画 0005 の回復を開始しました フラグ 0000000000000003
```

### 5.4 コンソールローカルコマンド

ケーパビリティ不要（OCS パーティション内で完結）。

#### SET LANGUAGE EN / SET LANGUAGE JA

- 構文: `SET LANGUAGE EN` または `SET LANGUAGE JA` (短縮形: `SET LANG EN/JA`)
- 出力:

```
FBV090I LANGUAGE SET TO ENGLISH
```
```
FBV090I 言語を日本語に設定しました
```

#### HELP

- 構文: `HELP` または `HELP <command>`
- 出力:

英語:
```
FBV095I AVAILABLE COMMANDS:
FBV096I   DISPLAY SYSTEM       - SHOW SYSTEM STATUS AND BOOT ID
FBV096I   DISPLAY CAPABILITIES - SHOW CPU AND PLATFORM CAPABILITIES
FBV096I   DISPLAY CONSOLE      - SHOW VCD RX/TX CHANNEL STATUS
FBV096I   DISPLAY PARTITIONS   - LIST ALL PARTITIONS
FBV096I   DISPLAY PARTITION n  - SHOW DETAIL FOR PARTITION n
FBV096I   DISPLAY FAULTINFO n  - SHOW FAULT DETAIL FOR PARTITION n
FBV096I   DISPLAY ARTIFACTS    - LIST ARTIFACT CATALOG
FBV096I   DISPLAY DEVICES      - LIST DEVICE CATALOG
FBV096I   QUIESCE PARTITION n  - QUIESCE PARTITION n
FBV096I   RESUME PARTITION n   - RESUME PARTITION n
FBV096I   RECOVER PARTITION n  - RECOVER FAULTED PARTITION n
FBV096I   SET LANGUAGE EN|JA   - SET CONSOLE LANGUAGE
FBV096I   HELP [command]       - DISPLAY HELP
```

日本語:
```
FBV095I 利用可能なコマンド:
FBV096I   DISPLAY SYSTEM       - システム状態と起動IDを表示
FBV096I   DISPLAY CAPABILITIES - CPUと基盤機能を表示
FBV096I   DISPLAY CONSOLE      - VCDのRX/TXチャネル状態を表示
FBV096I   DISPLAY PARTITIONS   - 全区画を一覧表示
FBV096I   DISPLAY PARTITION n  - 区画 n の詳細を表示
FBV096I   DISPLAY FAULTINFO n  - 区画 n の障害詳細を表示
FBV096I   DISPLAY ARTIFACTS    - 成果物カタログを表示
FBV096I   DISPLAY DEVICES      - デバイスカタログを表示
FBV096I   QUIESCE PARTITION n  - 区画 n を静止
FBV096I   RESUME PARTITION n   - 区画 n を再開
FBV096I   RECOVER PARTITION n  - 障害区画 n を回復
FBV096I   SET LANGUAGE EN|JA   - コンソール言語を設定
FBV096I   HELP [コマンド]       - ヘルプを表示
```

### 5.5 設計上の意図的な制限

- `QUIESCE ALL`、`RECOVER ALL` のような一括操作は提供しない。
- `PARTITION CREATE`、`PARTITION DESTROY`、`PARTITION START` は OCS コマンドとして提供しない。
- OCS は `KCI/KSI/IKS/SKS/UVS` および OCS 自身を制御対象にできない。

---

## 6. コマンド解析規則

1. **大文字小文字不問:** 入力は内部で大文字に正規化する。
2. **トークン区切り:** 1 個以上のスペース (`0x20`) を区切りとする。
3. **区画 ID:** 10 進整数、範囲 `1..65535`。
4. **16 進値:** `FLAGS` は `0x` 接頭辞付き 16 進。
5. **最大行長:** `FBVBS_OCS_MAX_LINE_BYTES = 128`（終端 NUL を含まない）。
6. **空行:** 実行せずプロンプト再表示。
7. **不明コマンド:** `FBV098E UNKNOWN COMMAND`。
8. **受理文字:** 印字可能 ASCII (`0x20..0x7E`)、`CR(0x0D)`、`LF(0x0A)`、`BS(0x08)`、`DEL(0x7F)`、`Ctrl-U(0x15)`。
9. **非受理文字:** 8. の集合以外は入力段階で破棄し、トークナイザへ渡さない。
10. **CRLF 終端:** `CRLF` は 1 行終端として扱う。`CR` 単独、`LF` 単独も 1 行終端として扱う。

### 6.1 合法な短縮形の閉集合

以下のみ合法とする。

- `D SYS` = `DISPLAY SYSTEM`
- `D CAP` = `DISPLAY CAPABILITIES`
- `D CONS` = `DISPLAY CONSOLE`
- `D PARTS` = `DISPLAY PARTITIONS`
- `D PART <id>` = `DISPLAY PARTITION <id>`
- `D FAULT <id>` = `DISPLAY FAULTINFO <id>`
- `D ART` = `DISPLAY ARTIFACTS`
- `D DEV` = `DISPLAY DEVICES`
- `Q PART <id>` = `QUIESCE PARTITION <id>`
- `RES PART <id>` = `RESUME PARTITION <id>`
- `REC PART <id> [FLAGS <hex_flags>]` = `RECOVER PARTITION <id> [FLAGS <hex_flags>]`
- `SET LANG EN` = `SET LANGUAGE EN`
- `SET LANG JA` = `SET LANGUAGE JA`

これ以外の短縮形は全て拒否する。

---

## 7. 国際化 (i18n)

### 7.1 言語選択

- **起動時既定:** 英語 (`FBVBS_OCS_DEFAULT_LANGUAGE`、既定 `EN`)
- **実行時切替:** `SET LANGUAGE EN` または `SET LANGUAGE JA`
- **状態変数:** `OCS_LANG_EN = 0`, `OCS_LANG_JA = 1`

### 7.2 翻訳対象

| 要素 | 翻訳する | 理由 |
|------|----------|------|
| メッセージ本文 | はい | オペレーター可読性 |
| 列見出し | はい | オペレーター可読性 |
| ヘルプ文 | はい | オペレーター可読性 |
| 状態名 | はい | 言語切替対応 |
| プロンプト `FBVBS>` | いいえ | 端末互換 |
| メッセージ ID `FBVnnnS` | いいえ | 機械可読性 |
| コマンドキーワード | いいえ | 固定 ASCII |
| 区画 ID / 16進値 | いいえ | 技術データ |
| サービス名 (KCI 等) | いいえ | ABI 固定識別子 |
| PCI 識別子 | いいえ | 技術データ |

### 7.3 文字列テーブル

EN/JA を常時コンパイルし、実行時インデックスで選択する。

```c
struct ocs_message_entry {
    uint16_t message_number;
    char severity;
    const char *text_en;
    const char *text_ja;
};
```

日本語文字列は UTF-8 とし、UART へ生バイト送出する。

### 7.4 文字列サイズ制約

- 最大 200 エントリ
- EN: 1 エントリ最大 120 バイト
- JA: 1 エントリ最大 240 バイト
- 合計サイズ: 約 72KiB 以内

---

## 8. セキュリティ

### 8.1 入力検証

1. 行バッファは固定長 128 バイト。超過時は overflow 状態へ遷移し、終端受信まで追加文字を破棄する。
2. overflow 行確定時に `FBV099E` を 1 回出力し、行バッファを空に戻す。
3. 文字フィルタは 6 章の受理集合のみ許可する。
4. コマンド解析は固定トークンテーブル一致のみ。
5. 区画 ID は `UINT16_MAX` 超過を必ず拒否する。
6. ユーザー入力文字列をフォーマット文字列として使用しない。

### 8.2 バッファ安全性

1. 全バッファは静的確保。
2. 動的メモリ確保を禁止。
3. 再帰を禁止。
4. スタック深さは有界で Frama-C/WP で解析可能であること。
5. すべての書込前に境界検査を行う。

### 8.3 DoS 防御と可用性

1. **入力レート制限:** RX リング満杯時は追加文字を破棄する。
2. **コマンド処理率:** OCS は 1 ループで最大 1 コマンドのみ処理する。
3. **出力レート制限:** TX リング満杯時は OCS が待機する。
4. **監査優先:** UART 多重化の優先順位は監査ログ > OCS 出力。
5. **bounded wait (UART 書込):** UART 1 文字送出待ちは `FBVBS_UART_BOOT_SPIN_LIMIT` で上限化する。
6. **bounded wait (OCS 全体):** TX 満杯で進捗が止まる場合、既存ウォッチドッグ検出窓（既定約 100ms）で OCS fault 化し得る。
7. **fairness 条件付き保証:**
   監査入力が UART 帯域を恒常的に飽和しない区間では、各ポーリング周期で OCS TX 排出機会を持つ。
   監査出力が連続飽和する場合、OCS 出力遅延は無界になり得る（設計上許容）。
8. **「失われない」の条件:**
   OCS 出力が失われないのは、UART が健全であり、かつ TX リング満杯による OCS fault が発生しない期間に限る。
9. **watchdog 連携要件:**
   OCS パーティションは他の trusted service と同一窓で watchdog 監視対象に含める。
   「コマンド進捗なし」かつ「TX 満杯継続」が `FBVBS_WATCHDOG_MAX_CONSECUTIVE`
   ウィンドウを超えた場合、OCS を fault 化し fail-safe に遷移させる。

### 8.4 オペレーター操作の監査ログ

OCS は監査ログに次を記録する。

- **発信元コンポーネント:** `FBVBS_SOURCE_COMPONENT_OCS (9U)`
- **イベントコード:**
  - `FBVBS_EVENT_OPERATOR_COMMAND (0x91U)`
  - `FBVBS_EVENT_OCS_STARTUP (0x92U)`
  - `FBVBS_EVENT_OCS_LANGUAGE_CHANGE (0x93U)`
- **重大度:**
  - 照会: `NOTICE`
  - 制御: `WARNING`
  - ローカル設定変更: `NOTICE`

監査ペイロードは固定長で次を含む。

`session_id` は 64 ビットの非零値であり、ハイパーバイザーが OCS 起動時に 1 回だけ割り当てる。
同一 OCS セッション中の全コマンドで不変とし、OCS 再起動または再 attach まで変更しない。

`channel_kind` はセッションごとの固定値であり、ハイパーバイザーが OCS セッション開始時に設定する。
実際の接続経路を分類できない場合は `FBVBS_OCS_CHANNEL_UNKNOWN` を記録する。

```c
struct fbvbs_audit_operator_command_payload_v1 {
    uint16_t call_id;                /* ABI call id。ローカル処理のみは 0 */
    uint8_t command_kind;            /* 1=query 2=control 3=local */
    uint8_t channel_kind;            /* 0=unknown 1=physical 2=bmc_sol 3=ipmi_sol */
    uint32_t normalized_reason;      /* 正規化失敗理由コード。成功時 0 */
    uint64_t session_id;             /* コンソールセッション識別子 */
    uint64_t target_partition_id;    /* 対象なしは 0 */
    uint16_t target_partition_kind;  /* 対象なしは 0 */
    uint16_t target_service_kind;    /* 対象なしは 0 */
    uint32_t abi_status;             /* ABI status またはローカル拒否ステータス */
    uint32_t reserved0;
    uint64_t recovery_flags;         /* RECOVER 以外は 0 */
};
```

`normalized_reason` は最低限次を持つ。

- `0`: SUCCESS
- `1`: TARGET_NOT_FOUND
- `2`: TARGET_POLICY_DENIED
- `3`: HOST_BREAK_GLASS_REQUIRED
- `4`: INVALID_TARGET_STATE
- `5`: ABI_ERROR_OTHER
- `6`: VCD_ERROR

これにより、物理アクセス前提を維持したまま、操作種別・対象・結果・接続経路・
セッションを相関可能な監査証跡を残す。

---

## 9. UART 通信

### 9.1 既存実装 (freestanding_runtime.c)

- COM1 ベースポート: `0x3F8`
- ボーレート: 115200 bps, 8N1, FIFO 有効 (`FCR=0xC7`)
- `fbvbs_serial_init()`: UART 初期化
- `fbvbs_serial_putchar(char)`: `LSR.THRE` をポーリングし THR へ書込
- `fbvbs_boot_console_puts(const char *)`: `\n` を `\r\n` に変換
- IER = `0x00`（割り込み無効）

### 9.2 新規追加

```c
#define FBVBS_UART_LSR_DR 0x01U

static int fbvbs_serial_rx_ready(void) {
    return (fbvbs_asm_inb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LSR))
            & FBVBS_UART_LSR_DR) != 0U;
}

static uint8_t fbvbs_serial_getchar(void) {
    return fbvbs_asm_inb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_THR));
}
```

いずれも `#ifdef FBVBS_OPERATOR_CONSOLE` ガード付き。

### 9.3 行編集（OCS パーティション側）

1. `BS (0x08)` と `DEL (0x7F)` は同義。
2. `BS/DEL` は行バッファ長が 0 のとき無視し、0 超のとき 1 文字削除。
3. `Ctrl-U (0x15)` は当該入力行を全消去する。
4. `CR` は行終端として行を確定する。
5. `LF` は直前が `CR` の場合は無視し、そうでなければ行終端として確定する。
6. 行確定後にトークナイズし、実行後に必ず `FBVBS>` を再表示する。

### 9.4 フロー制御

RTS/CTS および XON/XOFF は使用しない。

1. パーサー攻撃面を増やさないため。
2. 既定ポーリング周期とリングサイズで想定バーストを吸収するため。
3. 監査ログ経路を停止させないため。

---

## 10. ビルド統合

### 10.1 コンパイルフラグ

```c
#ifdef FBVBS_OPERATOR_CONSOLE
/* OCS code included */
#endif
```

- 既定は未定義（OCS 無効）。
- Makefile ノブ: `FBVBS_ENABLE_OCS`。
- 追加ノブ: `FBVBS_ENABLE_OCS_HOST_BREAK_GLASS`（既定無効、`FBVBS_ENABLE_OCS` 有効時のみ評価）。

### 10.2 Makefile 変更

```makefile
ifdef FBVBS_ENABLE_OCS
  BAREMETAL_CFLAGS += -DFBVBS_OPERATOR_CONSOLE -DFBVBS_BUILD_CFG_OCS=1
  OCS_SOURCES := src/ocs/ocs_main.c src/ocs/ocs_parser.c \
                 src/ocs/ocs_messages.c src/ocs/ocs_i18n.c \
                 src/ocs/ocs_handlers.c
  BAREMETAL_SOURCES += $(OCS_SOURCES)
  ALL_SOURCES += $(OCS_SOURCES)
  FRAMA_C_WP_SOURCES += $(OCS_SOURCES)
  ifdef FBVBS_ENABLE_OCS_HOST_BREAK_GLASS
    BAREMETAL_CFLAGS += -DFBVBS_BUILD_CFG_OCS_HOST_BREAK_GLASS=1
  else
    BAREMETAL_CFLAGS += -DFBVBS_BUILD_CFG_OCS_HOST_BREAK_GLASS=0
  endif
else
  BAREMETAL_CFLAGS += -DFBVBS_BUILD_CFG_OCS=0
  BAREMETAL_CFLAGS += -DFBVBS_BUILD_CFG_OCS_HOST_BREAK_GLASS=0
endif
```

### 10.3 ソース構成

```
hypervisor/
  src/
    ocs/
      ocs_main.c       — メインループ、VCD I/O、行編集
      ocs_parser.c     — トークナイズ、構文照合
      ocs_messages.c   — FBVnnnS 出力
      ocs_i18n.c       — EN/JA テーブル
      ocs_handlers.c   — ABI 呼び出しハンドラ
    vcd.c              — VCD attach/status/ring操作
  include/
    fbvbs_ocs.h        — OCS 固有型・定数
```

### 10.4 既存検証への影響

- `FBVBS_ENABLE_OCS` 未定義時: OCS 関連ソースをコンパイルしない。
- 定義時:
  - OCS/VCD 関数に ACSL 契約を追加。
  - OCS ソースを `FRAMA_C_WP_SOURCES` に追加。
  - `__FRAMAC__` モデルでは UART/VCD 実 I/O を抽象化する。

### 10.5 構成識別 (OCS あり/なし)

`FBVBS_ENABLE_OCS` と `FBVBS_ENABLE_OCS_HOST_BREAK_GLASS` の組み合わせは
次で機械的に識別可能でなければならない。

1. **boot artifact profile:** OCS 有効時のみ `SERVICE_KIND_OCS` の manifest profile が存在する。
2. **artifact catalog:** OCS 有効時のみ OCS image/manifest object が catalog に現れる。
3. **measured boot evidence:** boot 構成測定値に `FBVBS_BUILD_CFG_OCS` を反映する。
4. **評価対象構成 ID:**
   - OCS 無効: `FBVBS-CONFIG-OCS0`
   - OCS 有効 / break-glass 無効: `FBVBS-CONFIG-OCS1-BG0`
   - OCS 有効 / break-glass 有効: `FBVBS-CONFIG-OCS1-BG1`
5. **break-glass evidence:** `FBVBS_ENABLE_OCS_HOST_BREAK_GLASS` を有効化した場合は、
   その有無を release evidence に `FBVBS_BUILD_CFG_OCS_HOST_BREAK_GLASS` として反映する。

---

## 11. 新規 ABI 追加

### 11.1 定数

```c
/* サービス種別 */
#define SERVICE_KIND_OCS                6U

/* ケーパビリティ */
#define FBVBS_CAP_OCS_ACCESS            (1ULL << 11)

/* 発信元コンポーネント */
#define FBVBS_SOURCE_COMPONENT_OCS      9U

/* イベントコード */
#define FBVBS_EVENT_OPERATOR_COMMAND    0x91U
#define FBVBS_EVENT_OCS_STARTUP         0x92U
#define FBVBS_EVENT_OCS_LANGUAGE_CHANGE 0x93U

/* OCS channel kind */
#define FBVBS_OCS_CHANNEL_UNKNOWN       0U
#define FBVBS_OCS_CHANNEL_PHYSICAL_UART 1U
#define FBVBS_OCS_CHANNEL_BMC_SOL       2U
#define FBVBS_OCS_CHANNEL_IPMI_SOL      3U
```

### 11.2 新規コール ID

```c
/* OCS calls (0x8xxx) */
#define FBVBS_CALL_OCS_VCD_ATTACH       0x8007U
#define FBVBS_CALL_OCS_VCD_STATUS       0x8008U
```

#### OCS_VCD_ATTACH (0x8007)

- 目的: OCS が VCD リングを登録する。
- 要求ケーパビリティ: `FBVBS_CAP_OCS_ACCESS`
- 呼び出し元制約: `PARTITION_KIND_TRUSTED_SERVICE && SERVICE_KIND_OCS`
- 入力:

```c
struct fbvbs_ocs_vcd_attach_request {
    uint64_t rx_ring_gpa;
    uint64_t tx_ring_gpa;
};
```

- 出力: なし（`actual_output_length = 0`）

- 返却規則:
   - 成功: `OK`
  - 前提違反（整列違反、同一 GPA 指定、重複領域）: `INVALID_PARAMETER`
  - caller 不正: `INVALID_CALLER`
  - capability 不足: `PERMISSION_DENIED`
  - 既 attach 済み同 owner: `ALREADY_EXISTS`
  - 既 attach 済み他 owner: `PERMISSION_DENIED`

#### OCS_VCD_STATUS (0x8008)

- 目的: VCD 状態照会
- 要求ケーパビリティ: `FBVBS_CAP_OCS_ACCESS`
- 入力: なし
- 出力:

```c
struct fbvbs_ocs_vcd_status_response {
    uint32_t rx_available;
    uint32_t tx_free;
};
```

- `active=false` の場合は `INVALID_STATE`。

### 11.3 OCS パーティションのケーパビリティマスク

```c
FBVBS_CAP_AUDIT_DIAG | FBVBS_CAP_PARTITION_MANAGE | FBVBS_CAP_OCS_ACCESS
```

---

## 12. エラー処理

### 12.1 エラーメッセージ一覧

| メッセージ ID | 重大度 | 状態 | 英語 | 日本語 |
|-------------|--------|------|------|--------|
| FBV098E | E | 不明コマンド | UNKNOWN COMMAND | 不明なコマンド |
| FBV099E | E | 行長超過 | COMMAND LINE TOO LONG | コマンド行が長すぎます |
| FBV100W | W | 区画なし | PARTITION nnnn NOT FOUND | 区画 nnnn が見つかりません |
| FBV101E | E | ID 解析失敗 | INVALID PARTITION ID | 不正な区画ID |
| FBV102E | E | 不正状態 | FAILED - INVALID_STATE | 失敗 - 不正な状態 |
| FBV103E | E | 権限不足/ポリシー拒否 | FAILED - PERMISSION_DENIED | 失敗 - 権限なし |
| FBV104E | E | 使用中 | FAILED - RESOURCE_BUSY | 失敗 - リソース使用中 |
| FBV105E | E | 未対応 | FAILED - NOT_SUPPORTED_ON_PLATFORM | 失敗 - 非対応 |
| FBV106E | E | 一般 ABI 失敗 | ABI CALL FAILED (STATUS nn) | ABIコール失敗 (ステータス nn) |
| FBV107W | W | VCD 通信異常 | VCD COMMUNICATION ERROR | VCD通信エラー |
| FBV108S | S | OCS 内部障害 | INTERNAL OCS ERROR | OCS内部エラー |
| FBV109A | A | break-glass 要求 | HOST BREAK-GLASS REQUIRED | ホスト操作には緊急保守承認が必要 |
| FBV110W | W | VCD 所有権不一致 | VCD OWNER MISMATCH | VCD所有者不一致 |
| FBV111S | S | VCD リング破損 | VCD RING CORRUPTED | VCDリング破損 |

`FBV107W` は UART/VCD の通信異常に限定し、`FBV110W` は owner 不整合、
`FBV111S` はリング破損に限定する。

### 12.2 ABI エラーの表示

ABI が `OK` 以外を返した場合、メッセージに生 status を必ず付加する。

```
FBV102E QUIESCE PARTITION 0003 FAILED - INVALID_STATE (STATUS 16)
```

```
FBV102E 区画 0003 の静止に失敗 - 不正な状態 (ステータス 16)
```

### 12.3 障害時の回復

1. **OCS パーティション故障:**
   - FreeBSD host が存在し利用可能な構成では、host 側管理経路から `PARTITION_RECOVER` で回復する。
   - no-host 構成では、外部管理経路（BMC/IPMI 電源制御または物理再起動）を要件とする。
   - その経路が存在しない構成では、再起動のみが最終回復手段である。
2. **UART 障害:**
   - UART 応答低下/停止時、監査一次経路は劣化し得る。
   - OCS 出力は TX リング満杯により停止し得る。
   - 停止が継続し 8.3 の watchdog 連携条件を満たすと、OCS は fault 化し得る。
3. **VCD リング破損:**
   - `read_index/write_index/size/magic` をアクセスごとに検証する。
   - 破損検出時は当該リングを `read=write=0` に再同期し、未送受信データを破棄する。
   - attach セッション内で 3 回目の破損検出時、VCD を `active=false` へ遷移し `FBV111S` を記録する。
   - VCD 再利用には `OCS_VCD_ATTACH` の再実行を要求する。

---

## 13. 運用シナリオ

### 13.1 起動シーケンス

1. ハイパーバイザー起動、COM1 初期化
2. トラステッドセキュリティサービス群 (KCI/KSI/IKS/SKS/UVS) を起動
3. `FBVBS_OPERATOR_CONSOLE` 定義時、OCS パーティションを生成・起動
4. OCS `ocs_main()` 実行:
   - a. 行バッファ/言語/セッション ID 初期化
   - b. `OCS_VCD_ATTACH` を 1 回実行
   - c. 起動バナー出力
   - d. メインループ (RX 取込 → 行編集 → 解析 → 実行 → 表示 → プロンプト)
5. `FBVBS_EVENT_OCS_STARTUP` を監査ログへ記録

trusted services を OCS より先に起動する理由:

1. OCS の照会結果を起動直後から一貫状態にするため。
2. セキュリティサービス未起動時の制御コマンド誤用を防ぐため。
3. no-host 構成でも、最低限の防御境界を先に成立させるため。

OCS 起動前障害の診断手段:

- ハイパーバイザーのブート状態ログ (`FBVBS: ...` で出力される既存の起動メッセージ)
- 監査一次経路 (`AUDIT seq=...`) のブートイベント

### 13.2 障害調査

```
FBVBS> D PARTS
FBV010I PARTITION LIST (3 ENTRIES)
FBV011I ID   STATE     KIND             SERVICE
FBV012I 0001 RUNNING   TRUSTED_SERVICE  KCI
FBV012I 0002 FAULTED   TRUSTED_SERVICE  KSI
FBV012I 0003 RUNNING   FREEBSD_HOST     NONE
FBVBS> D FAULT 2
FBV050I FAULT INFO FOR PARTITION 0002
FBV051I   FAULT CODE      : 00000004
FBV052I   SOURCE COMPONENT: 00000001
FBV053I   DETAIL0         : 0000000000000000
FBV054I   DETAIL1         : 0000000000000000
FBVBS> RECOVER PARTITION 2
FBV103E FAILED - PERMISSION_DENIED (STATUS 3)
```

上記例では KSI は OCS 制御禁止対象であり、回復は host 側管理経路で実施する。

### 13.3 言語切替

```
FBVBS> SET LANGUAGE JA
FBV090I 言語を日本語に設定しました
FBVBS> D SYS
FBV001I システム準備完了
FBV002I 起動ID 0123456789ABCDEF FEDCBA9876543210
FBV003I ABIバージョン 0001
FBV004I CPU機能 MBEC HLAT CET AESNI
FBV005I 基盤機能 IOMMU 測定起動 ホスト権限縮退 基盤準備完了
```

### 13.4 緊急時: 全ゲスト VM の静止

緊急保守前に全ゲストを静止する場合:

1. `D PARTS` で対象 `GUEST_VM` を列挙
2. 各対象に `QUIESCE PARTITION <id>` を個別実行
3. `D PARTS` で `QUIESCED` を確認

`TRUSTED_SERVICE` と `FREEBSD_HOST` は既定で OCS 制御対象外である。

### 13.5 端境ケース

- **監査ログバースト:** 監査優先により OCS 出力は遅延し得る。遅延無界は監査帯域飽和時に許容。
- **高速タイピング:** RX 満杯時は追加入力を破棄する。
- **NUL バイト:** フィルタで破棄。
- **ESC シーケンス:** ESC 自体を破棄。後続の受理文字は通常入力として扱われる。
- **CRLF:** 1 行終端として 1 回のみ実行。
- **OCS メモリ枯渇:** 静的確保のみのため枯渇経路なし。
- **シリアル多重接続:** バイト混在により壊れた行になっても、未知コマンドとして安全失敗する。

---

## 14. 実装フェーズ

### フェーズ 1: ハイパーバイザー側 VCD/UART/ポリシー基盤

1. ABI 定数追加 (`SERVICE_KIND_OCS`, capability/event/call IDs)
2. VCD 固定レイアウト型追加（flexible array 不使用）
3. UART RX 関数追加 (`fbvbs_serial_rx_ready`, `fbvbs_serial_getchar`)
4. `src/vcd.c` でリング操作、破損検出、再同期、attach/status を実装
5. プリエンプションタイマー出口から VCD ポーリング呼び出し
6. `command.c` に OCS_VCD_ATTACH/STATUS ハンドラ追加
7. caller 制約を拡張し、OCS の許可 call と禁止 call を明示実装
8. 制御対象ポリシー（5.3.1）を ABI 呼び出し前に実装

### フェーズ 2: OCS パーティション

1. `ocs_main.c` — ループ、VCD I/O、行編集
2. `ocs_parser.c` — 15 構文解析、短縮形閉集合、CRLF 正規化
3. `ocs_handlers.c` — 照会/制御/ローカル処理とエラー変換
4. `ocs_messages.c` — `FBVnnnS` 形式出力
5. `ocs_i18n.c` — EN/JA テーブル
6. `fbvbs_ocs.h` — 定数、型、監査 payload 定義

### フェーズ 3: ビルド・成果物・構成識別

1. Makefile ノブ `FBVBS_ENABLE_OCS` と `FBVBS_ENABLE_OCS_HOST_BREAK_GLASS` を追加
2. OCS ソースと WP 対象を条件付き追加
3. boot artifact/profile に OCS あり/なし差分を反映
4. measured boot と release evidence に
   `FBVBS-CONFIG-OCS0` / `FBVBS-CONFIG-OCS1-BG0` / `FBVBS-CONFIG-OCS1-BG1` を反映

### フェーズ 4: 検証

1. ACSL 契約:
   - VCD リング不変条件
   - attach 前提条件
   - インデックス更新順序
2. ユニットテスト:
   - 禁止対象操作拒否（OCS 自身、KCI/KSI/IKS/SKS/UVS、HOST without break-glass）
   - HOST break-glass 正系（armed 時 1 回のみ許可、試行後自動 disarm）
   - HOST break-glass 再試行拒否（2 回目は `PERMISSION_DENIED`）
   - attach 前提違反（整列、同一 GPA、再 attach）
   - `DISPLAY CONSOLE` の `OCS_VCD_STATUS` 正常/異常系
   - OCS パーティションの watchdog 監視登録と stall fault 化
   - ring wraparound/full/empty
   - parser (`CRLF`, `DEL`, `Ctrl-U`, overlong line, unknown command)
   - audit payload 項目検証（command kind, channel, session, reason, flags）
3. ファズ:
   - `fuzz_ocs_parser.c`（文字列入力）
   - `fuzz_vcd_ring.c`（インデックス破損入力）
4. 回帰:
   - `FBVBS_ENABLE_OCS` あり/なし双方で既存 test/proof を通過

---

## 15. 想定される課題

1. **UART 上の UTF-8 表示差異:**
   一部 BMC 端末で日本語表示が崩れる可能性がある。
   緩和策: 既定 EN、JA は明示切替。

2. **監査優先時の操作感劣化:**
   監査バースト時に OCS 出力遅延が増大する。
   緩和策: 監査優先を維持しつつ、遅延条件を仕様で明示し誤解を防ぐ。

3. **パーティションスロット消費:**
   OCS は 16 スロット中 1 を消費。
   緩和策: OCS はオプション機能。

4. **Frama-C/WP 証明負荷増:**
   VCD 契約とパーサー境界条件で証明目標が増える。
   緩和策: 関数分割と bounded loop 維持。

5. **VCD 共有メモリ権限設計:**
   ページ単位では双方 RW が必要だが、書込責務は SPSC 契約で制約する必要がある。
   緩和策: 役割別書込規則、破損検出、3 回閾値で deactivate を仕様化する。

6. **no-host 構成の回復制約:**
   OCS 故障時に host 管理経路がない場合、外部再起動が唯一の回復手段となる。
   緩和策: デプロイ要件として外部管理経路の有無を明示し、なければ再起動手順を運用標準化する。
