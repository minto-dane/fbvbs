# スタンドアロン FBVBS マイクロハイパーバイザー OCS / VCD 要件

- 文書バージョン: 2.0
- 最終更新: 2026-04-03
- 適用対象: standalone トラック
- 非適用対象: FreeBSD 保護スタックの trusted-service 制御面

---

## 1. この文書の役割

本書は、**スタンドアロン FBVBS マイクロハイパーバイザー**向けの OCS (Operator Console Service) と VCD (Virtual Console Device) の要件を定義する。

重要な前提:

1. OCS は standalone トラックの運用支援機能である
2. OCS は full FBVBS スタックの KCI/KSI/IKS/SKS/UVS 制御面ではない
3. VCD は OCS を支える transport substrate である

---

## 2. 現在の実装状況

| 項目 | 状態 | 実装 |
|---|---|---|
| `SERVICE_KIND_OCS` | 実装済み | `hypervisor/include/fbvbs_abi.h` |
| `FBVBS_CAP_OCS_ACCESS` | 実装済み | `hypervisor/include/fbvbs_abi.h` |
| `OCS_VCD_ATTACH` / `OCS_VCD_STATUS` | 実装済み | `src/command.c` |
| VCD attach/status fail-closed | 実装済み | `src/io/vcd_virtualization.c` |
| VCD テスト | 実装済み | `tests/c/storage/test_vcd_virtualization.c` |
| OCS runtime skeleton | 実装済み | `src/io/vcd_virtualization.c` |
| OCS runtime skeleton テスト | 実装済み | `tests/c/storage/test_vcd_virtualization.c` |
| parser / command set | 最小実装済み | `src/io/vcd_virtualization.c` |
| i18n | 最小実装済み | `tools/operator/generate_operator_console_severity_summary.py` |
| UART multiplexer | 未実装 | なし |

したがって、2026-04-05 時点で実装済みなのは **VCD substrate と OCS 最小 command set** であり、
**OCS 製品機能全体ではない**。

---

## 3. スコープ

### 3.1 対象

1. VCD attach/status ABI
2. VCD owner binding と fail-closed 動作
3. OCS が操作する standalone 管理面の最小要件
4. OCS の監査・故障・回復方針

### 3.2 対象外

1. KCI/KSI/IKS/SKS/UVS の制御
2. `fbvbs.ko` と FreeBSD 介入点
3. shell、スクリプト、任意プログラム実行
4. FreeBSD host break-glass の設計

---

## 4. アーキテクチャ境界

## 4.1 原則

1. ハイパーバイザーが transport と監査境界を所有する
2. OCS は VCD のみを介して I/O する
3. OCS は optional であり、無効でも本体が成立する
4. OCS は standalone 管理面だけを扱う

## 4.2 構成

```text
operator transport
        |
        v
  hypervisor-owned ingress/egress
        |
        v
      VCD substrate
        |
        v
   optional OCS partition
```

---

## 5. 実装済み ABI 拡張

### 5.1 定数

```c
#define SERVICE_KIND_OCS      6U
#define FBVBS_CAP_OCS_ACCESS  (1ULL << 13)
```

### 5.2 call ID

```c
#define FBVBS_CALL_OCS_VCD_ATTACH 0x8011U
#define FBVBS_CALL_OCS_VCD_STATUS 0x8012U
```

### 5.3 request / response

```c
struct fbvbs_ocs_vcd_attach_request {
    uint64_t rx_ring_gpa;
    uint64_t tx_ring_gpa;
};

struct fbvbs_ocs_vcd_status_response {
    uint8_t active;
    uint8_t reserved0[3];
    uint32_t corruption_count;
    uint64_t owner_partition_id;
    uint64_t rx_ring_gpa;
    uint64_t tx_ring_gpa;
};
```

### 5.4 呼び出し前提

1. caller は `PARTITION_KIND_TRUSTED_SERVICE`
2. caller は `SERVICE_KIND_OCS`
3. caller は `FBVBS_CAP_OCS_ACCESS` を持つ
4. 不一致は fail-closed で拒否する

---

## 6. VCD 契約

## 6.1 目的

VCD は OCS のための transport substrate であり、ハイパーバイザーと OCS の間に最小限の双方向リング境界を提供する。

## 6.2 契約

1. RX/TX は single-producer / single-consumer とする
2. `owner_partition_id` は authoritative な owner binding とする
3. owner mismatch を検出したら `active=false` へ fail-closed 遷移する
4. `OCS_VCD_STATUS` は owner に対する状態照会のみを許可する
5. VCD は command interpreter を含まない

## 6.3 監査

最低限記録する事象:

1. attach
2. status
3. owner mismatch
4. corruption count 増加

---

## 7. 将来の OCS が扱う管理面

standalone OCS は、将来次の管理面のみを扱う。

### 7.1 照会系

1. system summary
2. partition list / partition status
3. scaling limits / headroom
4. storage pool / vdisk status
5. fault / health / evidence summary
6. reason guidance / remediation hints

### 7.2 制御系

1. quiesce / resume / recover partition
2. acknowledge degraded state
3. trigger evidence export
4. request safe-stop or maintenance mode

### 7.3 明示的非目標

1. shell
2. filesystem access
3. arbitrary binary launch
4. KCI/KSI/IKS/SKS/UVS 操作
5. FreeBSD host protection policy の直接操作

### 7.4 presentation model

1. OCS の authoritative boundary は VCD と structured command set である
2. operator-facing UI はその上位 presentation layer として構成する
3. 既定 presentation は ISPF 風の panel set とする
4. presentation locale は少なくとも `ja` と `en` をサポートする
5. locale 差分で machine-readable JSON schema を変えてはならない
6. panel set は少なくとも primary option menu / partition list / partition detail を持つ
7. panel 操作規約は `Option ===>` / `Command ===>` / `Scroll ===>` / PF key footer / line command を基本とする
6. mainframe 風 UI profile の詳細は `plan/standalone/operator-console-mainframe-ui.md` を参照する

---

## 8. セキュリティ原則

1. OCS は standalone 管理面を越える権限を持たない
2. OCS を理由に transport と監査の ownership を移してはならない
3. OCS 出力より監査出力を優先する
4. OCS fault は fail-safe に扱う
5. OCS を万能 recovery path と誤認しない

---

## 9. 障害時の振る舞い

### 9.1 現在実装済みの failure semantics

1. owner mismatch は VCD 無効化
2. attach 前提違反は `INVALID_PARAMETER`
3. 非 owner の状態照会は fail-closed

### 9.2 将来必要な failure semantics

1. transport stall
2. parser corruption
3. command overrun
4. audit backpressure
5. operator session reset

各 failure は、理由コード、監査、operator 可視性、回復条件を持たなければならない。

---

## 10. 実装フェーズ

## Phase O0: VCD substrate

すでに実装済み。

1. `SERVICE_KIND_OCS`
2. `FBVBS_CAP_OCS_ACCESS`
3. `OCS_VCD_ATTACH`
4. `OCS_VCD_STATUS`
5. owner mismatch fail-closed

## Phase O1: OCS runtime skeleton

次の最小構成を追加した。

1. session state
2. transport multiplexer
3. command dispatcher
4. structured message format
5. `HELLO / GET_SYSTEM_SUMMARY / GET_PARTITION_SUMMARY / GET_SCALING_SUMMARY / GET_STORAGE_SUMMARY / GET_HELP`

## Phase O2: standalone command set

1. display system
2. display partitions
3. display scaling
4. display storage
5. quiesce / resume / recover
6. help

現在は 1, 2, 3, 4, 5, 6 の最小 command set が実装済みで、`acknowledge degraded state` は未実装である。

### 現在の基盤 ABI

1. `DIAG_GET_PARTITION_LIST`
   health / quarantine / last fault / measurement epoch を含む
2. `PARTITION_GET_STATUS`
   state / health / quarantine を返す
3. `PARTITION_GET_FAULT_INFO`
   structured fault record と remediation guidance を返す
4. `DIAG_GET_REASON_GUIDANCE`
   deny / fault / health / partition ごとの runbook code と recovery/action flags を返す
5. `DIAG_GET_INVENTORY`
   partition / artifact / device / storage の inventory summary を返す
6. `generate_operator_console_severity_summary.py`
   inventory / partition list / fault record / guidance から one-screen severity summary を生成し、
   Markdown と ISPF 風 panel set を `ja` / `en` locale で出力する
7. `render_operator_console_mainframe.py`
   canonical summary JSON から ISPF 風 panel set を生成する
8. `ocs_mainframe_tui.py`
   canonical summary JSON から read-only full-screen TUI を起動し、
   PF key 相当の操作で primary menu / partition list / partition detail / reference を遷移できる
8. `run_operator_console_tui.py`
   canonical summary JSON を read-only full-screen TUI として表示し、
   PF key 相当のキー操作で primary/list/detail/reference を遷移できる

## Phase O3: verification and evidence

1. parser tests
2. fault / stall tests
3. audit correlation
4. OCS enabled / disabled build evidence
5. operator tooling compatibility matrix generation evidence
6. operator console severity summary generation evidence

---

## 11. 完了条件

OCS 機能群は、少なくとも次を満たしたときに完成扱いとする。

1. standalone 文脈でのスコープが固定されている
2. VCD と OCS runtime の責務が分離されている
3. command set が閉じている
4. shell 化していない
5. fault / audit / recovery behavior が定義済みである
6. OCS 無効構成でも本体が成立する
