# FBVBS スタンドアロン・マイクロハイパーバイザー 本番アーキテクチャ

- 文書バージョン: 2.0
- 最終更新: 2026-04-03
- 対象: スタンドアロン FBVBS マイクロハイパーバイザー
- 非対象: FreeBSD 保護スタックそのもの

---

## 1. この文書の位置づけ

本書は、shared retained-C foundation を**独立した仮想化基盤**として成立させるためのアーキテクチャ文書である。

ここでの「スタンドアロン」は次を意味する。

1. FreeBSD を保護対象 OS とする FBVBS スタックとは別トラックである
2. KCI/KSI/IKS/SKS/UVS の完成を前提にしない
3. scaling / storage / diagnostics / VCD/OCS を中心に製品化する

フル FBVBS スタックの規範仕様は `plan/full-stack/fbvbs-design.md` が正本である。

---

## 2. アーキテクチャ境界

### 2.1 共有基盤として再利用するもの

1. partition / vCPU / memory / VM の状態機械
2. EPT/NPT、IOMMU、割り込み制御、CPU security
3. boot / log / watchdog / page allocator
4. fail-closed hypercall ABI 基盤

### 2.2 standalone として追加で成立させるもの

1. scaling runtime limits
2. storage pool / virtual disk 管理
3. diagnostics / health / inventory
4. VCD と optional OCS
5. standalone release evidence と運用 runbook

### 2.3 standalone に含めないもの

1. FreeBSD を守るための trusted services
2. `fbvbs.ko`
3. `bhyve` / `vmm` の full-stack 統合意味論

---

## 3. 現在の実装スナップショット

| 領域 | 実装 | 現状 |
|---|---|---|
| shared foundation | `command.c`, `partition.c`, `memory.c`, `security.c`, `log.c` | 実装済み |
| platform | `src/platform/*`, `cpu_security.c`, `watchdog.c`, `page_alloc.c` | 実装済みだが実機閉鎖未完 |
| scaling | `src/core/scaling.c` | 実装済み |
| storage | `src/storage/storage_virtualization.c` | 実装済み |
| VCD | `src/io/vcd_virtualization.c` | attach/status + message transport 実装済み |
| OCS runtime | parser / command set / session management | 最小実装済み |

standalone 製品としては、**基盤と最小管理面はあるが、運用面と実機閉鎖がまだ足りない**。

---

## 4. 論理アーキテクチャ

## 4.1 実行面

実行面は shared retained-C foundation に依存する。

1. partition lifecycle
2. vCPU 実行
3. memory mapping
4. DMA / interrupt boundary
5. CPU security enforcement

## 4.2 管理面

standalone 管理面は、full-stack service control ではなく、**独立仮想化基盤の管理機能**に限定する。

主要 surfaces:

1. diagnostics
2. scaling limits
3. storage lifecycle
4. health / evidence
5. optional OCS

## 4.3 データ面

データ面で管理する主要オブジェクト:

1. partition
2. vCPU
3. memory object
4. IOMMU domain
5. storage pool
6. virtual disk
7. VCD control block

---

## 5. standalone 管理オブジェクト

## 5.1 scaling

`src/core/scaling.c` は runtime 上限の正本である。

standalone では少なくとも次を外部可視化する。

1. VM 数上限
2. vCPU 数上限
3. host CPU 数上限
4. VM あたり vdisk 数上限
5. VM あたり memory 上限
6. vdisk size 上限

## 5.2 storage

`src/storage/storage_virtualization.c` は standalone ストレージ管理面の核である。

管理対象:

1. storage pool
2. virtual disk
3. attach / detach
4. pool status / vdisk status
5. vdisk QoS

## 5.3 VCD

`src/io/vcd_virtualization.c` は OCS 用 transport substrate である。

現在の責務:

1. OCS partition の登録
2. owner binding
3. status 照会
4. owner mismatch fail-closed

現在の非責務:

1. command parser
2. line editing
3. transport multiplexer
4. operator session policy

---

## 6. OCS の扱い

OCS は **optional control-plane extension** である。

1. OCS がなくてもハイパーバイザー本体は成立しなければならない
2. OCS があっても UART 直接所有を許さない
3. OCS が操作するのは standalone 管理面に限定する
4. OCS を full-stack trusted services の制御面と混同しない

OCS の詳細要件は `plan/standalone/operator-console-requirements.md` が正本である。

---

## 7. セキュリティ原則

1. management ABI も guest ABI と同様に fail-closed とする
2. capability は必要条件、policy は十分条件とする
3. storage / scaling / diagnostics であっても監査境界外に置かない
4. teardown 後の stale mapping / stale DMA visibility を禁止する
5. convenience path を理由に万能権限主体を作らない

---

## 8. 障害と運用

standalone 製品で閉じるべき障害面:

1. collector loss
2. storage corruption
3. device revoke failure
4. OCS fault
5. health degradation

必要な性質:

1. 理由コードがある
2. 監査される
3. operator に可視
4. 回復条件がある

---

## 9. 現在の主要 blocker

1. authoritative IOMMU 実機 bring-up
2. final host deprivilege / `VMLAUNCH`
3. standalone control-plane compatibility discipline
4. evidence / health / runbook の体系化
5. OCS runtime の未実装

これらが閉じるまで、standalone-ready を主張してはならない。

---

## 10. 検証と release

standalone トラックでも、shared foundation と同じ release discipline を使う。

主要ゲート:

1. `make -C hypervisor analyze`
2. `make -C hypervisor test`
3. `make -C hypervisor proof-shards`
4. `make -C hypervisor release-hypervisor`

ただし、現在の `release-hypervisor` は retained-C foundation release gate であり、standalone 製品完成宣言ではない。

standalone release に追加で必要なもの:

1. management ABI compatibility evidence
2. storage / scaling operational evidence
3. OCS or non-OCS management runbook
4. hardware validation campaign

---

## 11. 文書間の責務分担

1. `plan/full-stack/fbvbs-design.md`
   - フル FBVBS スタック仕様
2. `plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md`
   - 全体ロードマップ
3. `plan/standalone/goal-quality-implementation-plan.md`
   - standalone 実装優先計画
4. `plan/standalone/operator-console-requirements.md`
   - standalone OCS 要件

本書は standalone アーキテクチャの正本であり、full-stack の規範仕様を置き換えない。
