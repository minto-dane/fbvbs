# FBVBS — FreeBSD Virtualization-Based Security

FBVBS v7 は、FreeBSD 向けのマイクロハイパーバイザーベースのセキュリティアーキテクチャです。このリポジトリは、その retained C 実装と設計文書を保持します。

producer-facing な standalone コンポーネントとしては `hypervisor/` を境界に扱います。将来の FBVBS trusted-service stack は `plan/` で設計を進めており、同じリポジトリ内にあっても release 境界は分けて扱います。

## 現在の実装状態

- **マイクロハイパーバイザー本体**: C11 + ACSL。現時点の機械的検証は GCC `-fanalyzer` と unit test が中心です。
- **bare-metal boot path**: Multiboot2 + GRUB ISO + QEMU smoke を追加しました。現在は TCG smoke とローカル KVM smoke の両方で `boot64`、boot artifact materialization、boot catalog ingest、host partition seed まで進み、VMX を expose しない環境では `VMX unavailable` で fail-closed します。bare-metal retained-C release profile では host kernel artifact `0x1700` をロード済みハイパーバイザーの immutable image bytes に束縛し、残りの retained boot artifact は `artifact:0x...` / `fbvbs.object_id=0x...` を持つ明示 Multiboot module からのみ受理します。ISO build はその module 群の封入有無も検証します。
- **retained-C foundation 判定**: `fbvbs_audit_runtime_ready()`、`fbvbs_platform_foundation_ready()`、`fbvbs_platform_high_assurance_foundation_ready()` により、一次監査ログ経路を初期化済みか、VMX + runtime-ready IOMMU + audit path まで到達した foundation か、さらに measured boot を伴う高保証 foundation かをコード上で区別するようにしました。host deprivilege は別に `fbvbs_host_deprivilege_runtime_ready()` で可視化されます。
- **host-side 検証安全化**: unit test / coverage / fuzz などの userspace build では CPU security 内部の MSR access を最小ソフトウェアモデルに落とし、privileged `RDMSR/WRMSR` を直接実行しないようにしています。bare-metal build は引き続き実 MSR 命令を使います。
- **VM 実行ハンドオフ**: VMCS 構成ロジックはありますが、host deprivilege / `VMLAUNCH` の end-to-end handoff はまだ release 完了ではありません。
- **Frama-C WP**: `make proof` / `make frama-c-wp` は `opam` 側の Frama-C を優先して起動します。現時点では proof gap が残っており、主な残課題は `vmx.c` の union モデル warning、Missing RTE guards、一部 timeout です。`make proof-smoke` は fatal annotation/user error なしで安定起動するようになりました。
- **残る hard blocker**: authoritative な IOMMU bring-up、safe device passthrough teardown、host deprivilege / `VMLAUNCH` handoff、Frama-C proof gap の縮退は未完です。`PARTITION_LOAD_IMAGE` 自体は retained-C の固定 ELF64 `ET_EXEC` loader として実装済みで、authoritative `image_object_id` を materialize して `Loaded` へ遷移できます。manifest/profile 整合、`entry_ip` の executable segment 包含、`initial_sp` の writable/non-executable stack 条件を満たさない場合は `MEASUREMENT_FAILED` / `INVALID_PARAMETER` で拒否します。measured boot は high-assurance 条件として検出し、foundation build では absence を fail-closed stop ではなく capability/state として記録します。`KCI_SET_WX` は retained-C 内蔵の SHA-384 と approved per-page digest table を用いて runtime binding します。synthetic boot artifact builders は non-bare-metal test path 限定であり、bare-metal release 境界には含めません。

## セキュリティ目標

1. パーティションメモリ分離
2. カーネルコード整合性
3. カーネル状態整合性
4. 秘密鍵非抽出性
5. 監査証跡整合性

## ディレクトリ構成

```
fbvbs/
├── hypervisor/           # retained C マイクロハイパーバイザー実装
│   ├── src/              # C11 + ACSL ソース
│   ├── include/          # ヘッダファイル
│   ├── tests/            # unit test
│   └── compliance/       # コンプライアンス/保証文書
├── plan/                 # 設計・計画文書
│   ├── fbvbs-design.md   # FBVBS v7 仕様書
│   ├── fbvbs-comprehensive-roadmap-2026-03-20.md
│   └── agent-handoff-summary.md
└── README.md             # このファイル
```

## ビルドと検証

```bash
cd hypervisor
make analyze  # GCC -fanalyzer
make test     # unit test
make coverage # gcov line/branch coverage (command.c/vm_policy.c/vmx.c の 0% regression を拒否)
make proof    # Frama-C WP（WP plugin がある環境のみ）
make proof-smoke
make baremetal-iso
make run-qemu-smoke
make release-manifest
make release-hypervisor
```

## 関連文書

- [FBVBS v7 仕様書](plan/fbvbs-design.md)
- [包括ロードマップ](plan/fbvbs-comprehensive-roadmap-2026-03-20.md)
- [エージェント引き継ぎサマリー](plan/agent-handoff-summary.md)
- [Standalone Hypervisor Boundary](hypervisor/README.md)
- [retained C 境界保証](hypervisor/compliance/retained_c_leaf_boundary.md)
- [Contribution Guide](CONTRIBUTING.md)
- [Release Guide](RELEASE.md)
- [Security Policy](SECURITY.md)
