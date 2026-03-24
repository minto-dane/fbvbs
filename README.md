# FBVBS — FreeBSD Virtualization-Based Security

FBVBS v7 は、FreeBSD 向けのマイクロハイパーバイザーベースのセキュリティアーキテクチャです。このリポジトリは、その retained C 実装と設計文書を保持します。

producer-facing な standalone コンポーネントとしては `hypervisor/` を境界に扱います。将来の FBVBS trusted-service stack は `plan/` で設計を進めており、同じリポジトリ内にあっても release 境界は分けて扱います。

## 現在の実装状態

- **マイクロハイパーバイザー本体**: C11 + ACSL。現時点の機械的検証は GCC `-fanalyzer` と unit test が中心です。
- **bare-metal boot path**: Multiboot2 + GRUB ISO + QEMU smoke を追加しました。現在は TCG smoke とローカル KVM smoke の両方で `boot64` と retained-C init まで進み、VMX を expose しない環境では `VMX unavailable` で fail-closed します。より機能の多い環境では、その先の IOMMU / boot-integrity gate まで進む設計です。
- **VM 実行ハンドオフ**: VMCS 構成ロジックはありますが、host deprivilege / `VMLAUNCH` の end-to-end handoff はまだ release 完了ではありません。
- **Frama-C WP**: `make proof` / `make frama-c-wp` は `opam` 側の Frama-C を優先して起動します。現時点では proof gap が残っており、特に `command.c` の typed-cast 境界と一部 public API contract の tightening を継続中です。
- **fail-closed の未実装機能**: `PARTITION_LOAD_IMAGE` の実 loader/materializer、authoritative な IOMMU/boot integrity bring-up、safe device passthrough teardown は未完成のため成功を返さない設計にしています。`KCI_SET_WX` は retained-C 内蔵の SHA-384 と approved per-page digest table を用いて runtime binding するようになりました。

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
make proof    # Frama-C WP（WP plugin がある環境のみ）
make baremetal-iso
make run-qemu-smoke
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
