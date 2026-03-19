# FBVBS — FreeBSD Virtualization-Based Security

FBVBS v7 は、FreeBSD 向けのマイクロハイパーバイザーベースのセキュリティアーキテクチャです。このリポジトリは、その retained C 実装と設計文書を保持します。

## 現在の実装状態

- **マイクロハイパーバイザー本体**: C11 + ACSL。現時点の機械的検証は GCC `-fanalyzer` と unit test が中心です。
- **Frama-C WP**: `make proof` で実行できますが、現在の環境では WP plugin が未導入なら fail します。
- **fail-closed の未実装機能**: `KCI_SET_WX` の byte-backed page binding、authoritative な IOMMU/boot integrity bring-up、device passthrough qualification は未完成のため成功を返さない設計にしています。

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
│   └── development-plan.md
└── README.md             # このファイル
```

## ビルドと検証

```bash
cd hypervisor
make analyze  # GCC -fanalyzer
make test     # unit test
make proof    # Frama-C WP（WP plugin がある環境のみ）
```

## 関連文書

- [FBVBS v7 仕様書](plan/fbvbs-design.md)
- [開発計画](plan/development-plan.md)
- [retained C 境界保証](hypervisor/compliance/retained_c_leaf_boundary.md)
