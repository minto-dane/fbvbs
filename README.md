# FBVBS — FreeBSD Virtualization-Based Security

FBVBS v7 は、FreeBSD 向けのマイクロハイパーベースのセキュリティアーキテクチャです。

## アーキテクチャ概要

FBVBS はデュアル言語アーキテクチャを採用しています：

- **マイクロハイパーバイザー本体**: C11 + ACSL + Frama-C WP による形式検証
- **信頼サービスパーティション**: Ada 2022 + SPARK 2014 による実装

## セキュリティ目標

1. パーティションメモリ分離
2. カーネルコード整合性
3. カーネル状態整合性
4. 秘密鍵非抽出性
5. 監査証跡整合性

## ディレクトリ構成

```
fbvbs/
├── hypervisor/           # マイクロハイパーバイザー
│   ├── src/              # C11 + Frama-C WP 検証済みソース
│   ├── include/          # ヘッダファイル
│   ├── tests/            # テスト
│   └── compliance/       # コンプライアンス文書
├── plan/                 # 設計・計画文書
│   └── fbvbs-design.md   # FBVBS v7 仕様書
└── README.md             # このファイル
```

## ビルド

```bash
cd hypervisor
make proof    # Frama-C WP による証明
make analyze  # Frama-C EVA による解析
make test     # テスト実行
```

## 関連文書

- [FBVBS v7 仕様書](plan/fbvbs-design.md)
