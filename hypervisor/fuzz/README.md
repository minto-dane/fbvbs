# FBVBS ファズハーネス

このディレクトリには、retained-C マイクロハイパーバイザー向けのfuzzテスト用エントリポイントが含まれています。

## ハーネス一覧

- `fuzz_command_page.c`
  - コマンドページの解析とディスパッチ前提条件を検査します
  - `fuzz/corpus/command_page/` には schema registry と guest feature negotiation の valid / malformed / reserved-zero seed を含め、host-only 管理 ABI の parser/smoke を決定論的に再現します
  - 制限事項: ファズハーネスはシングルスレッドで動作するため、複数 CPU が同時にコマンドページを操作する競合状態（TOCTOU）は検査対象外です。ハイパーバイザー本体はマルチ CPU 対応であり、本番コードではスピンロックやローカルコピーで競合を防いでいます
- `fuzz_manifest.c`
  - マニフェスト・プロファイル・アーティファクトの検証パスを検査します
- `fuzz_multiboot2.c`
  - Multiboot2 タグの解析と境界チェックを検査します
- `fuzz_iommu.c`
  - DMAR/IVRS テーブルの解析と IOMMU 探索ロジックを検査します
- `fuzz_log_decoder.c`
  - 監査ログリングの初期化、レコード追記、CRC 処理、ミラー情報照会を検査します
- `fuzz_partition_loader.c`
  - retained-C 固定 ELF64 `ET_EXEC` パーティションローダーを検査します（マニフェスト/プロファイル紐付け、セグメント検証、後処理を含む）

## 現在の状況

- リポジトリにはハーネスのソース、`fuzz/corpus/` 配下のシードコーパス、`make -C hypervisor fuzz-build`、`make -C hypervisor fuzz-smoke` が同梱されています。
- シードコーパスは意図的に小規模かつ決定論的です。長時間の AFL++/libFuzzer による本格的なファジングは、補完的な外部エビデンスとして別途実施します。
- ファズテストの結果は補助的なエビデンスであり、形式検証やハードウェア検証の代替にはなりません。
- `fuzz/corpus/command_page/` には standalone 管理 ABI の malformed input seed を同梱しています。guest feature negotiation、command version negotiation、reserved-zero 違反、reserved flag 違反、短い入出力長を最低限の corpus として固定しています。

## 使い方

全ハーネスのビルドとスモークテスト:

```bash
cd hypervisor
make fuzz-build
make fuzz-smoke
```

生成されたバイナリは `hypervisor/build/` に配置されます。`make fuzz-smoke` の結果は `hypervisor/build/fuzz-smoke.txt` に出力されます。
