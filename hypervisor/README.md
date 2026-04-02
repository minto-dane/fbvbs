# スタンドアロン マイクロハイパーバイザー

このディレクトリは、retained-C で実装されたマイクロハイパーバイザーの単体コンポーネントです。

完全な FBVBS スタックよりも意図的にスコープを絞っています:

- 含まれるもの: ハイパーバイザー本体、bare-metal ブートパス、テスト、ファズハーネス、コンプライアンス文書
- 含まれないもの: トラステッドサービスパーティション、FreeBSD フロントエンド、bhyve/vmm 統合

## 前提条件

### 必須パッケージ（ビルド・テスト・静的解析）

```bash
sudo apt-get update
sudo apt-get install -y \
    gcc-13 \
    make \
    cppcheck \
    python3
```

### Bare-metal ISO ビルド・QEMU スモークテスト用

```bash
sudo apt-get install -y \
    qemu-system-x86 \
    grub-pc-bin \
    grub-common \
    xorriso \
    mtools
```

### Frama-C WP 形式検証用

```bash
sudo apt-get install -y opam z3
opam init --auto-setup --disable-sandboxing -y
opam install frama-c alt-ergo -y
eval $(opam env)
```

> **注意:** Frama-C コマンドの実行前には毎回 `eval $(opam env)` が必要です。

## ビルドチュートリアル

### 1. リポジトリの取得と移動

```bash
git clone <repository-url>
cd fbvbs/hypervisor
```

### 2. 基本ビルド（静的解析）

GCC の `-fanalyzer` で全ソースを解析します。まずはここから始めてください。

```bash
make analyze
```

成功すると `GCC -fanalyzer: all 25 sources passed.` と表示されます。

### 3. ユニットテストの実行

8 つのテストスイートを順番に実行します。

```bash
make test
```

### 4. cppcheck による追加の静的解析

```bash
make cppcheck
```

### 5. カバレッジ計測

gcov で行カバレッジとブランチカバレッジを計測します。

```bash
make coverage
```

結果は `build/` 配下の `.gcov` ファイルに出力されます。

### 6. ファズハーネスのビルドとスモークテスト

6 つのファズハーネスをビルドし、コミット済みコーパスでスモーク実行します。

```bash
make fuzz-build
make fuzz-smoke
```

### 7. Bare-metal ISO のビルドと QEMU 起動

GRUB Multiboot2 の ISO イメージを作成し、QEMU でブートテストを行います。

```bash
make baremetal-iso          # ISO イメージの生成
make run-qemu-smoke         # TCG モードでスモークテスト
make run-qemu-iommu-smoke   # Intel/AMD 両 IOMMU エミュレーション
make run-qemu-matrix        # 全組み合わせマトリクス
```

KVM が利用可能な環境では、より高速なテストも実行できます:

```bash
make run-qemu-kvm-smoke
```

### 8. Frama-C WP 形式検証

ACSL アノテーションに対する WP 証明を実行します。事前に opam 環境を有効にしてください。

```bash
eval $(opam env)
make proof              # 全ソース一括検証
make proof-shards       # ファイルごとの個別検証（推奨）
make proof-smoke        # 起動確認のみ（高速）
```

### 9. CI ゲート全体の一括実行

CI パイプラインと同等の全検証を順番に実行します。

```bash
make ci
```

### 10. リリースビルド

全ゲート通過後、リリース成果物を生成します。

```bash
make release-readiness
make release-manifest
make release-evidence
make release-hypervisor
```

署名付きリリースを行う場合:

```bash
FBVBS_RELEASE_SIGNING_KEY=/path/to/release-key.pem make sign-release
```

## 主要コマンド一覧

| コマンド | 説明 |
|---------|------|
| `make analyze` | GCC `-fanalyzer` による静的解析 |
| `make test` | ユニットテスト（8 スイート） |
| `make coverage` | gcov カバレッジ計測 |
| `make cppcheck` | cppcheck 静的解析 |
| `make fuzz-build` | ファズハーネスのビルド |
| `make fuzz-smoke` | ファズスモークテスト |
| `make proof` | Frama-C WP 一括検証 |
| `make proof-shards` | Frama-C WP ファイル別検証 |
| `make proof-smoke` | Frama-C WP 起動確認 |
| `make baremetal-iso` | Bare-metal ISO 生成 |
| `make run-qemu-smoke` | QEMU/TCG スモークテスト |
| `make run-qemu-kvm-smoke` | QEMU/KVM スモークテスト |
| `make run-qemu-iommu-smoke` | IOMMU エミュレーション付きスモーク |
| `make run-qemu-matrix` | QEMU 全マトリクス実行 |
| `make ci` | CI ゲート一括実行 |
| `make provenance` | 来歴メタデータ生成 |
| `make release-hypervisor` | リリースゲート実行 |
| `make sign-release` | 署名付きリリース |

## 現在のブート状況

bare-metal Multiboot2 イメージには、リポジトリ内で完結する段階的な QEMU テストパスがあります:

- **ステージ 1:** `make run-qemu-smoke` — Intel VT-d エミュレーション付き QEMU/TCG ブートテスト
- **ステージ 2:** `make run-qemu-kvm-smoke` — `/dev/kvm` とパスワードなし `sudo` が必要な QEMU/KVM ブートテスト
- **ステージ 3:** `make run-qemu-iommu-smoke` — q35 上で `intel-iommu` と `amd-iommu` の両方をテスト。`make run-qemu-matrix` で全組み合わせを一括実行

現在の開発環境では、`boot64` → ブートアーティファクト実体化 → ブートカタログ取り込み → FreeBSD ホストパーティションのシードまで到達します。VMX を公開しない環境では `VMX unavailable` で安全に停止します。

retained-C の監査パスは、bare-metal 上でコミット済みレコードをプライマリ COM1/UART シンクへ出力しつつ、ミラーリングをメモリ上に保持します。ブートパスは以下の準備状態を区別します:

- **基盤準備完了:** VMX + ランタイム対応 IOMMU (`fbvbs_platform_foundation_ready`)
- **監査ランタイム準備完了:** ミラーリング初期化済み + retained-C プライマリ UART/OOB シンク (`fbvbs_audit_runtime_ready`)
- **高保証基盤準備完了:** 基盤 + measured boot (`fbvbs_platform_high_assurance_foundation_ready`)
- **ホスト権限委譲準備完了:** `VMLAUNCH` ハンドオフ完了 (`fbvbs_host_deprivilege_runtime_ready`)

ブートアーティファクトは、ホストカーネル成果物がハイパーバイザーイメージのバイト列に紐付けられ、その他の retained ブートアーティファクトは `artifact:0x...` / `fbvbs.object_id=0x...` コマンドラインを持つ Multiboot モジュールとして受理されます。`make baremetal-iso verify-baremetal-iso` でこれらのモジュールが ISO に含まれていることを検証できます。

ホスト側の検証では、retained-C CPU セキュリティ層がユーザー空間ビルドで決定論的なソフトウェア MSR モデルを使用します。そのため、ユニットテスト・gcov・ファズハーネスは特権命令 `RDMSR/WRMSR` を実行しません。bare-metal ビルドでは実 MSR 命令を使用します。

## リリースに関する注意

現在の環境で `make release-hypervisor` の retained-C 基盤ゲートは通過しており、`provenance.json`、`release-readiness.json`、`release-evidence.tar.gz`、QEMU テストサマリー、ケースごとの QEMU ログが出力されます。署名鍵が用意できれば `make sign-release` で分離署名を追加できます。ただし、証明の未完了箇所、ハードウェア初期化の未完了箇所、ホスト権限委譲ハンドオフが残っているため、高保証リリースとしてはまだ完結していません。

カバレッジゲートはリーフ境界・ポリシーセキュリティ・障害注入の各テストスイートを含み、`command.c`・`vm_policy.c`・`vmx.c` の行/ブランチカバレッジがゼロに退行することを拒否します。現在の計測値は以下の通りです:

| ファイル | 行カバレッジ | ブランチカバレッジ |
|---------|------------|-----------------|
| `command.c` | 24.44% | 57.62% |
| `vm_policy.c` | 67.34% | 59.32% |
| `vmx.c` | 95.00% | 100.00% |
