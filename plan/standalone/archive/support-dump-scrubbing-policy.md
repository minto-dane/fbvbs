# Standalone Support Dump Scrubbing Policy

## 目的

standalone 運用時に採取する support dump から、operator token や private key などの secret-like 値を
fail-close で除去する初版ポリシーを定義する。

## 実装済み土台

`hypervisor/tools/diagnostics/scrub_support_dump.py` を追加し、text / binary / archive の support dump に対して次を強制する。

1. repository root または `--allow-input-root` 配下の入力だけを許可する
2. symlink-backed input を拒否する
3. binary payload は byte-level redaction を試み、archive member は再帰 scrub する
4. encrypted archive member / unsafe path / symlink member は fail-close で拒否する
5. bearer token / API key / AWS secret access key / password assignment / private key block を赤線化する
6. scrub report を JSON で残し、どの rule が何件発火したかを固定する

## 既定 redaction

1. `Authorization: Bearer ...` -> `<REDACTED:BEARER_TOKEN>`
2. `x-api-key: ...` -> `<REDACTED:API_KEY>`
3. `aws_secret_access_key = ...` -> `<REDACTED:AWS_SECRET_ACCESS_KEY>`
4. `password = ...` -> `<REDACTED:PASSWORD>`
5. `-----BEGIN ... PRIVATE KEY----- ... -----END ... PRIVATE KEY-----` -> `<REDACTED:PRIVATE_KEY>`

## 運用境界

1. zip / tar / gzip archive は再帰 scrub する
2. binary payload は byte-level redaction 対象にし、text と同じ rule を優先適用する
3. confidential guest crash dump の完全 scrub はまだ未完で、別ワークストリームで扱う
4. scrub 済み output は `export_diagnostic_bundle.py --support-dump` と
   `--support-dump-report` で正式格納できる

## 残課題

1. tenant identifier / host path / network topology の追加 redaction
2. confidential workload 向け dump policy
3. bundle export への sealed incident timeline / acknowledgment 自動連携
