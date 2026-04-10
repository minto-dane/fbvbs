# Standalone Diagnostic ABI Compatibility Baseline

## 目的

`plan/standalone` の WS-A / WS-K / WS-L で要求される運用診断 ABI の初版固定点を定義する。
この文書は、operator が deny / fault / health / inventory を同一の管理 ABI から読めること、
および schema 互換性の初版を機械的に確認できることを目的とする。

## 対象コマンド

### `FBVBS_CALL_DIAG_GET_REASON_GUIDANCE` (`0x8008`)

- 入力: `fbvbs_diag_reason_guidance_request`
- 出力: `fbvbs_diag_reason_guidance_response`
- 用途:
  - deny status から canonical deny reason を取得する
  - health state から運用 severity / runbook を取得する
  - partition 現在状態から remediation を取得する
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - 返却値に秘密 payload は含めない

### `FBVBS_CALL_DIAG_GET_INVENTORY` (`0x8009`)

- 入力: なし
- 出力: `fbvbs_diag_inventory_response`
- 用途:
  - partition / health / artifact / device / storage の集約状態を 1 回で観測する
  - operator console の初期 inventory/health 集計に使う
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - count だけを返し、contents や secret metadata は返さない

### `FBVBS_CALL_DIAG_GET_FAULT_RECORD` (`0x800A`)

- 入力: `partition_id`
- 出力: `fbvbs_diag_fault_record_response`
- 用途:
  - partition の最新 fault / quarantine を 1 レコードとして取得する
  - `fault_code`, `source_component`, `detail0/1`, `severity`, `runbook_code`,
    `recommended_recovery_flags`, `recommended_action_flags` をまとめて返す
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - latest record のみ返し、監査ログ全量 export とは分離する

### `FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY` (`0x800B`)

- 入力: なし
- 出力: `fbvbs_diag_schema_registry_response`
- 用途:
  - management ABI / health / audit / inventory / guidance / fault record の schema version を固定する
  - tooling が silent mismatch を起こさないよう compatibility flag を返す
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - reserved field は将来拡張まで `0` のままとする

### `FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION` (`0x800C`)

- 入力: `fbvbs_diag_command_version_request`
- 出力: `fbvbs_diag_command_version_response`
- 用途:
  - tooling が `target_call_id` ごとの negotiated ABI version を事前照会する
  - `required_capability_mask` と `command_class_flags` を call ごとに固定して、silent mismatch を防ぐ
  - `supported_feature_flags` / `required_feature_flags` で transport 前提を機械取得する
  - `requested_abi_version == 0` を current supported version への auto-negotiate として扱う
  - unsupported version は structured `negotiation_status` で返し、silent fallback しない
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - unsupported call は transport error ではなく structured `negotiation_status` で返す

### `FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES` (`0x800D`)

- 入力: `fbvbs_diag_guest_feature_request`
- 出力: `fbvbs_diag_guest_feature_response`
- 用途:
  - tooling が standalone guest profile を `partition_kind` ごとに事前照会する
  - `requested_feature_bitmap` に対して enabled / denied bit を machine-readable に返す
  - measured boot / direct device assignment の runtime gating を silent mismatch なしで取得する
  - unsupported profile は `UNSUPPORTED_PROFILE` を返す
- security:
  - `FBVBS_CAP_AUDIT_DIAG` 必須
  - host partition call のみ許可
  - denied bit は transport error ではなく structured response で返す

## Schema Versions

- `FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION = 1`
- `FBVBS_HEALTH_SCHEMA_VERSION = 1`
- `FBVBS_AUDIT_SCHEMA_VERSION = 1`
- `FBVBS_INVENTORY_SCHEMA_VERSION = 1`
- `FBVBS_GUIDANCE_SCHEMA_VERSION = 1`
- `FBVBS_FAULT_RECORD_SCHEMA_VERSION = 1`

## Compatibility Flags

- `FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE`
  - health state ABI 初版を minor upgrade で維持する
- `FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE`
  - audit ABI 初版を minor upgrade で維持する
- `FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE`
  - deny / fault / health guidance shape を初版固定する
- `FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO`
  - tooling / caller は reserved field を常に `0` にする
- `FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE`
  - `DIAG_GET_PARTITION_LIST` の entry layout を health schema 初版として固定する
- `FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE`
  - `PARTITION_GET_FAULT_INFO` の structured layout を fault record schema と整合させて固定する

## Runbook Mapping Baseline

- deny:
  - `INVALID_PARAMETER`, `ABI_VERSION_UNSUPPORTED` -> `FBVBS_RUNBOOK_VALIDATE_INPUT`
  - `PERMISSION_DENIED` -> `FBVBS_RUNBOOK_REVIEW_CAPABILITY`
  - `INVALID_CALLER`, `CALLSITE_REJECTED`, `REPLAY_DETECTED` -> `FBVBS_RUNBOOK_REAUTHORIZE_CALLER`
  - page busy / command race 由来の `RETRY_LATER` -> `FBVBS_RUNBOOK_RETRY_COMMAND`
  - abuse-guard lockout 由来の `RETRY_LATER` -> `FBVBS_RUNBOOK_WAIT_LOCKOUT`
- fault:
  - `FAULT_CODE_VM_EXIT_UNCLASSIFIED` -> `FBVBS_RUNBOOK_PLATFORM_INVESTIGATION`
  - `FBVBS_FAULT_WATCHDOG_TIMEOUT` -> `FBVBS_RUNBOOK_PARTITION_RECOVERY`
  - `FBVBS_FAULT_POLICY_DENY_THRESHOLD` -> `FBVBS_RUNBOOK_PARTITION_RECOVERY`
- health:
  - `HEALTHY` -> `FBVBS_RUNBOOK_NONE`
  - `DEGRADED` -> `FBVBS_RUNBOOK_PLATFORM_INVESTIGATION`
  - `QUARANTINED` -> `FBVBS_RUNBOOK_PARTITION_RECOVERY`
  - `RECOVERY` -> `FBVBS_RUNBOOK_MONITOR_RECOVERY`

## 実装境界

- inventory は summary count を返す初版に限定する
- fault record は latest partition fault に限定する
- schema registry は version disclosure と compatibility flag に限定する
- command version negotiation は current command-page ABI の negotiated version disclosure と capability/class disclosure に限定する
- diagnostic bundle export tool は schema registry / inventory / partition list / fault record / guidance を正規化 tarball に束ねる
- bundle export は repository root または `--allow-input-root` 配下の入力だけを許可し、symlink と secret-like include を拒否する
- signed bundle は detached manifest signature と signer `sha384` metadata を固定する
- incident timeline と downgrade/upgrade 互換検証は次段で実装する
- operator tooling compatibility matrix generator は `hypervisor/include/fbvbs_abi.h` の固定点から JSON / Markdown の同一 row set を出力する
