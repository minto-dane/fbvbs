# Standalone Management Diagnostics ABI

- Status: Active
- Authority level: derived specification
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 19-20, 49, Appendix L.11
- Depends on: `plan/standalone/architecture/standalone-runtime-architecture.md`
- Supersedes: standalone diagnostics ABI fragments in `plan/standalone/archive/`
- Intended audience: runtime 実装者、operator tooling 実装者、compatibility reviewer

## 1. 目的

standalone 管理面で operator が最低限追うべき `health / fault / deny / inventory` を、
監査や回復 runbook と結びついた ABI として固定する。

この文書は、現時点で実装済みの初版診断 ABI をまとめる。

## 2. 実装済み call

1. `FBVBS_CALL_DIAG_GET_REASON_GUIDANCE`
2. `FBVBS_CALL_DIAG_GET_INVENTORY`
3. `FBVBS_CALL_DIAG_GET_FAULT_RECORD`
4. `FBVBS_CALL_DIAG_GET_PARTITION_LIST`
5. `FBVBS_CALL_PARTITION_GET_FAULT_INFO`
6. `FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY`
7. `FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION`

## 3. Reason Guidance

### 3.1 request

`fbvbs_diag_reason_guidance_request`

1. `reason_domain`
2. `reason_input`
3. `partition_id`

### 3.2 domain

1. `FBVBS_GUIDANCE_DOMAIN_DENY`
2. `FBVBS_GUIDANCE_DOMAIN_FAULT`
3. `FBVBS_GUIDANCE_DOMAIN_HEALTH`
4. `FBVBS_GUIDANCE_DOMAIN_PARTITION`

### 3.3 response

`fbvbs_diag_reason_guidance_response`

1. canonical reason code
2. severity
3. runbook code
4. current `health_state`
5. current `fault_code`
6. current `deny_reason`
7. current `quarantine_reason`
8. `recommended_recovery_flags`
9. `recommended_action_flags`

### 3.4 意味

1. deny status は canonical `deny_reason` へ正規化する
2. policy deny threshold fault は recovery runbook と security escalation を返す
3. degraded / quarantined / recovery の health は operator guidance を返す
4. partition domain は現在状態から適切な fault/health guidance を導出する
5. `RETRY_LATER` は generic deny guidance では `BUSY` / `RETRY_COMMAND` として扱い、abuse-guard lockout のみ監査側で `RATE_LIMIT` に分岐させる

## 4. Inventory

### 4.1 response

`fbvbs_diag_inventory_response`

1. occupied partition count
2. tombstone partition count
3. guest VM count
4. service partition count
5. healthy / degraded / quarantined / recovery count
6. artifact count
7. device count
8. storage pool count
9. vdisk count

### 4.2 目的

1. component inventory ABI の初版
2. health aggregation model の基礎カウンタ
3. operator console の system summary 入力

## 5. Structured Fault Record

### 5.1 request

`fbvbs_partition_id_request`

### 5.2 response

`fbvbs_diag_fault_record_response`

1. `partition_id`
2. `partition_state`
3. `health_state`
4. `fault_code`
5. `source_component`
6. `quarantine_reason`
7. severity
8. runbook code
9. `fault_detail0`
10. `fault_detail1`
11. `measurement_epoch`
12. `recommended_recovery_flags`
13. `recommended_action_flags`

### 5.3 意味

1. fault record は current partition state と remediation guidance を同時に返す
2. `last_fault_code == 0` かつ `quarantine_reason == 0` の partition に対しては `NOT_FOUND`
3. policy deny threshold quarantine は structured fault として返す

## 6. Partition Diagnostics

### 6.1 list entry

`fbvbs_diag_partition_entry`

1. `partition_id`
2. `state`
3. `health_state`
4. `fault_code`
5. `quarantine_reason`
6. `kind`
7. `service_kind`
8. `measurement_epoch`

### 6.2 fault info response

`fbvbs_partition_fault_info_response`

1. `fault_code`
2. `source_component`
3. `health_state`
4. severity
5. runbook code
6. `deny_reason`
7. `quarantine_reason`
8. `fault_detail0`
9. `fault_detail1`
10. `measurement_epoch`
11. `recommended_recovery_flags`
12. `recommended_action_flags`

### 6.3 意味

1. partition list は isolation / quarantine / recovery を list view のまま観測できる
2. fault info は structured fault record の軽量 API として使える
3. health ABI は `partition status` と `partition list` の両方で露出する
4. management abuse guard の `lockout_windows` と `policy_deny_count` も `partition status` / `partition list` で観測できる

## 7. Schema Registry

`fbvbs_diag_schema_registry_response`

1. management ABI version
2. health / audit / inventory / guidance / fault record schema version
3. compatibility flags

この call は初版 compatibility baseline を operator tooling に提供する。
`health_schema_version` は `partition status` / `partition list` の health layout を含み、
`fault_record_schema_version` は `partition fault info` の structured layout と整合する。
tooling は加えて `FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE` と
`FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE` を見て parser を固定する。

## 8. Command Version Negotiation

`fbvbs_diag_command_version_request`

1. `target_call_id`
2. `requested_abi_version`
3. reserved field は `0`

`fbvbs_diag_command_version_response`

1. `target_call_id`
2. `negotiation_status`
3. `negotiated_abi_version`
4. `minimum_abi_version`
5. `maximum_abi_version`
6. `command_class_flags`
7. `service_kind`
8. `required_capability_mask`
9. `supported_feature_flags`
10. `required_feature_flags`
11. `compatibility_flags`

意味:

1. `requested_abi_version == 0` は current supported version への auto-negotiate として扱う
2. unsupported call は hypercall 全体を失敗させず、`negotiation_status` で `UNSUPPORTED_CALL` を返す
3. unsupported version は `negotiation_status` で `UNSUPPORTED_VERSION` を返し、silent fallback しない
4. `supported/required feature flags` は caller sequence, caller nonce, replay protection, reserved-zero, separate-output, host callsite validation の前提を返す
5. operator tooling は schema registry と組み合わせて per-call gating を事前判定できる

## 8.5 Guest Feature Bitmap Negotiation

`fbvbs_diag_guest_feature_request`

1. `partition_kind`
2. `requested_abi_version`
3. `requested_feature_bitmap`
4. reserved field は `0`

`fbvbs_diag_guest_feature_response`

1. `partition_kind`
2. `negotiation_status`
3. `negotiated_abi_version`
4. `minimum_abi_version`
5. `maximum_abi_version`
6. `supported_feature_bitmap`
7. `required_feature_bitmap`
8. `negotiated_feature_bitmap`
9. `denied_feature_bitmap`
10. `compatibility_flags`

意味:

1. `partition_kind == PARTITION_KIND_GUEST_VM` を standalone guest profile の固定点として扱う
2. `requested_abi_version == 0` は current supported guest profile への auto-negotiate として扱う
3. unsupported version は `UNSUPPORTED_VERSION` を返し、silent fallback しない
4. unsupported profile は `UNSUPPORTED_PROFILE` を返す
5. denied bits は `denied_feature_bitmap` で返し、tooling が silent downgrade しない
6. measured boot / device assignment は runtime capability bitmap に応じて supported set が変わる

## 9. セキュリティ境界

1. すべて host 管理 call として扱う
2. capability は `FBVBS_CAP_AUDIT_DIAG`
3. command page validation と host callsite validation を経由する
4. response は固定長 ABI で返し、任意文字列や可変長 secret を含めない

## 10. Diagnostic Bundle Export

`hypervisor/tools/diagnostics/export_diagnostic_bundle.py` はこの ABI 群を tarball に束ねる補助ツールとして実装済みで、以下を fail-close で強制する。

1. 入力は repository root 配下、または `--allow-input-root` で明示した採取 root 配下に限定する
2. symlink 経由の入力は拒否する
3. `--include` / `--doc` は private key / secret-like content を既定拒否する
4. `schema registry` の必須 key と artifact 側 `schema_version` を、存在する範囲で照合する
5. `measurement_epoch` と `boot_id` は、入力 JSON が値を持つ場合に cross-check する
6. 署名時は archive に格納される最終 manifest 自身を署名し、`signature_algorithm`、`public_key_fingerprint_sha384`、`certificate_fingerprint_sha384`、`verification_hint` を固定する
7. `tools/diagnostics/scrub_support_dump.py` は UTF-8 support dump を別段で scrub し、redaction report を残す
8. `--support-dump` を bundle に含める場合、`--support-dump-report` を必須化し、manifest に `support_dump_scrubbing` を固定する
9. `capture_complete` は既定で `false` とし、operator が `--capture-complete` を明示した場合だけ complete 扱いにする

## 11. Operator Console Severity Summary

`hypervisor/tools/operator/generate_operator_console_severity_summary.py` は
`inventory / partition list / fault record / guidance` を集約し、
operator console の one-screen summary を JSON / Markdown で生成する。

1. partition severity は `fault-record` -> `guidance` -> `health-state` 推定の順で決める
2. overall severity は partition ごとの最大値とする
3. `ALERT / CRITICAL / ERROR / WARNING / NOTICE / INFO / DEBUG` に応じた display rule を固定する
4. これにより ABI 自体は固定長のまま、operator tooling 側の summary 表示規則だけを文書化できる

## 12. Incident Timeline Integrity

`hypervisor/tools/incident/reconstruct_incident_timeline.py` は raw log から normalized timeline を生成し、
`hypervisor/tools/incident/seal_incident_timeline.py` は record ごとに
`record_sha384` / `previous_chain_sha384` / `chain_sha384` を付与して、
top-level `root_chain_sha384` で sealed timeline を固定する。

`hypervisor/tools/incident/record_operator_acknowledgment.py` はこの `root_chain_sha384` に紐づく
append-only acknowledgment ledger を生成する。

## 13. Standalone Evidence Pack

`hypervisor/tools/diagnostics/correlate_standalone_incident_artifacts.py` は
diagnostic bundle / sealed timeline / severity summary / acknowledgment ledger /
compatibility matrix / panel manifest を横断して correlation summary を生成する。

`hypervisor/tools/diagnostics/generate_standalone_evidence_pack.py` は
これらを `fbvbs-standalone-evidence-pack` として束ね、
必要に応じて evidence pack manifest を detached signature で署名する。

fail-close consistency:

1. diagnostic bundle は `fbvbs-standalone-diagnostic` でなければならない
2. timeline は `root_chain_sha384` を持たなければならない
3. acknowledgment ledger がある場合は timeline root と一致しなければならない
4. allowed root 外や symlink-backed input は拒否する
5. correlation summary は warnings を manifest に固定する

## 14. 現時点の未完

1. full health aggregation scoring
2. support dump 全体に対する完全な secret scrubbing policy

## 15. 関連文書

1. `../implementation/standalone-implementation-plan.md`
2. `../architecture/standalone-runtime-architecture.md`
3. `../operations/operator-control-plane.md`
4. `../operations/incident-audit-and-recovery.md`
5. `compatibility-and-versioning.md`
6. `verification-and-validator-suite.md`
7. `evidence-and-support-artifacts.md`
