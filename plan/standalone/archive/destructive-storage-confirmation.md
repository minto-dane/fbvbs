# Destructive Storage Confirmation

## 目的

destroy 系 storage 操作を bare ID だけで進めず、operator intent と
inventory precondition に束縛された confirmation artifact を要求する。

## 実装

`hypervisor/tools/storage/issue_destructive_storage_confirmation.py` は
少なくとも次の operation をサポートする。

1. `destroy-pool`
2. `destroy-vdisk`

artifact は次を含む。

1. `operation`
2. `target_kind`
3. `target_id`
4. `session_correlation_id`
5. `inventory_sha384`
6. `preconditions`
7. optional `origin_attestation_sha384`

`hypervisor/tools/storage/verify_destructive_storage_confirmation.py` は
hash / session / operation / expiry を検証する。

## fail-close rules

1. `destroy-pool` は empty pool でなければ発行しない
2. `destroy-vdisk` は detached vdisk でなければ発行しない
3. `storage-admin` 以外には発行しない

## 検証

`hypervisor/tests/python/storage/test_storage_governance_tools.py` は
origin attestation に束縛された `destroy-vdisk` confirmation を発行・検証できることを固定する。
