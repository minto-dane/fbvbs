# Command Idempotency Rules

## 目的

standalone 管理 command の duplicate / replay 時の意味を、operator tooling と CI が同じ形で参照できるように固定する。

## 実装

`hypervisor/tools/partition/generate_standalone_command_idempotency_rules.py` は、standalone で重要な管理 command について次を JSON / Markdown で出力する。

1. mutation class
2. idempotency class
3. replay policy
4. duplicate outcome
5. operator 向けメモ

## 現時点の代表ルール

1. `DIAG_GET_SCHEMA_REGISTRY` は deterministic read
2. `DIAG_NEGOTIATE_COMMAND_VERSION` は deterministic read
3. `DIAG_NEGOTIATE_GUEST_FEATURES` は deterministic read
4. `PARTITION_QUIESCE` と `PARTITION_RESUME` は convergent mutation
5. `PARTITION_RECOVER` は measurement epoch を進めるため non-idempotent mutation
6. `OCS_VCD_ATTACH` は create-once で duplicate は `ALREADY_EXISTS`
7. `STORAGE_CREATE_POOL` と `STORAGE_CREATE_VDISK` は non-idempotent mutation

## 完了条件

1. duplicate request の意味が command 単位で列挙される
2. replay protection と idempotency が混同されない
3. CI で row set が固定される
