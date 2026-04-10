# Storage Authorization Model

## 目的

host / service / tenant の storage 権限と ownership scope を整理し、
storage 操作の actor ごとの意味差をなくす。

## 実装

`hypervisor/tools/storage/generate_storage_authorization_model.py` は次を固定する。

1. `host`
2. `service`
3. `tenant`

各 actor について、allowed call set、required capability baseline、
ownership scope、delegation 可否を JSON / Markdown で出力する。

ownership policy は少なくとも次を含む。

1. `owner_partition_id_authoritative = true`
2. delegation は `attached_partition_only`
3. owner change は新規 vdisk 発行でのみ許可
4. pool granularity invariant を維持

runtime 側では `hypervisor/src/storage/storage_virtualization.c` が requester を
`host` / `trusted service admin` / `tenant owner` として解決し、pool 作成/破棄や
QoS 更新は admin のみ、vdisk status と attach/detach は owner tenant にも開く。

## 検証

`hypervisor/tests/python/storage/test_storage_governance_tools.py` は
tenant actor が `owned-only` scope を持つことを固定する。
