# Vdisk Lifecycle State Machine

## 目的

boolean の組み合わせではなく、operator tooling が使える状態機械として
vdisk lifecycle を固定する。

## 実装

`hypervisor/tools/storage/generate_vdisk_lifecycle_model.py` は次の状態を出力する。

1. `PROVISIONED`
2. `ATTACHED`
3. `DETACH_PENDING`
4. `RELEASE_PENDING`
5. `QUARANTINED`
6. `DESTROYED`

transition table は少なくとも次を含む。

1. `attach-vdisk`
2. `detach-vdisk`
3. `detach-audit-closed`
4. `destroy-confirmed`
5. `destroy-vdisk`
6. `corruption-detected`

runtime 側では `hypervisor/include/fbvbs_hypervisor.h` の
`fbvbs_virtual_disk.lifecycle_state` と
`hypervisor/src/storage/storage_virtualization.c` の helper で、
create/attach/detach/destroy のたびに internal lifecycle を更新する。

## 検証

`hypervisor/tests/python/storage/test_storage_governance_tools.py` は
model JSON / Markdown が生成されることを固定する。
