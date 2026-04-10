# Storage Invariant Checker

## 目的

pool / vdisk の capacity・allocated・attached 整合性を fail-close に検証する。

## 実装

`hypervisor/tools/storage/check_storage_invariants.py` は少なくとも次を検査する。

1. `sum(vdisk.size_bytes) == pool.allocated_bytes`
2. `len(vdisks in pool) == pool.vdisk_count`
3. `allocated_bytes <= capacity_bytes`
4. `vdisk.size_bytes % granularity_bytes == 0`
5. attached vdisk count の整合

## 検証

`hypervisor/tests/python/storage/test_storage_and_memory_integrity_tools.py` は
allocated_bytes mismatch を violation として検出する。
