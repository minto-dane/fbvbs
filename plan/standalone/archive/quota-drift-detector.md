# Quota Drift Detector

## 目的

desired scaling quota と observed usage の乖離を機械検出する。

## 実装

`hypervisor/tools/partition/detect_quota_drift.py` は次の metric を比較する。

1. `runtime_max_vm_count` vs `current_vm_count`
2. `runtime_max_vcpus_per_vm` vs `max_vcpus_per_vm_observed`
3. `runtime_max_vdisks_per_vm` vs `max_vdisks_per_vm_observed`
4. `runtime_max_vdisk_size_bytes` vs `max_vdisk_size_observed_bytes`

limit 超過があれば non-zero exit する。

## 検証

`hypervisor/tests/python/partition/test_boundary_and_capacity_tools.py` は
VM count と vdisk-per-VM の drift を検出する。
