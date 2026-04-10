# Stale Mapping Detector

## 目的

revoke / destroy 後に残る stale memory mapping を機械検出する。

## 実装

`hypervisor/tools/partition/detect_stale_mappings.py` は partition inventory と
memory mapping inventory を比較し、次を stale とみなす。

1. owner partition が存在しない
2. target partition が存在しない
3. owner / target が `DESTROYED`
4. `revoked=true` なのに `active=true`

## 検証

`hypervisor/tests/python/partition/test_boundary_and_capacity_tools.py` は destroyed target を指す
mapping を stale として検出する。
