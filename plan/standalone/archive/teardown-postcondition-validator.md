# Teardown Postcondition Validator

## 目的

partition teardown 後に object / mapping / attachment の残骸が残らないことを
fail-close に確認する。

## 実装

`hypervisor/tools/partition/validate_teardown_postconditions.py` は指定 partition に対して、
少なくとも次の残存を検出する。

1. owned memory objects
2. owned shared objects
3. inbound / outbound memory mappings
4. attached virtual disks

違反が 1 件でもあれば non-zero exit する。

## 検証

`hypervisor/tests/python/partition/test_boundary_and_capacity_tools.py` は teardown 後に memory object が
残るケースを reject する。
