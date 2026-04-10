# Attach/Detach Audit Consistency

## 目的

vdisk の現 attachment 状態と storage audit event の履歴が一致することを
fail-close に検証する。

## 実装

`hypervisor/tools/storage/verify_storage_attach_detach_audit.py` は
storage inventory と audit event mirror から次を検査する。

1. attached vdisk に成功 attach audit が存在する
2. attached partition id と attach audit の target が一致する
3. detached vdisk に未閉鎖 attach audit が残っていない
4. `latest_successful_event` を vdisk ごとに出力する

## fail-close rules

1. attach audit が無い attached vdisk は violation
2. detached なのに last successful op が attach のままなら violation
3. audit target partition が inventory とずれたら violation

## 検証

`hypervisor/tests/python/storage/test_storage_governance_tools.py` は
detach audit を欠いた vdisk を violation として検出する。
