# Storage Evidence Trail

## 目的

pool / vdisk ごとの storage 変更履歴を inventory、audit consistency、
destructive confirmation から再構成し、incident 対応に使える証跡にする。

## 実装

`hypervisor/tools/storage/generate_storage_evidence_trail.py` は次を入力に取る。

1. storage inventory
2. attach/detach audit consistency report
3. optional destructive storage confirmation artifact

出力は少なくとも次を含む。

1. `pool_trails`
2. `vdisk_trails`
3. `latest_successful_event`
4. `destructive_confirmation_sha384`
5. warnings

## fail-close rules

1. `RELEASE_PENDING` 相当なのに destructive confirmation が無ければ warning を上げる
2. evidence trail は inventory と audit report の digest を保持する
3. incomplete trail は non-zero exit で示す

## 検証

`hypervisor/tests/python/storage/test_storage_governance_tools.py` は
confirmation 付き vdisk trail を生成し、warning が反映されることを固定する。
