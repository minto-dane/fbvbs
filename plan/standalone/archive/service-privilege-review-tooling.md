# Service Privilege Review Tooling

## 目的

service kind ごとの最小 capability baseline を固定し、service plane の権限 drift を
レビュー可能にする。

## 実装

`hypervisor/tools/service/generate_service_privilege_review.py` は
`fbvbs_abi.h` の `SERVICE_KIND_*` と `FBVBS_CAP_*` から、
service kind ごとの role 名と minimal capability mask を JSON / Markdown で生成する。

初版では少なくとも次を固定する。

1. `SERVICE_KIND_KCI`
2. `SERVICE_KIND_KSI`
3. `SERVICE_KIND_IKS`
4. `SERVICE_KIND_SKS`
5. `SERVICE_KIND_UVS`
6. `SERVICE_KIND_OCS`

## fail-close rules

1. service kind は checked-in baseline に無い値を許さない
2. minimal capability mask は dedicated service access capability のみを既定とする
3. review 出力は service kind / role / required capability の対応を機械可読で固定する

## 検証

`hypervisor/tests/python/service/test_service_privilege_review_tools.py` は次を固定する。

1. `SERVICE_KIND_OCS` の baseline が `FBVBS_CAP_OCS_ACCESS` を要求する
2. review Markdown / JSON が生成される
