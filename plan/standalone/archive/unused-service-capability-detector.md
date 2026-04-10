# Unused Service Capability Detector

## 目的

service partition に過剰 capability が残っていないかを fail-close で検出する。

## 実装

`hypervisor/tools/service/detect_unused_service_capabilities.py` は service assignment JSON と
service privilege review baseline を比較し、各 service に対して次を計算する。

1. `assigned_capability_mask`
2. `required_capability_mask`
3. `unused_capability_mask`
4. `missing_capability_mask`
5. `compliant`

unused または missing capability がある場合、tool は non-zero exit する。

## fail-close rules

1. unknown `service_kind` は拒否する
2. `services` 配列以外の入力 shape は拒否する
3. unused capability が 1bit でもあれば noncompliant とする
4. required capability が欠けても noncompliant とする

## 検証

`hypervisor/tests/python/service/test_service_privilege_review_tools.py` は次を固定する。

1. `SERVICE_KIND_OCS` に `FBVBS_CAP_STORAGE_MANAGE` を余分に与えると検出される
2. report に unused capability 名が機械可読で出る
