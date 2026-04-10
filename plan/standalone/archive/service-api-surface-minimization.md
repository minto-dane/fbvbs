# Service API Surface Minimization

## 目的

service profile ごとの allowed call surface を固定し、意図しない API 拡大を fail-close に検出する。

## 実装

`hypervisor/tools/service/generate_service_api_surface_minimization.py` は
service profile ごとの `allowed_calls` baseline を JSON / Markdown で出力する。

`--observed` を渡した場合、service instance ごとの observed call set と比較し、
profile baseline に無い call を violation として列挙する。

## fail-close rules

1. profile baseline に無い management call は violation とする
2. service profile が不明な observed row は accepted surface に含めない
3. violation が 1 件でもあれば non-zero exit とする

## 検証

`hypervisor/tests/python/service/test_service_plane_security_tools.py` は
`diagnostics` profile が `FBVBS_CALL_STORAGE_CREATE_POOL` を観測した場合に
violation になることを固定する。
