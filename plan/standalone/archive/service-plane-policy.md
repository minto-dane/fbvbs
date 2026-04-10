# Service Plane Policy

## 目的

service partition を万能権限主体にせず、責務ごとに分離した profile と
object access policy を機械可読で固定する。

## 実装

`hypervisor/tools/service/generate_service_plane_policy.py` は
`hypervisor/tools/service/standalone_service_plane.py` を正本に、少なくとも次を出力する。

1. `storage-control`
2. `audit-collection`
3. `attestation`
4. `secret-key`
5. `diagnostics`
6. `operator-console`

各 profile は次を持つ。

1. 許可される `service_kind` 候補
2. required capability baseline
3. per-service object access policy
4. service-to-service allowlist
5. `default_break_glass_bypass_allowed = false`
6. compromise containment rule

## fail-close rules

1. profile に無い object access は deny-by-default
2. break-glass bypass は profile 単位で既定拒否にする
3. peer policy hash が一致しない service identity は trusted peer にしない

## 検証

`hypervisor/tests/python/service/test_service_plane_security_tools.py` は次を固定する。

1. `storage-control` profile が break-glass bypass default deny を持つ
2. `diagnostics` profile が `audit-collection` との peer policy を持つ
3. `attestation` profile が `SERVICE_KIND_UVS` を要求する
