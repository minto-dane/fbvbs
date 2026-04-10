# Service Identity Attestation

## 目的

service profile、service kind、capability mask、signer identity を
runtime から切り離した artifact として固定し、service plane の identity drift を検出する。

## 実装

`hypervisor/tools/security/issue_service_identity_attestation.py` は次を含む
service identity attestation artifact を生成する。

1. `service_profile`
2. `service_kind`
3. `service_instance_id`
4. `session_correlation_id`
5. `partition_id`
6. required capability mask
7. `access_policy_sha384`
8. `peer_policy_sha384`
9. `service_identity.image_digest_sha384`
10. `service_identity.signer_identity`

`hypervisor/tools/security/verify_service_identity_attestation.py` は
現在の service policy baseline と照合して hash / profile / session を検証する。

## fail-close rules

1. profile baseline と capability mask がずれた attestation は拒否する
2. `access_policy_sha384` と `peer_policy_sha384` が一致しない attestation は拒否する
3. `service_kind` が profile の allowlist に無ければ拒否する

## 検証

`hypervisor/tests/python/service/test_service_plane_security_tools.py` は
`attestation` profile の artifact を発行・検証できることを固定する。
