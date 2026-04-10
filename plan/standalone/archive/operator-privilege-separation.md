# Operator Privilege Separation

## 目的

standalone 管理 command を capability 単独ではなく、operator role / domain /
action / context で fail-close に仕分ける。

## 実装

`hypervisor/tools/partition/standalone_command_contracts.py` を正本として、各 command に
次を固定する。

1. `authorization.domain`
2. `authorization.action`
3. `authorization.allowed_roles`
4. `authorization.requires_origin_attestation`
5. `authorization.break_glass_eligible`
6. `authorization.separate_break_glass_audit`

`hypervisor/tools/operator/generate_standalone_operator_privilege_model.py` はこの正本から
JSON / Markdown を生成する。

role catalog は少なくとも次を持つ。

1. `observer`
2. `incident-responder`
3. `capacity-admin`
4. `storage-admin`
5. `ocs-operator`

## fail-close rules

1. role 未登録は拒否する
2. role が `allowed_roles` に無ければ拒否する
3. origin attestation 必須 command は attestation なしで実行しない
4. break-glass 可能 command でも、通常経路とは別監査を必須にする

## 検証

`hypervisor/tests/python/operator/test_operator_privilege_model_tool.py` は次を固定する。

1. role catalog が生成される
2. `PARTITION_RECOVER` は `incident-responder` のみ
3. `DIAG_SET_SCALING_LIMITS` は `capacity-admin` のみ
4. break-glass separate-audit 属性が recover 系に付く
