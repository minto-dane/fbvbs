# Command Origin Attestation

## 目的

standalone 管理 command の origin を session / role / transport / host callsite に
束縛し、spoof と replay の運用面を縮小する。

## 実装

`hypervisor/tools/security/issue_command_origin_attestation.py` は次を含む
origin attestation artifact を生成する。

1. `operator_id`
2. `operator_role`
3. `session_correlation_id`
4. `call`
5. `authorization`
6. `origin.transport`
7. `origin.console`
8. `origin.host_callsite`
9. `command_context.break_glass`
10. `command_context.timeline_root_chain_sha384`

artifact は `origin_attestation_sha384` を持ち、`hypervisor/tools/security/verify_command_origin_attestation.py`
で再検証できる。

host callsite は次の allowlist に限定する。

1. `FBVBS_HOST_CALLSITE_FBVBS_PRIMARY`
2. `FBVBS_HOST_CALLSITE_FBVBS_SECONDARY`
3. `FBVBS_HOST_CALLSITE_VMM_PRIMARY`
4. `FBVBS_HOST_CALLSITE_VMM_SECONDARY`

## fail-close rules

1. role と call の組み合わせが privilege model に無ければ拒否する
2. host callsite が allowlist 外なら拒否する
3. transport / console 組が不整合なら拒否する
4. `session_correlation_id` が無ければ拒否する
5. break-glass の場合は justification を必須にする
6. expiration を過ぎた artifact は既定で拒否する

## 検証

`hypervisor/tests/python/security/test_command_origin_attestation_tools.py` は次を固定する。

1. `PARTITION_RECOVER` の break-glass attestation を発行・検証できる
2. `observer` が recover attestation を発行しようとすると拒否される
