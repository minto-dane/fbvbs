# Service Lifecycle Audit

## 目的

service instance の起動、credential rotate、quiesce、resume、revoke を
append-only ledger で追跡し、service compromise containment の監査経路を持つ。

## 実装

`hypervisor/tools/service/record_service_lifecycle_audit.py` は
service identity attestation に束縛された lifecycle event を ledger に append する。

初版では次の event をサポートする。

1. `boot`
2. `rotate`
3. `quiesce`
4. `resume`
5. `revoke`

`hypervisor/tools/service/verify_service_lifecycle_audit.py` は
hash chain、sequence、service profile、session correlation を検証する。

runtime 側では `hypervisor/src/partition.c` が trusted service の
`measure / start / quiesce / resume / fault / recover / destroy` 遷移で
`fbvbs_audit_service_lifecycle_event` を emit する。

## fail-close rules

1. sequence は連番でなければならない
2. `previous_event_sha384` は直前 event hash と一致しなければならない
3. service profile / session が drift した ledger append は拒否する

## 検証

`hypervisor/tests/python/service/test_service_plane_security_tools.py` は
service lifecycle ledger を 2 event 以上 append し、verify が通ることを固定する。

`hypervisor/tests/c/storage/test_scaling_storage.c` は trusted service partition の
runtime 遷移が `FBVBS_EVENT_SERVICE_RESTART` payload として記録されることを固定する。
