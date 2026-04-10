# Standalone Evidence Pack Format

## 目的

standalone incident と release 証跡を、operator が一式として保管・移送・検証できる
evidence pack 形式を定義する。

## 実装

`hypervisor/tools/diagnostics/generate_standalone_evidence_pack.py` は次の入力を束ねる。

1. diagnostic bundle
2. sealed incident timeline
3. operator console severity summary
4. operator acknowledgment ledger
5. command origin attestation
6. dedicated break-glass ledger
7. operator tooling compatibility matrix
8. OCS panel manifest
9. 追加 evidence artifact

同時に `hypervisor/tools/diagnostics/correlate_standalone_incident_artifacts.py` が
cross-artifact correlation summary を生成する。

`hypervisor/tools/audit/check_retention_integrity.py` は diagnostic bundle / evidence pack の
manifest artifact digest を再計算して retention integrity を検証する。

`hypervisor/tools/diagnostics/plan_remote_export_retry.py` は archive ごとの fail-closed retry schedule を
machine-readable manifest として生成する。

## 出力

evidence pack tarball は少なくとも次を含む。

1. `evidence/standalone-evidence-pack-manifest.json`
2. `evidence/standalone-evidence-correlation.json`
3. `evidence/standalone-state-manifest.json`
4. `docs/standalone-evidence-correlation.md`
5. `evidence/diagnostic-bundle.tar.gz`
6. `evidence/timeline-sealed.json`
7. `evidence/operator-console-severity-summary.json`

optional:

1. `evidence/operator-ack-ledger.json`
2. `evidence/recovery-approval.json`
3. `evidence/origin-attestation.json`
4. `evidence/break-glass-ledger.json`
5. `evidence/operator-tooling-compatibility-matrix.json`
6. `ui/ocs-panel-manifest.json`
7. `evidence/evidence-pack-signer.pem`
8. `evidence/standalone-evidence-pack-manifest.sig`

## fail-close consistency rules

1. diagnostic bundle は `fbvbs-standalone-diagnostic` でなければならない
2. timeline は `root_chain_sha384` を持たなければならない
3. acknowledgment ledger がある場合、`timeline_root_chain_sha384` は timeline root と一致しなければならない
4. break-glass ledger がある場合、`timeline_root_chain_sha384` は timeline root と一致しなければならない
5. break-glass origin attestation がある場合、separate break-glass ledger を推奨 warning として上げる
6. symlink-backed input は拒否する
7. allowed root 外の input は拒否する
8. forensic preservation mode は `capture_complete=true` と署名を必須とする

## 署名

`--signing-key` を指定した場合、evidence pack manifest を detached signature で署名する。

manifest には少なくとも次を固定する。

1. `signature_algorithm`
2. `public_key_fingerprint_sha384`
3. `verification_hint`
4. `certificate_fingerprint_sha384`
5. `certificate_subject`

forensic preservation mode を有効にした場合、archive には
`evidence/forensic-preservation.json` を追加し、append-only retention lock を要求する。

## correlation summary

correlation summary は次を集約する。

1. diagnostic bundle の signed / capture_complete / artifact count
2. timeline の record count / boot session count / gap count
3. severity summary の overall severity / partition count / top partitions
4. acknowledgment count / timeline root match / session correlation ID
5. origin attestation call / role / break-glass flag
6. break-glass ledger event count / audit channel / session correlation ID
7. compatibility matrix row count
8. panel manifest style / locale
9. warnings
10. audit schema version consistency
11. state format version registry

## 検証

`hypervisor/tests/python/diagnostics/test_standalone_evidence_pack_tools.py` は次を固定する。

1. correlation JSON / Markdown が生成される
2. signed evidence pack manifest が生成できる
3. detached signature を OpenSSL で検証できる
4. correlation summary が ack / timeline / severity / diagnostic bundle を横断集約する
5. retention integrity checker が archive manifest digest を再検証できる
6. evidence pack manifest から operator session を追跡できる
7. origin attestation / break-glass ledger の存在が state manifest と correlation summary に反映される
