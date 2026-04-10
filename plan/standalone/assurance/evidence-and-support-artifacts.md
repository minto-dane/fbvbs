# Standalone Evidence And Support Artifacts

- Status: Active
- Authority level: validation / assurance doc
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 13-15, 42-45
- Depends on: `plan/standalone/operations/incident-audit-and-recovery.md`, `plan/standalone/assurance/compatibility-and-versioning.md`
- Supersedes: `plan/standalone/archive/standalone-evidence-pack-format.md`, `plan/standalone/archive/support-dump-scrubbing-policy.md`
- Intended audience: release 担当、incident responder、support / forensic 担当

## Scope

本書は、standalone runtime の release / incident artifact をどの形で束ね、署名し、保持するかを定義する。

## Required Artifact Set

1. diagnostic bundle
2. sealed incident timeline
3. operator console severity summary
4. operator acknowledgment ledger when incident-driven
5. compatibility matrix or equivalent baseline snapshot
6. state manifest

optional:

1. recovery approval
2. origin attestation
3. break-glass ledger
4. panel manifest
5. scrubbed support dump and scrub report

## Evidence Pack Rules

1. evidence pack manifest は canonical digest を保持する
2. timeline root と acknowledgment / break-glass ledger の root は一致しなければならない
3. allowed root 外や symlink-backed input は拒否する
4. forensic preservation mode は `capture_complete=true` と detached signature を必須にする

## Support Dump Scrubbing

support dump はそのまま evidence pack に入れてはならない。最低限、以下を redaction 対象にする。

1. bearer token
2. API key
3. password assignment
4. cloud secret
5. private key block

scrubbing は report を伴い、support dump を pack に含める場合は report を必須とする。

## Retention And Remote Export

1. retention integrity checker で manifest digest を再計算できること
2. remote export retry schedule は fail-closed manifest として保持すること
3. signed / unsigned、capture complete / partial capture を明示すること

## Relationship To Incident Workflow

incident handling の主手順は `../operations/incident-audit-and-recovery.md` を正とする。本書は、その結果生成される artifact pack の format と preservation policy を定義する。
