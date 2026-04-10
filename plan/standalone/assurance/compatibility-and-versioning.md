# Standalone Compatibility And Versioning

- Status: Active
- Authority level: validation / assurance doc
- Source-of-truth: `plan/full-stack/fbvbs-design.md` sections 2.2, 20, 42-45, Appendix L
- Depends on: `plan/standalone/assurance/management-diagnostics-abi.md`
- Supersedes: `plan/standalone/archive/diagnostic-abi-compatibility-baseline.md`, `plan/standalone/archive/downgrade-compatibility-policy.md`, `plan/standalone/archive/migration-compatibility-checker.md`, `plan/standalone/archive/operator-tooling-compatibility-matrix.md`, `plan/standalone/archive/deprecated-field-policy.md`, `plan/standalone/archive/reserved-field-enforcement.md`
- Intended audience: ABI 実装者、tooling 実装者、CI / release 担当

## Scope

本書は、standalone 管理 ABI と関連 state artifact の互換性規律を定義する。要求仕様そのものではなく、**どう壊さないか** と **どう検出するか** を定義する assurance 文書である。

## Authoritative Compatibility Sources

1. `management-diagnostics-abi.md`
2. `baselines/operator-tooling-compatibility-baseline.json`
3. `hypervisor/include/fbvbs_abi.h`

compatibility matrix や baseline は、上記 source-of-truth から再生成される派生成果物として扱う。

## Versioning Rules

1. major ABI 期間中は append-only field layout を維持する
2. reserved field は versioned promotion まで `0` のままにする
3. deprecated field は minor release で削除・再利用しない
4. unsupported version / unsupported profile は structured response で返し、silent fallback しない

## Compatibility Windows

target は少なくとも次の window を持たなければならない。

1. management ABI version
2. health / guidance / inventory / fault record schema version
3. evidence / state manifest format version
4. locale / presentation support window when operator artifacts are exchanged

window が欠落している構成は fail-closed で incompatible とする。

## Preflight Policies

### Downgrade

1. source version が target accepted window 内にあること
2. source locale が target supported locale に含まれること
3. version window 不在は即 fail

### Migration Preflight

1. timeline root の存在
2. sequence gap が target budget を超えないこと
3. panel style / required matrix / version window の整合

## CI And Tooling Gates

1. compatibility matrix regeneration
2. baseline diff
3. reserved-field enforcement report
4. incompatible change detector
5. downgrade / migration preflight regression

## Machine-Readable Baselines

checked-in baseline は `baselines/operator-tooling-compatibility-baseline.json` を正とする。生成物がこの baseline と一致しない場合、変更は互換性レビュー対象である。
