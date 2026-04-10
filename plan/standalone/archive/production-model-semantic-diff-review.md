# Production / Model Semantic Diff Review

## 目的

proof model と production 実装の乖離を、人手メモではなく CI で継続監視する。

## 実装

1. `hypervisor/tools/verification/generate_framac_divergence_report.py` が `__FRAMAC__` 分岐 inventory を生成する
2. `make -C hypervisor semantic-drift-check` が forbidden divergence を strict mode で fail する
3. `.github/workflows/ci.yml` が divergence report を artifact として保存する
4. `hypervisor/compliance/wp_verification_boundary.md` はこの report を verification boundary の補助証跡として参照する

## fail-close rules

1. forbidden divergence が 1 件でもあれば `semantic-drift-check` は失敗する
2. report は repo 内 source / header 全体を走査し、部分走査にしない
3. release 判断では checked-in report と current run の両方を参照する

## 検証

`hypervisor/tests/python/verification/test_framac_divergence_report_tool.py` と
`make -C hypervisor semantic-drift-check` を通して確認する。
