# Fault Escalation Matrix

## 目的

fault から containment policy までの operator 判断を固定化する。

## 実装

`hypervisor/tools/partition/generate_fault_escalation_matrix.py` は
health state / fault severity ごとの escalation level、containment policy、
operator action を JSON / Markdown で生成する。

matrix は `safe-stop`、`quarantine`、`recovering` を含み、
safe stop / degraded / quarantine の policy 固定点も兼ねる。

## 検証

`hypervisor/tests/python/partition/test_boundary_and_capacity_tools.py` は
`quarantine` containment policy が matrix に含まれることを固定する。
