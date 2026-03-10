# FBVBS executable specification toolkit

This repository now turns `plan/fbvbs-design.md` into machine-readable, validated artifacts instead of leaving the design as prose only.

## What is implemented

- a standard-library-only parser for the frozen FBVBS v7.0 contracts
- validation for requirements metadata, verification-class normalization, partition lifecycle rules, ABI catalogs, and fixed layouts
- artifact generation for JSON, CSV, Graphviz DOT, and generated C/Rust bindings
- automated tests that exercise the parser and generator directly against the design document

## Repository layout

- `plan/fbvbs-design.md`: normative source document
- `fbvbs_spec/`: parser, validator, generator, and CLI
- `generated/`: checked-in derived artifacts produced from the design document
- `hypervisor/`: Ada/SPARK-first hypervisor implementation and assurance workspace; any remaining C is migration-only and non-authoritative
- `tests/`: regression coverage for the executable-spec pipeline

## Usage

Generate artifacts:

```bash
python3 -m fbvbs_spec generate --source plan/fbvbs-design.md --output generated
```

Validate the design document without writing files:

```bash
python3 -m fbvbs_spec validate --source plan/fbvbs-design.md
```

Show a quick summary:

```bash
python3 -m fbvbs_spec summary --source plan/fbvbs-design.md
```

Run spec-tool tests:

```bash
python3 -m unittest discover -s tests -v
```

Run the retained-C warning and compiler static-analysis gate:

```bash
make -C hypervisor analyze
```

Run the retained-C bounded proof artifact:

```bash
make -C hypervisor proof
```

Build and run the Ada/SPARK hypervisor executable checks:

```bash
gprbuild -P hypervisor/ada/fbvbs_hypervisor.gpr
(
  cd hypervisor/ada
  ./fbvbs_hypervisor_main
)
(
  cd hypervisor/ada
  alr build
  ./fbvbs_hypervisor_main
)
```

The Ada/SPARK implementation path is the primary acceptance target. Python in this repository is used for spec parsing/generation/validation tooling; it is not the hypervisor runtime itself. Any remaining C is temporary migration code outside the authoritative implementation path unless and until it satisfies the spec's explicit exception rules for MISRA C compliance, static analysis, and formal verification. The default repository-enforced C baseline is now the leaf-only `vmx.c` boundary plus its dedicated `include/fbvbs_leaf_vmx.h` interface, checked with warnings-as-errors, a compiler `-fanalyzer` pass via `make -C hypervisor analyze`, a retained-C subset gate, and a bounded proof artifact via `make -C hypervisor proof`, while VM exit state transitions, ABI exit-code/length shaping, a selected hypercall-dispatch path, Ada-side memory/W^X plus unmap/shared-registration policy, selected KCI control calls (`KCI_VERIFY_MODULE`, `KCI_SET_WX`, `KCI_PIN_CR`, `KCI_INTERCEPT_MSR`), selected KSI/IKS/SKS crypto-service dispatch, partition create/destroy/status/quiesce/resume/fault-info control, audit mirror-info queries, `VM_GET_VCPU_STATUS`, `VM_SET_REGISTER`, `VM_GET_REGISTER`, KSI Tier B shadow-update sequencing, and selected diagnostic query modeling are now implemented authoritatively in Ada/SPARK.

## Notes

The design document remains the source of truth. Generated artifacts are reproducible, and repository changes should converge on an Ada/SPARK-first implementation; any remaining C during migration should be treated as temporary, explicitly bounded, non-authoritative, and subject to MISRA/static-analysis/formal-verification requirements before it can re-enter the trusted path.
