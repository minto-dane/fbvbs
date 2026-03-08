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

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

## Notes

The design document remains the source of truth. Generated artifacts are reproducible and are intended to unblock future Ada/SPARK, Rust, assembly, and FreeBSD integration work with precise contracts instead of manual transcription.
