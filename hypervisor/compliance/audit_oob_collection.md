# Audit OOB Collection

This document defines how the standalone retained-C microhypervisor's primary audit sink must be collected for release use.

## Boundary

The retained-C runtime emits committed audit records to:

- a primary COM1/UART-oriented sink intended for OOB collection
- an in-memory mirror ring used for local correlation and post-incident inspection

The mirror ring is not the primary evidence source.

## Accepted collection paths

- physical UART capture
- BMC serial redirection
- IPMI Serial-over-LAN
- an equivalent dedicated serial concentrator outside the FreeBSD trust boundary

## Minimum operator procedure

1. Provision the collector before booting the release image.
2. Confirm collector timestamps are synchronized to the deployment time source.
3. Capture boot, runtime, and shutdown or fault output without truncation.
4. Preserve raw output and any decoding metadata with the release evidence bundle.

## Verification steps

1. Trigger at least one known audit event in a test environment.
2. Confirm the primary collector records the serialized `AUDIT seq=...` line.
3. Confirm the same record sequence appears in the mirror ring consumer path.
4. Document any transport framing or terminal settings used by the collector.

## Failure handling

If the primary collector is unavailable:

- do not claim FAU_STG.2-equivalent operational readiness
- keep the hypervisor deployment in non-release or lab status
- document the outage and the compensating controls, if any

## Current retained-C status

The repository implements the producer-side emission path.

Operational collection, retention, and tamper-evident storage remain deployment responsibilities and must be validated per target environment.
