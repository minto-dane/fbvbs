# Audit OOB Collection

This document defines how the standalone retained-C microhypervisor's primary audit sink must be collected for release use.

## Boundary

The retained-C runtime emits committed audit records to:

- a primary serial-port / UART sink intended for OOB collection on FreeBSD platforms (for example `/dev/ttyu0`, BMC serial redirection, or SOL capture)
- an in-memory mirror ring used for local correlation and post-incident inspection

The mirror ring is not the primary evidence source.

## Accepted collection paths

- physical UART capture
- BMC serial redirection
- IPMI Serial-over-LAN
- an equivalent dedicated serial concentrator outside the FreeBSD trust boundary

## Minimum operator procedure

1. Provision the collector before booting the release image.
2. Configure collector time synchronization explicitly:
   - NTP per RFC 5905 is the baseline requirement with authenticated `chrony`/`NTPsec` and measured offset `<= 100 ms`.
   - PTP / IEEE 1588 is required for sub-millisecond environments, with authenticated grandmaster configuration and measured offset `<= 1 ms`.
   - The collector must log the active sync source, protocol, measured offset/drift, and the timestamp of the last successful sync. If drift exceeds threshold, the audit collection run is failed. The allowed drift thresholds are: NTP drift > 500 ms or PTP drift > 100 ppm. If drift exceeds these limits, the audit collection run is marked as failed.
3. Establish continuous service monitoring:
   - health check or heartbeat for the collector daemon/service by exact service name
   - log and metric collection for collector restart count, ingest error rate, dropped bytes, framing errors, and clock drift
   - automatic restart and bounded retry policy in the service supervisor
4. Configure alerts:
   - critical alert on collector stop, heartbeat loss, or inability to write the primary audit stream
   - warning alert on sustained high error rate, timestamp skew above threshold, or repeated reconnects
   - notification path and escalation contacts must be recorded in the deployment runbook
5. Capture boot, runtime, and shutdown or fault output without truncation.
6. Preserve raw output, sync logs, monitoring alerts, and any decoding metadata with the release evidence bundle.
7. Define temporary spool/re-ingest handling:
   - if transport is interrupted, spool raw serial data locally on the collector
   - document the re-ingest procedure and retain chain-of-custody notes
8. Retain audit evidence for the deployment retention period required by policy; producer-facing release evidence must be retained for at least the full release-candidate review window plus incident-retention requirements.

## Serialized record format

The primary collector must validate the exact serialized line format:

```text
AUDIT seq=<u64> ts=<unix-ns> src=<u16> sev=<u16> event=<u16> len=<u16> payload=<hex>
```

- `seq`: monotonically increasing record sequence
- `ts`: the value of the hypervisor's TSC-normalized monotonic counter at
  log-append time, expressed in nanoseconds. This is **not** a POSIX
  timestamp; the counter resets to 0 on each hypervisor boot. External
  collectors must correlate with wall-clock time using the boot event record
- `src`: source component identifier
- `sev`: severity code
- `event`: event code
- `len`: decoded payload length in bytes
- `payload`: lowercase hex payload bytes with no separators

Examples:

```text
AUDIT seq=41 ts=1774747065123456789 src=1 sev=2 event=6 len=8 payload=0100000000000000
AUDIT seq=42 ts=1774747066123456789 src=1 sev=4 event=132 len=4 payload=02000000
```

## Verification steps

1. Trigger at least one known audit event in a test environment.
2. Confirm the primary collector records the serialized `AUDIT seq=...` line exactly as specified in [Serialized record format](#serialized-record-format).
3. Confirm the same record sequence appears in the mirror ring consumer path.
   - Tooling/interface: use the retained audit diagnostic path that backs `AUDIT_GET_MIRROR_INFO`, or the deployment-specific mirror-log API/CLI wrapper around that interface.
   - Example operator command: `fbvbs-auditctl mirror-dump --start-seq 41 --count 2`
   - Example API call: `GET /api/v1/mirror/consumers/default/records?start_seq=41&count=2`
   - Required authorization: read-only audit role with permission to access mirror-log metadata and record payloads
   - Expected output: monotonically increasing `seq` values whose `event`, `sev`, and `payload` fields match the primary serial collector
   - Troubleshooting: verify role assignment, confirm the ring size from `AUDIT_GET_MIRROR_INFO`, check for mirror consumer lag, and compare the collector framing settings against the primary serial capture
4. Document any transport framing or terminal settings used by the collector.

## Failure handling

If the primary collector is unavailable:

- do not claim FAU_STG.2-equivalent operational readiness
- keep the hypervisor deployment in non-release or lab status
- document the outage and the compensating controls, if any
- require encryption for audit data in transit and at rest:
  - TLS or equivalent authenticated transport for exported audit bundles
  - encrypted-at-rest storage for collector spools and retained archives
- restrict audit access to explicit roles only:
  - collector service account for ingestion
  - security operations / incident response read role
  - release authority role for evidence packaging
- preserve tamper evidence and immutability:
  - append-only or write-once storage where available
  - detached cryptographic signatures or hash-chained bundle manifests for exported archives
  - regular integrity verification of stored logs against the release manifest or collector-side digest set
- alert on unauthorized access or integrity anomalies:
  - failed access attempts
  - unexpected permission changes
  - hash/signature mismatch
  - unscheduled audit export or deletion attempts

## Current retained-C status

The repository implements the producer-side emission path.

Operational collection, retention, and tamper-evident storage remain deployment responsibilities and must be validated per target environment.
