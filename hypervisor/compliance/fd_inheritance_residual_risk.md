# FBVBS Residual Risk: File Descriptor Inheritance (REQ-0505)

**Document:** RR-005
**Date:** 2026-03-23
**Scope:** File descriptor inheritance across setuid/setgid exec transitions
**Applicable:** Phase 9-4 audit preparation, Risk Register R-5
**Related Requirements:** REQ-0503, REQ-0504, REQ-0505, REQ-0507

---

## 1. Requirement

**REQ-0505:** File descriptor inheritance risk must be documented as residual
risk within the FBVBS threat model.

This requirement was identified during deep audit of the KSI (Kernel State
Integrity) subsystem design. While KSI monitors kernel object integrity and
setuid/setgid exec transitions, the UNIX file descriptor inheritance model
introduces an attack surface that falls outside the KSI protection boundary.
This document records the risk, its analysis, existing mitigations, and the
rationale for residual risk acceptance.

---

## 2. Background: UNIX File Descriptor Inheritance

### 2.1 The Inheritance Model

In UNIX-derived operating systems including FreeBSD, file descriptors (fds)
are per-process integer handles referencing open files, sockets, pipes,
device nodes, and other kernel objects. The fundamental property is:

- **fork(2):** Child processes inherit all open file descriptors from the
  parent. Both parent and child share the same underlying file description
  (struct file in the kernel).
- **exec(2):** File descriptors survive the exec transition by default.
  Only descriptors marked with the close-on-exec flag (FD_CLOEXEC) are
  closed during exec.

### 2.2 The Security Implication

When a process calls execve(2) on a setuid or setgid binary, the kernel
elevates the effective UID/GID of the new process image. However, the file
descriptor table is inherited from the caller. This creates a privilege
boundary crossing:

1. The unprivileged caller opens file descriptors to arbitrary resources.
2. The caller execs a setuid binary.
3. The setuid binary now runs with elevated privileges AND has access to
   the caller's pre-opened file descriptors.
4. If the setuid binary reads from or writes to inherited descriptors
   without validation, it may operate on attacker-controlled I/O channels.

This is a well-known UNIX security concern documented in CERT C STD
FIO42-C and POSIX security guidelines.

---

## 3. FBVBS KSI Protection Scope

### 3.1 What KSI Monitors

The KSI subsystem provides hypervisor-enforced kernel object integrity for
FreeBSD. Its protection scope includes:

| Capability | Requirement | Mechanism |
|-----------|-------------|-----------|
| Setuid/setgid exec verification | REQ-0503 | `fbvbs_ksi_validate_setuid()` validates exec transitions against a registered setuid database |
| Filesystem identity verification | REQ-0504 | fsid + fileid pair uniquely identifies the binary being executed, preventing path-based substitution |
| Setuid database reconciliation | REQ-0507 | Registered setuid binaries are reconciled against a hypervisor-held database of authorized programs |
| Kernel object shadow copies | REQ-0501 | Tier A/B kernel objects are protected via shadow copy with write-enable windows |
| Reference pointer registration | REQ-0502 | Kernel reference pointers are constrained to a registered legitimate object set |

### 3.2 What KSI Does NOT Monitor

The KSI subsystem does **not** monitor the contents of the per-process file
descriptor table (`struct filedesc` in FreeBSD). Specifically:

- KSI does not track which file descriptors a process has open.
- KSI does not intercept open(2), dup(2), socket(2), or other fd-creating
  system calls.
- KSI does not enforce close-on-exec policy on inherited descriptors.
- KSI cannot prevent pre-opened file descriptors from surviving across an
  exec transition that it validates via `fbvbs_ksi_validate_setuid()`.

The file descriptor table is classified as **Tier C** (high-frequency
mutable state) in the KSI protection model. Tier C objects are outside the
KSI protection boundary because the performance cost of hypervisor-level
interception on every fd operation would be prohibitive (see Section 6.2).

### 3.3 Protection Boundary Diagram

```
+------------------------------------------------------------------+
|                    FBVBS Hypervisor (VMX root)                    |
|                                                                   |
|  KSI Protected (Tier A/B)        KSI Unprotected (Tier C)        |
|  +-------------------------+     +---------------------------+    |
|  | Kernel text (W^X)       |     | struct filedesc (fd table)|    |
|  | Credential structures   |     | Socket buffers (mbuf)     |    |
|  | Setuid database         |     | Routing tables            |    |
|  | Module integrity        |     | Scheduler run queues      |    |
|  | vnode identity (fsid)   |     | VM page mappings          |    |
|  +-------------------------+     +---------------------------+    |
|                                                                   |
|  KSI validates exec transitions (REQ-0503/0504/0507)             |
|  but does NOT inspect or constrain fd table contents              |
+------------------------------------------------------------------+
```

---

## 4. Risk Analysis

### 4.1 Attack Scenario

The canonical fd inheritance attack proceeds as follows:

1. **Setup:** An unprivileged attacker process opens a sensitive resource
   (e.g., a raw socket, a device node via an exploited driver, or a
   file in a privileged directory via a race condition).

2. **Exec:** The attacker calls execve(2) on a setuid-root binary. KSI
   validates the exec transition (REQ-0503): the binary's fsid+fileid
   match the registered setuid database, and the measured hash is
   verified. KSI approves the transition.

3. **Inheritance:** The setuid binary begins execution with elevated
   privileges. The attacker's pre-opened file descriptors are present
   in the new process's fd table.

4. **Exploitation:** If the setuid binary performs I/O on inherited
   descriptors (e.g., it assumes fd 0/1/2 are the terminal, or it
   reads from an fd number passed via environment/arguments), the
   attacker controls the data source or sink.

### 4.2 Impact Assessment

| Factor | Assessment |
|--------|-----------|
| **Confidentiality** | Medium -- setuid binary may write privileged data to an attacker-controlled descriptor |
| **Integrity** | Medium -- setuid binary may read attacker-controlled input from an inherited descriptor |
| **Availability** | Low -- fd inheritance does not directly enable denial of service |
| **Scope** | Bounded by the setuid binary's own privilege level and the resources accessible via the inherited fd |

### 4.3 Likelihood Assessment

| Factor | Assessment |
|--------|-----------|
| **Attacker capability** | Low -- requires specific knowledge of the target setuid binary's fd usage patterns |
| **Preconditions** | The target setuid binary must use inherited fds without validation; modern setuid binaries typically call closefrom(3) or equivalent |
| **KSI barrier** | Only KSI-approved setuid binaries can be executed; this constrains the attack surface to registered programs |
| **Historical precedent** | fd inheritance vulnerabilities are well-documented (CVE-2003-0466, CVE-2011-0997, CVE-2014-3566 relay variants) but uncommon in modern, audited setuid programs |

### 4.4 Risk Rating

| Dimension | Rating |
|-----------|--------|
| Likelihood | **Low** |
| Severity | **Medium** |
| Overall Risk | **Low-Medium** |

---

## 5. Existing Mitigations

### 5.1 FreeBSD Kernel Mitigations

| Mitigation | Mechanism | Coverage |
|-----------|-----------|----------|
| **O_CLOEXEC / FD_CLOEXEC** | File descriptors opened with O_CLOEXEC are automatically closed on exec(2). fcntl(F_SETFD, FD_CLOEXEC) sets the flag post-open. | Protects fds that are explicitly marked; does not protect legacy fds opened without the flag |
| **closefrom(2)** | FreeBSD system call that closes all file descriptors >= a given number in a single atomic operation. | Highly effective when called by setuid binaries at startup (e.g., `closefrom(STDERR_FILENO + 1)`) |
| **Capsicum capability mode** | cap_enter(2) restricts the process to capability mode: no new global namespaces (open, connect, etc.), and fd operations are constrained by capability rights. | Comprehensive protection for programs that enter capability mode after opening required resources |
| **fdescfs restrictions** | FreeBSD does not mount fdescfs by default, preventing /dev/fd/ based descriptor leakage. | Defense-in-depth; irrelevant if direct inheritance is the vector |

### 5.2 FBVBS Hypervisor Mitigations

| Mitigation | Mechanism | Coverage |
|-----------|-----------|----------|
| **KSI setuid verification (REQ-0503)** | `fbvbs_ksi_validate_setuid()` verifies that the target binary is in the authorized setuid database before permitting the exec transition. | Constrains attack surface to known, audited setuid binaries |
| **KSI fsid+fileid identity (REQ-0504)** | Binary identity is verified by filesystem ID and inode number, preventing symlink or path traversal substitution. | Prevents attacker from substituting a vulnerable setuid binary |
| **KSI measured hash verification** | The binary's measured hash (64-byte, SHA-512) is compared against the registered hash in the setuid database. | Prevents tampered setuid binaries |
| **Tier A kernel text W^X** | Kernel text is write-protected via EPT/NPT. A setuid binary cannot be modified in memory after loading. | Prevents runtime modification of setuid binary behavior |

### 5.3 Application-Level Mitigations

Well-written setuid programs implement defense-in-depth against fd
inheritance:

1. **Close inherited fds:** Call `closefrom(STDERR_FILENO + 1)` immediately
   at startup, before processing any input.
2. **Validate standard fds:** Verify that fds 0, 1, 2 are open and point to
   expected device types (terminal, pipe, etc.).
3. **Use O_CLOEXEC:** Open all new file descriptors with O_CLOEXEC to prevent
   further inheritance if the program itself forks/execs.
4. **Capsicum sandboxing:** Enter capability mode after opening required
   resources, preventing new namespace operations.
5. **Privilege separation:** Drop privileges (setuid back to real UID) as
   early as possible, limiting the window for fd-based exploitation.

---

## 6. Residual Risk Acceptance

### 6.1 Fundamental Design Property

File descriptor inheritance across exec(2) is a fundamental UNIX design
property dating to Version 7 UNIX (1979). It enables essential
functionality:

- Shell I/O redirection (pipes, redirects)
- Daemon socket passing (inetd, systemd socket activation)
- Privilege separation (pre-open resources, then drop privileges)

Eliminating fd inheritance would break the UNIX process model and is not
a viable mitigation strategy.

### 6.2 Hypervisor-Level Intervention Is Infeasible

Intercepting fd operations at the hypervisor level would require:

1. **Trapping every open/dup/socket/accept/pipe/socketpair call:** These
   are among the highest-frequency system calls in any UNIX workload.
   VM exit on every fd operation would impose unacceptable performance
   overhead (estimated 10-100x slowdown for I/O-intensive workloads),
   violating the FBVBS performance budget (Appendix J).

2. **Maintaining a shadow fd table:** The hypervisor would need to track
   every process's fd table, duplicating kernel bookkeeping. This
   increases TCB complexity and introduces its own correctness risks.

3. **Policy decision complexity:** Determining which inherited fds are
   "safe" requires semantic understanding of the target binary's
   intended fd usage -- knowledge that the hypervisor does not and
   should not possess.

For these reasons, fd-level intervention is outside the FBVBS protection
model. The appropriate defense layer is the OS (FreeBSD) and the setuid
binary itself.

### 6.3 OS-Level Mitigations Are Sufficient

FreeBSD provides robust mechanisms for mitigating fd inheritance risk:

- **closefrom(2)** is a single system call that atomically closes all
  unnecessary descriptors.
- **Capsicum** provides capability-based security that fundamentally
  constrains fd operations after cap_enter(2).
- **O_CLOEXEC** is supported on all fd-creating system calls in modern
  FreeBSD (13.x+).

These mechanisms operate at the correct abstraction layer (the OS kernel)
with negligible performance impact.

### 6.4 Acceptance Statement

The file descriptor inheritance risk (REQ-0505, Risk Register R-5) is
**accepted as residual risk** with the following conditions:

1. This document serves as the formal residual risk record.
2. The setuid binary audit checklist (Section 7) is applied to all
   binaries registered in the KSI setuid database.
3. FreeBSD deployment configurations enable Capsicum where applicable.
4. The risk is re-evaluated if FBVBS is ported to a non-UNIX host OS
   where equivalent mitigations may not exist.

---

## 7. Recommendations: Setuid Binary Audit Checklist

All setuid/setgid binaries registered in the KSI setuid database
(REQ-0507) must be audited against the following checklist before
registration:

| # | Check | Severity | Rationale |
|---|-------|----------|-----------|
| 1 | Calls `closefrom(STDERR_FILENO + 1)` or equivalent before processing input | **Required** | Closes all inherited fds except stdin/stdout/stderr |
| 2 | Validates fd 0, 1, 2 are open at startup (opens /dev/null if not) | **Required** | Prevents fd reuse attacks where attacker closes stdin/stdout/stderr before exec |
| 3 | Opens all new fds with O_CLOEXEC flag | **Required** | Prevents further inheritance if the binary forks/execs |
| 4 | Enters Capsicum capability mode (cap_enter) after resource acquisition | **Recommended** | Strongest available fd restriction; prevents new global namespace operations |
| 5 | Drops privileges (seteuid to real UID) as early as possible | **Required** | Limits the privilege window during which inherited fds could cause damage |
| 6 | Does not read from or write to fds passed via environment variables or command-line arguments without validation | **Required** | Prevents attacker from directing I/O to inherited descriptors |
| 7 | Uses syscall restriction if available: `pledge(2)` (OpenBSD only). On FreeBSD, use `procctl(2)` with `PROC_NO_NEW_PRIVS` or equivalent process supervision policy. Capsicum `cap_enter(2)` is already covered by requirement #4 and should not be duplicated here. | **Recommended** | Additional defense-in-depth for syscall surface reduction |
| 8 | Audited for CWE-403 (Exposure of File Descriptor to Unintended Control Sphere) | **Required** | Systematic check against the relevant CWE |

### 7.1 Audit Evidence

For each registered setuid binary, the following evidence must be recorded
in the KSI setuid database registration:

- Source code location of closefrom(2) or equivalent call
- Capsicum capability mode entry point (if applicable)
- Privilege drop location (seteuid/setgid call)
- Date of last fd inheritance audit
- Auditor identification

---

## 8. References

- IEEE Std 1003.1-2017 (POSIX), Section 2.5.1 (File Descriptor Allocation)
- FreeBSD closefrom(2) manual page
- FreeBSD capsicum(4) manual page
- CERT C Secure Coding Standard, FIO42-C (Close Files When They Are No Longer Needed)
- CWE-403: Exposure of File Descriptor to Unintended Control Sphere
- CWE-543: Use of the Standard Static Buffer in a setuid/setgid Program
- Chen, Wagner, Dean, "Setuid Demystified" (USENIX Security 2002)
- Watson, Anderson, Laurie, Kennaway, "Capsicum: Practical Capabilities for UNIX" (USENIX Security 2010)
- FBVBS Design Specification, Section 27 (KSI Subsystem)
- FBVBS Risk Register, R-5 (fd Inheritance Risk)
