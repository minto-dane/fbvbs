// Generated from plan/fbvbs-design.md. Do not edit manually.
#![allow(non_camel_case_types)]

pub const FBVBS_CMD_FLAG_SEPARATE_OUTPUT: u64 = (1ULL << 0);

pub const EMPTY: u64 = 0;
pub const READY: u64 = 1;
pub const EXECUTING: u64 = 2;
pub const COMPLETED: u64 = 3;
pub const FAILED: u64 = 4;

pub const FBVBS_CALL_PARTITION_CREATE: u64 = 0x0001;
pub const FBVBS_CALL_PARTITION_DESTROY: u64 = 0x0002;
pub const FBVBS_CALL_PARTITION_GET_STATUS: u64 = 0x0003;
pub const FBVBS_CALL_PARTITION_QUIESCE: u64 = 0x0004;
pub const FBVBS_CALL_PARTITION_RESUME: u64 = 0x0005;
pub const FBVBS_CALL_PARTITION_MEASURE: u64 = 0x0006;
pub const FBVBS_CALL_PARTITION_LOAD_IMAGE: u64 = 0x0007;
pub const FBVBS_CALL_PARTITION_START: u64 = 0x0008;
pub const FBVBS_CALL_PARTITION_RECOVER: u64 = 0x0009;
pub const FBVBS_CALL_PARTITION_GET_FAULT_INFO: u64 = 0x000A;
pub const FBVBS_CALL_MEMORY_ALLOCATE_OBJECT: u64 = 0x1000;
pub const FBVBS_CALL_MEMORY_MAP: u64 = 0x1001;
pub const FBVBS_CALL_MEMORY_UNMAP: u64 = 0x1002;
pub const FBVBS_CALL_MEMORY_SET_PERMISSION: u64 = 0x1003;
pub const FBVBS_CALL_MEMORY_REGISTER_SHARED: u64 = 0x1004;
pub const FBVBS_CALL_MEMORY_RELEASE_OBJECT: u64 = 0x1005;
pub const FBVBS_CALL_MEMORY_UNREGISTER_SHARED: u64 = 0x1006;
pub const FBVBS_CALL_KCI_VERIFY_MODULE: u64 = 0x2001;
pub const FBVBS_CALL_KCI_SET_WX: u64 = 0x2002;
pub const FBVBS_CALL_KCI_PIN_CR: u64 = 0x2003;
pub const FBVBS_CALL_KCI_INTERCEPT_MSR: u64 = 0x2004;
pub const FBVBS_CALL_KSI_CREATE_TARGET_SET: u64 = 0x3000;
pub const FBVBS_CALL_KSI_REGISTER_TIER_A: u64 = 0x3001;
pub const FBVBS_CALL_KSI_REGISTER_TIER_B: u64 = 0x3002;
pub const FBVBS_CALL_KSI_MODIFY_TIER_B: u64 = 0x3003;
pub const FBVBS_CALL_KSI_REGISTER_POINTER: u64 = 0x3004;
pub const FBVBS_CALL_KSI_VALIDATE_SETUID: u64 = 0x3005;
pub const FBVBS_CALL_KSI_ALLOCATE_UCRED: u64 = 0x3006;
pub const FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT: u64 = 0x3007;
pub const FBVBS_CALL_KSI_UNREGISTER_OBJECT: u64 = 0x3008;
pub const FBVBS_CALL_IKS_IMPORT_KEY: u64 = 0x4001;
pub const FBVBS_CALL_IKS_SIGN: u64 = 0x4002;
pub const FBVBS_CALL_IKS_KEY_EXCHANGE: u64 = 0x4003;
pub const FBVBS_CALL_IKS_DERIVE: u64 = 0x4004;
pub const FBVBS_CALL_IKS_DESTROY_KEY: u64 = 0x4005;
pub const FBVBS_CALL_SKS_IMPORT_DEK: u64 = 0x5001;
pub const FBVBS_CALL_SKS_DECRYPT_BATCH: u64 = 0x5002;
pub const FBVBS_CALL_SKS_ENCRYPT_BATCH: u64 = 0x5003;
pub const FBVBS_CALL_SKS_DESTROY_DEK: u64 = 0x5004;
pub const FBVBS_CALL_UVS_VERIFY_MANIFEST_SET: u64 = 0x6001;
pub const FBVBS_CALL_UVS_VERIFY_ARTIFACT: u64 = 0x6002;
pub const FBVBS_CALL_UVS_CHECK_REVOCATION: u64 = 0x6003;
pub const FBVBS_CALL_VM_CREATE: u64 = 0x7001;
pub const FBVBS_CALL_VM_DESTROY: u64 = 0x7002;
pub const FBVBS_CALL_VM_RUN: u64 = 0x7003;
pub const FBVBS_CALL_VM_SET_REGISTER: u64 = 0x7004;
pub const FBVBS_CALL_VM_GET_REGISTER: u64 = 0x7005;
pub const FBVBS_CALL_VM_MAP_MEMORY: u64 = 0x7006;
pub const FBVBS_CALL_VM_INJECT_INTERRUPT: u64 = 0x7007;
pub const FBVBS_CALL_VM_ASSIGN_DEVICE: u64 = 0x7008;
pub const FBVBS_CALL_VM_RELEASE_DEVICE: u64 = 0x7009;
pub const FBVBS_CALL_VM_GET_VCPU_STATUS: u64 = 0x700A;
pub const FBVBS_CALL_AUDIT_GET_MIRROR_INFO: u64 = 0x8001;
pub const FBVBS_CALL_AUDIT_GET_BOOT_ID: u64 = 0x8002;
pub const FBVBS_CALL_DIAG_GET_PARTITION_LIST: u64 = 0x8003;
pub const FBVBS_CALL_DIAG_GET_CAPABILITIES: u64 = 0x8004;
pub const FBVBS_CALL_DIAG_GET_ARTIFACT_LIST: u64 = 0x8005;
pub const FBVBS_CALL_DIAG_GET_DEVICE_LIST: u64 = 0x8006;

pub const PARTITION_KIND_TRUSTED_SERVICE: u64 = 1;
pub const PARTITION_KIND_FREEBSD_HOST: u64 = 2;
pub const PARTITION_KIND_GUEST_VM: u64 = 3;
pub const SERVICE_KIND_NONE: u64 = 0;
pub const SERVICE_KIND_KCI: u64 = 1;
pub const SERVICE_KIND_KSI: u64 = 2;
pub const SERVICE_KIND_IKS: u64 = 3;
pub const SERVICE_KIND_SKS: u64 = 4;
pub const SERVICE_KIND_UVS: u64 = 5;
pub const PARTITION_ID_MICROHYPERVISOR: u64 = 0;
pub const MEM_PERM_R: u64 = 0x0001;
pub const MEM_PERM_W: u64 = 0x0002;
pub const MEM_PERM_X: u64 = 0x0004;
pub const KSI_CLASS_UCRED: u64 = 1;
pub const KSI_CLASS_PRISON: u64 = 2;
pub const KSI_CLASS_SECURELEVEL: u64 = 3;
pub const KSI_CLASS_MAC: u64 = 4;
pub const KSI_CLASS_CAPSICUM: u64 = 5;
pub const KSI_CLASS_FIREWALL: u64 = 6;
pub const KSI_CLASS_P_TEXTVP: u64 = 7;
pub const IKS_KEY_ED25519: u64 = 1;
pub const IKS_KEY_ECDSA_P256: u64 = 2;
pub const IKS_KEY_RSA3072: u64 = 3;
pub const IKS_KEY_X25519: u64 = 4;
pub const IKS_KEY_ECDH_P256: u64 = 5;
pub const IKS_OP_SIGN: u64 = 0x0001;
pub const IKS_OP_KEY_EXCHANGE: u64 = 0x0002;
pub const IKS_OP_DERIVE: u64 = 0x0004;
pub const CR_NUMBER_CR0: u64 = 0;
pub const CR_NUMBER_CR3: u64 = 3;
pub const CR_NUMBER_CR4: u64 = 4;
pub const UVS_OBJECT_KEY: u64 = 1;
pub const UVS_OBJECT_ARTIFACT: u64 = 2;
pub const VM_FLAG_X2APIC: u64 = 0x0001;
pub const VM_FLAG_NESTED_VIRT_DISABLED: u64 = 0x0002;
pub const VM_RUN_FLAG_NONE: u64 = 0x0000;
pub const VM_REG_RIP: u64 = 1;
pub const VM_REG_RSP: u64 = 2;
pub const VM_REG_RFLAGS: u64 = 3;
pub const VM_REG_CR0: u64 = 4;
pub const VM_REG_CR3: u64 = 5;
pub const VM_REG_CR4: u64 = 6;
pub const VM_DELIVERY_FIXED: u64 = 1;
pub const VM_DELIVERY_NMI: u64 = 2;
pub const CR_ACCESS_READ: u64 = 1;
pub const CR_ACCESS_WRITE: u64 = 2;
pub const FAULT_CODE_PARTITION_INTERNAL: u64 = 1;
pub const FAULT_CODE_MEASUREMENT_FAILURE: u64 = 2;
pub const FAULT_CODE_VM_EXIT_UNCLASSIFIED: u64 = 3;
pub const CAP_BITMAP0_MBEC_OR_GMET: u64 = (1ULL << 0);
pub const CAP_BITMAP0_HLAT: u64 = (1ULL << 1);
pub const CAP_BITMAP0_CET: u64 = (1ULL << 2);
pub const CAP_BITMAP0_AESNI: u64 = (1ULL << 3);

pub const OK: u64 = 0;
pub const INVALID_PARAMETER: u64 = 1;
pub const INVALID_CALLER: u64 = 2;
pub const PERMISSION_DENIED: u64 = 3;
pub const RESOURCE_BUSY: u64 = 4;
pub const NOT_SUPPORTED_ON_PLATFORM: u64 = 5;
pub const MEASUREMENT_FAILED: u64 = 6;
pub const SIGNATURE_INVALID: u64 = 7;
pub const ROLLBACK_DETECTED: u64 = 8;
pub const RETRY_LATER: u64 = 9;
pub const REVOKED: u64 = 10;
pub const GENERATION_MISMATCH: u64 = 11;
pub const DEPENDENCY_UNSATISFIED: u64 = 12;
pub const CALLSITE_REJECTED: u64 = 13;
pub const POLICY_DENIED: u64 = 14;
pub const INTERNAL_CORRUPTION: u64 = 15;
pub const INVALID_STATE: u64 = 16;
pub const NOT_FOUND: u64 = 17;
pub const ALREADY_EXISTS: u64 = 18;
pub const RESOURCE_EXHAUSTED: u64 = 19;
pub const BUFFER_TOO_SMALL: u64 = 20;
pub const ABI_VERSION_UNSUPPORTED: u64 = 21;
pub const SNAPSHOT_INCONSISTENT: u64 = 22;
pub const FRESHNESS_FAILED: u64 = 23;
pub const REPLAY_DETECTED: u64 = 24;
pub const TIMEOUT: u64 = 25;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct fbvbs_log_record_v1 {
    pub sequence: u64,
    pub boot_id_hi: u64,
    pub boot_id_lo: u64,
    pub timestamp_counter: u64,
    pub cpu_id: u32,
    pub source_component: u32,
    pub severity: u16,
    pub event_code: u16,
    pub payload_length: u32,
    pub payload: [u8; 220],
    pub crc32c: u32,
}
pub const FBVBS_LOG_RECORD_V1_SIZE: usize = 272;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct fbvbs_log_ring_header_v1 {
    pub abi_version: u32,
    pub total_size: u32,
    pub record_size: u32,
    pub write_offset: u32,
    pub max_readable_sequence: u64,
    pub boot_id_hi: u64,
    pub boot_id_lo: u64,
}
pub const FBVBS_LOG_RING_HEADER_V1_SIZE: usize = 40;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct fbvbs_command_page_v1 {
    pub abi_version: u32,
    pub call_id: u16,
    pub flags: u16,
    pub input_length: u32,
    pub output_length_max: u32,
    pub caller_sequence: u64,
    pub caller_nonce: u64,
    pub command_state: u32,
    pub actual_output_length: u32,
    pub output_page_gpa: u64,
    pub reserved0: u64,
    pub body: [u8; 4040],
}
pub const FBVBS_COMMAND_PAGE_V1_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct fbvbs_bootstrap_page_v1 {
    pub abi_version: u32,
    pub vcpu_count: u32,
    pub command_page_gpa: [u64; 252],
}
pub const FBVBS_BOOTSTRAP_PAGE_V1_SIZE: usize = 2024;
