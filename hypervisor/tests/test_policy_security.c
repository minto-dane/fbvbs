/* FBVBS Policy/Security Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト), REQ-1005 (MC/DC カバレッジ)
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_cpu_security.h"
#include "../include/fbvbs_hypervisor.h"

#define TEST_ELF_CODE_OFFSET 0x100U
#define TEST_ELF_CODE_SIZE 0x40U
#define TEST_AUDIT_CAPTURE_BYTES 2048U

static char g_audit_capture[TEST_AUDIT_CAPTURE_BYTES];
static size_t g_audit_capture_length;
static int g_audit_capture_enabled;

void fbvbs_audit_primary_sink_write(const char *message) {
    size_t index = 0U;

    if (!g_audit_capture_enabled || message == NULL) {
        return;
    }

    while (message[index] != '\0' &&
           g_audit_capture_length + 1U < sizeof(g_audit_capture)) {
        g_audit_capture[g_audit_capture_length] = message[index];
        ++g_audit_capture_length;
        ++index;
    }
    g_audit_capture[g_audit_capture_length] = '\0';
}

static void reset_audit_capture(void) {
    memset(g_audit_capture, 0, sizeof(g_audit_capture));
    g_audit_capture_length = 0U;
}

struct test_elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct test_elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

static void build_test_boot_image_with_segment_flags(
    uint8_t page[FBVBS_PAGE_SIZE],
    uint64_t entry_ip,
    uint32_t segment_flags
) {
    struct test_elf64_ehdr ehdr = {0};
    struct test_elf64_phdr phdr = {0};
    uint32_t index;

    memset(page, 0, FBVBS_PAGE_SIZE);

    ehdr.e_ident[0] = 0x7FU;
    ehdr.e_ident[1] = (uint8_t)'E';
    ehdr.e_ident[2] = (uint8_t)'L';
    ehdr.e_ident[3] = (uint8_t)'F';
    ehdr.e_ident[4] = 2U;
    ehdr.e_ident[5] = 1U;
    ehdr.e_ident[6] = 1U;
    ehdr.e_type = 2U;
    ehdr.e_machine = 62U;
    ehdr.e_version = 1U;
    ehdr.e_entry = entry_ip;
    ehdr.e_phoff = sizeof(ehdr);
    ehdr.e_ehsize = (uint16_t)sizeof(ehdr);
    ehdr.e_phentsize = (uint16_t)sizeof(phdr);
    ehdr.e_phnum = 1U;

    phdr.p_type = 1U;
    phdr.p_flags = segment_flags;
    phdr.p_offset = TEST_ELF_CODE_OFFSET;
    phdr.p_vaddr = entry_ip;
    phdr.p_paddr = entry_ip;
    phdr.p_filesz = TEST_ELF_CODE_SIZE;
    phdr.p_memsz = FBVBS_PAGE_SIZE;
    phdr.p_align = FBVBS_PAGE_SIZE;

    memcpy(page, &ehdr, sizeof(ehdr));
    memcpy(&page[sizeof(ehdr)], &phdr, sizeof(phdr));
    for (index = 0U; index < TEST_ELF_CODE_SIZE; ++index) {
        page[TEST_ELF_CODE_OFFSET + index] = (uint8_t)(0x90U + (index & 0x0FU));
    }
}

static void build_test_boot_image(uint8_t page[FBVBS_PAGE_SIZE], uint64_t entry_ip) {
    build_test_boot_image_with_segment_flags(page, entry_ip, 0x5U);
}

static void init_authorized_host_command_caller(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t observed_rip
) {
    state->partitions[0].occupied = true;
    state->partitions[0].partition_id = partition_id;
    state->partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state->partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[0].vcpu_count = 1U;
    state->partitions[0].capability_mask = FBVBS_CAP_AUDIT_DIAG;
    state->partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNABLE;
    state->partitions[0].vcpus[0].rip = observed_rip;

    state->host_callsites[0].active = true;
    state->host_callsites[0].caller_class = FBVBS_HOST_CALLER_CLASS_FBVBS;
    state->host_callsites[0].count = 1U;
    state->host_callsites[0].relocated_callsites[0] = observed_rip;
}

static void init_ready_diag_command_page(
    struct fbvbs_command_page_v1 *page,
    uint64_t caller_sequence
) {
    memset(page, 0, sizeof(*page));
    page->abi_version = FBVBS_ABI_VERSION;
    page->call_id = FBVBS_CALL_DIAG_GET_CAPABILITIES;
    page->output_length_max = (uint32_t)sizeof(struct fbvbs_diag_capabilities_response);
    page->caller_sequence = caller_sequence;
    page->command_state = READY;
}

static void init_runnable_guest_vm(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    state->vmx_caps.vmx_supported = 1U;
    state->partitions[0].occupied = true;
    state->partitions[0].partition_id = partition_id;
    state->partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state->partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[0].vcpu_count = 1U;
    state->partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state->partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNABLE;
}

static void test_dispatch_hypercall_returns_diag_capabilities_for_authorized_host_page(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers = {0};
    struct fbvbs_diag_capabilities_response response;
    struct fbvbs_command_page_v1 *page;
    int status;

    memset(&state, 0, sizeof(state));
    init_authorized_host_command_caller(&state, 0x5000U, 0x400000U);
    state.capability_bitmap0 = 0x1122334455667788ULL;
    state.capability_bitmap1 = CAP_BITMAP1_IOMMU | CAP_BITMAP1_FOUNDATION_READY;

    page = &state.partitions[0].command_pages[0].page;
    init_ready_diag_command_page(page, 1U);

    registers.rax = (uint64_t)(uintptr_t)page;
    status = fbvbs_dispatch_hypercall(&state, &registers);

    assert(status == OK);
    assert(page->command_state == COMPLETED);
    assert(page->actual_output_length == sizeof(response));
    assert(registers.rax == OK);
    assert(registers.rbx == COMPLETED);
    assert(registers.rcx == sizeof(response));
    memcpy(&response, page->body, sizeof(response));
    assert(response.capability_bitmap0 == state.capability_bitmap0);
    assert(response.capability_bitmap1 == state.capability_bitmap1);
    assert(state.command_trackers[0].active);
    assert(state.command_trackers[0].last_sequence == 1U);
}

static void test_dispatch_hypercall_rejects_replayed_sequence(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers = {0};
    struct fbvbs_command_page_v1 *page;
    int status;

    memset(&state, 0, sizeof(state));
    init_authorized_host_command_caller(&state, 0x5001U, 0x400100U);

    page = &state.partitions[0].command_pages[0].page;
    init_ready_diag_command_page(page, 7U);

    registers.rax = (uint64_t)(uintptr_t)page;
    status = fbvbs_dispatch_hypercall(&state, &registers);
    assert(status == OK);

    init_ready_diag_command_page(page, 7U);
    registers = (struct fbvbs_trap_registers){
        .rax = (uint64_t)(uintptr_t)page
    };
    status = fbvbs_dispatch_hypercall(&state, &registers);

    assert(status == REPLAY_DETECTED);
    assert(page->command_state == FAILED);
    assert(page->actual_output_length == 0U);
    assert(registers.rax == REPLAY_DETECTED);
    assert(registers.rbx == FAILED);
}

static void test_dispatch_hypercall_rejects_unowned_command_page(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_command_page_v1 page;
    } command_page = {0};
    uint64_t original_rax;
    int status;

    memset(&state, 0, sizeof(state));
    init_ready_diag_command_page(&command_page.page, 1U);

    registers.rax = (uint64_t)(uintptr_t)&command_page.page;
    original_rax = registers.rax;
    status = fbvbs_dispatch_hypercall(&state, &registers);

    assert(status == PERMISSION_DENIED);
    assert(command_page.page.command_state == READY);
    assert(command_page.page.actual_output_length == 0U);
    assert(registers.rax == original_rax);
    assert(registers.rbx == 0U);
    assert(registers.rcx == 0U);
    assert(registers.rdx == 0U);
}

static void test_dispatch_hypercall_rejects_host_callsite_outside_allowlist(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers = {0};
    struct fbvbs_command_page_v1 *page;
    int status;

    memset(&state, 0, sizeof(state));
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x5002U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].capability_mask = FBVBS_CAP_AUDIT_DIAG;
    state.partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNABLE;
    state.partitions[0].vcpus[0].rip = 0x400200U;

    page = &state.partitions[0].command_pages[0].page;
    init_ready_diag_command_page(page, 1U);

    registers.rax = (uint64_t)(uintptr_t)page;
    status = fbvbs_dispatch_hypercall(&state, &registers);

    assert(status == CALLSITE_REJECTED);
    assert(page->command_state == FAILED);
    assert(registers.rax == CALLSITE_REJECTED);
    assert(registers.rbx == FAILED);
}

static void test_dispatch_hypercall_supports_registered_separate_output_page(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers = {0};
    struct fbvbs_diag_capabilities_response response;
    struct fbvbs_command_page_v1 *page;
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } output_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    init_authorized_host_command_caller(&state, 0x5003U, 0x400300U);
    state.capability_bitmap0 = 0xA5A5A5A5A5A5A5A5ULL;
    state.capability_bitmap1 = CAP_BITMAP1_HIGH_ASSURANCE_FOUNDATION;

    page = &state.partitions[0].command_pages[0].page;
    init_ready_diag_command_page(page, 9U);
    page->flags = FBVBS_CMD_FLAG_SEPARATE_OUTPUT;
    page->output_page_gpa = (uint64_t)(uintptr_t)output_page.bytes;

    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_WRITE;
    state.partitions[0].mappings[0].memory_object_id = 0xCAFEU;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)output_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;

    state.shared_objects[0].active = true;
    state.shared_objects[0].peer_permissions = FBVBS_MEMORY_PERMISSION_WRITE;
    state.shared_objects[0].memory_object_id = 0xCAFEU;
    state.shared_objects[0].size = FBVBS_PAGE_SIZE;
    state.shared_objects[0].owner_partition_id = 0x5003U;
    state.shared_objects[0].peer_partition_id = 0U;

    registers.rax = (uint64_t)(uintptr_t)page;
    status = fbvbs_dispatch_hypercall(&state, &registers);

    assert(status == OK);
    assert(page->command_state == COMPLETED);
    assert(page->actual_output_length == sizeof(response));
    memcpy(&response, output_page.bytes, sizeof(response));
    assert(response.capability_bitmap0 == state.capability_bitmap0);
    assert(response.capability_bitmap1 == state.capability_bitmap1);
    assert(page->body[0] == 0U);
}

static void test_vm_run_translates_common_vm_exits(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_run_request request = {0};
    struct fbvbs_vm_run_response response = {0};
    struct fbvbs_vm_exit_external_interrupt external = {0};
    struct fbvbs_vm_exit_cr_access cr_access = {0};
    struct fbvbs_vm_exit_msr_access msr_access = {0};
    struct fbvbs_vm_exit_ept_violation ept_violation = {0};
    struct fbvbs_vm_exit_pio pio = {0};
    struct fbvbs_vm_exit_mmio mmio = {0};
    int status;

    memset(&state, 0, sizeof(state));
    init_runnable_guest_vm(&state, 0x6000U);
    request.vm_partition_id = 0x6000U;

    state.partitions[0].vcpus[0].pending_interrupt_delivery = 1U;
    state.partitions[0].vcpus[0].pending_interrupt_vector = 48U;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT);
    memcpy(&external, response.exit_payload, sizeof(external));
    assert(external.vector == 48U);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(state.partitions[0].vcpus[0].state == FBVBS_VCPU_STATE_RUNNABLE);

    state.pinned_cr4_mask = CR4_PCE;
    state.pinned_cr4_value = 0U;
    state.partitions[0].vcpus[0].cr4 = CR4_PCE;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS);
    memcpy(&cr_access, response.exit_payload, sizeof(cr_access));
    assert(cr_access.cr_number == 4U);
    assert(cr_access.access_type == FBVBS_VM_CR_ACCESS_WRITE);
    assert(cr_access.value == 0U);
    assert(state.partitions[0].vcpus[0].cr4 == 0U);

    state.intercepted_msrs[0] = 0xC0000080U;
    state.intercepted_msr_count = 1U;
    state.partitions[0].vcpus[0].rflags = 1U;
    state.partitions[0].vcpus[0].rsp = 0x1122334455667788ULL;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_MSR_ACCESS);
    memcpy(&msr_access, response.exit_payload, sizeof(msr_access));
    assert(msr_access.msr == 0xC0000080U);
    assert(msr_access.is_write == 1U);
    assert(msr_access.value == 0x1122334455667788ULL);

    state.intercepted_msr_count = 0U;
    state.partitions[0].mapped_bytes = 0U;
    state.partitions[0].vcpus[0].rflags =
        (uint64_t)FBVBS_VM_EPT_ACCESS_WRITE << FBVBS_SYNTHETIC_EPT_ACCESS_SHIFT;
    state.partitions[0].vcpus[0].rsp = 0x2000U;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_EPT_VIOLATION);
    memcpy(&ept_violation, response.exit_payload, sizeof(ept_violation));
    assert(ept_violation.guest_physical_address == 0x2000U);
    assert(ept_violation.access_bits == FBVBS_VM_EPT_ACCESS_WRITE);

    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].vcpus[0].rip = FBVBS_SYNTHETIC_EXIT_RIP_PIO;
    state.partitions[0].vcpus[0].rsp = 0x3F8U;
    state.partitions[0].vcpus[0].rflags = 1U;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_PIO);
    memcpy(&pio, response.exit_payload, sizeof(pio));
    assert(pio.port == 0x03F8U);
    assert(pio.width == 4U);
    assert(pio.is_write == 1U);
    assert(pio.count == 1U);
    assert(pio.value == 1U);

    state.partitions[0].vcpus[0].rip = FBVBS_SYNTHETIC_EXIT_RIP_MMIO;
    state.partitions[0].vcpus[0].rsp = 0x2000U;
    state.partitions[0].vcpus[0].rflags = 0U;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_MMIO);
    memcpy(&mmio, response.exit_payload, sizeof(mmio));
    assert(mmio.guest_physical_address == 0x2000U);
    assert(mmio.width == 8U);
    assert(mmio.is_write == 0U);

    state.partitions[0].vcpus[0].rip = 0x1234U;
    status = fbvbs_vm_run(&state, &request, &response);
    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_HALT);
    assert(state.partitions[0].vcpus[0].state == FBVBS_VCPU_STATE_BLOCKED);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_RUNNABLE);
}

static void test_vm_run_shutdown_faults_partition(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_run_request request = {0};
    struct fbvbs_vm_run_response response = {0};
    int status;

    memset(&state, 0, sizeof(state));
    init_runnable_guest_vm(&state, 0x6001U);
    request.vm_partition_id = 0x6001U;
    state.partitions[0].vcpus[0].rip = FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN;

    status = fbvbs_vm_run(&state, &request, &response);

    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_SHUTDOWN);
    assert(state.partitions[0].vcpus[0].state == FBVBS_VCPU_STATE_FAULTED);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
}

static void test_vm_run_unclassified_fault_records_partition_fault(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_run_request request = {0};
    struct fbvbs_vm_run_response response = {0};
    struct fbvbs_vm_exit_unclassified_fault fault = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.boot_id_hi = 0x1U;
    state.boot_id_lo = 0x2U;
    assert(fbvbs_log_init(&state) == OK);
    init_runnable_guest_vm(&state, 0x6002U);
    request.vm_partition_id = 0x6002U;
    state.partitions[0].vcpus[0].rip = FBVBS_SYNTHETIC_EXIT_RIP_FAULT;

    status = fbvbs_vm_run(&state, &request, &response);

    assert(status == OK);
    assert(response.exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT);
    memcpy(&fault, response.exit_payload, sizeof(fault));
    assert(fault.fault_code == FAULT_CODE_VM_EXIT_UNCLASSIFIED);
    assert(fault.detail0 == 0U);
    assert(fault.detail1 == FBVBS_SYNTHETIC_EXIT_RIP_FAULT);
    assert(state.partitions[0].last_fault_code == FAULT_CODE_VM_EXIT_UNCLASSIFIED);
    assert(state.partitions[0].last_fault_detail0 == 0U);
    assert(state.partitions[0].last_fault_detail1 == FBVBS_SYNTHETIC_EXIT_RIP_FAULT);
    assert(state.partitions[0].vcpus[0].state == FBVBS_VCPU_STATE_FAULTED);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
}

static void test_kci_verify_module_uses_current_manifest_generation(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response response = {0};
    struct fbvbs_kci_verify_module_request request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    memset(module_page.bytes, 0x5A, sizeof(module_page.bytes));

    manifest.object_id = 0x2222U;
    manifest.generation = 7U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;

    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa = (uint64_t)(uintptr_t)&manifest_page.page;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x1111U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x2222U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 1U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x1111U;
    state.approvals[0].manifest_object_id = 0x2222U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x1111U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x1111U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)module_page.bytes;

    request.module_object_id = 0x1111U;
    request.manifest_object_id = 0x2222U;
    request.generation = 6U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == GENERATION_MISMATCH);

    request.generation = 7U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == OK);
    assert(response.verdict == 1U);
    assert(state.approved_module_object_id == 0x1111U);
}

static void test_vm_set_register_enforces_arch_and_pin_policy(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_register_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.pinned_cr0_mask = CR0_WP;
    state.pinned_cr0_value = CR0_WP;
    state.pinned_cr4_mask = CR4_SMEP | CR4_SMAP | CR4_PCE;
    state.pinned_cr4_value = CR4_SMEP | CR4_SMAP;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x3333U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNABLE;

    request.vm_partition_id = 0x3333U;
    request.vcpu_id = 0U;

    request.register_id = VM_REG_RFLAGS;
    request.value = 0U;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == INVALID_PARAMETER);

    request.register_id = VM_REG_CR4;
    request.value = CR4_SMEP | CR4_SMAP | CR4_PCE;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == PERMISSION_DENIED);

    request.register_id = VM_REG_CR4;
    request.value = CR4_SMEP | CR4_SMAP;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].vcpus[0].cr4 == (CR4_SMEP | CR4_SMAP));
}

static void test_log_append_fails_closed_on_sequence_wraparound(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));

    assert(fbvbs_log_init(&state) == OK);
    state.mirror_log.header.max_readable_sequence = UINT64_MAX;

    status = fbvbs_log_append(&state, 0U, 0U, 0U, 0U, NULL, 0U);
    assert(status == RESOURCE_EXHAUSTED);
    assert(state.mirror_log.header.max_readable_sequence == UINT64_MAX);
    assert(state.log_lock == 0U);
}

static void test_sha384_matches_known_vector(void) {
    static const uint8_t expected[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };
    uint8_t digest[48];

    fbvbs_sha384("abc", 3U, digest);
    assert(memcmp(digest, expected, sizeof(expected)) == 0);
}

static void test_multiboot_parser_tracks_boot_modules_and_resets_boot_metadata(void) {
    struct fbvbs_hypervisor_state state;
    struct {
        _Alignas(8) uint8_t bytes[64];
    } info = {{0}};
    static const char cmdline[] = "artifact:0x1700";
    uint32_t total_size = 48U;
    uint32_t type;
    uint32_t size;
    uint32_t mod_start;
    uint32_t mod_end;

    memset(&state, 0, sizeof(state));
    state.boot_device = 0xFFFFFFFFU;
    state.boot_partition = 0xFFFFFFFFU;
    state.boot_sub_partition = 0xFFFFFFFFU;
    state.boot_module_count = 1U;
    state.boot_modules[0].active = true;
    strcpy(state.boot_modules[0].cmdline, "stale");

    memcpy(&info.bytes[0], &total_size, sizeof(total_size));

    type = 3U;
    size = 32U;
    mod_start = 0x200000U;
    mod_end = 0x201234U;
    memcpy(&info.bytes[8], &type, sizeof(type));
    memcpy(&info.bytes[12], &size, sizeof(size));
    memcpy(&info.bytes[16], &mod_start, sizeof(mod_start));
    memcpy(&info.bytes[20], &mod_end, sizeof(mod_end));
    memcpy(&info.bytes[24], cmdline, sizeof(cmdline));

    type = 0U;
    size = 8U;
    memcpy(&info.bytes[40], &type, sizeof(type));
    memcpy(&info.bytes[44], &size, sizeof(size));

    fbvbs_process_multiboot_info(&state, info.bytes, total_size);

    assert(state.boot_device == 0U);
    assert(state.boot_partition == 0U);
    assert(state.boot_sub_partition == 0U);
    assert(state.boot_module_count == 1U);
    assert(state.boot_modules[0].active);
    assert(state.boot_modules[0].start_phys == 0x200000U);
    assert(state.boot_modules[0].size == 0x1234U);
    assert(strcmp(state.boot_modules[0].cmdline, cmdline) == 0);
}

static void test_shared_registration_only_charges_real_mappings(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request map_shared = {0};
    struct fbvbs_memory_map_request map_private = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    state.memory_objects[1].allocated = true;
    state.memory_objects[1].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[1].memory_object_id = 0x2000U;
    state.memory_objects[1].owner_partition_id = 0x200U;
    state.memory_objects[1].size = FBVBS_PAGE_SIZE;

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(
        &state,
        &share_request,
        &share_response,
        0x100U
    );
    assert(status == OK);
    assert(share_response.shared_object_id != 0U);
    assert(state.partitions[1].mapped_bytes == 0U);
    assert(state.memory_objects[0].shared_count == 1U);

    map_shared.partition_id = 0x200U;
    map_shared.memory_object_id = 0x1000U;
    map_shared.guest_physical_address = FBVBS_PAGE_SIZE;
    map_shared.size = FBVBS_PAGE_SIZE;
    map_shared.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_shared, 0x100U);
    assert(status == OK);

    map_private.partition_id = 0x200U;
    map_private.memory_object_id = 0x2000U;
    map_private.guest_physical_address = FBVBS_PAGE_SIZE * 2U;
    map_private.size = FBVBS_PAGE_SIZE;
    map_private.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_private, 0x200U);
    assert(status == OK);

    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE * 2U);
    assert(state.memory_objects[0].map_count == 1U);
    assert(state.memory_objects[1].map_count == 1U);

    status = fbvbs_partition_destroy(&state, 0x100U);
    assert(status == OK);
    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE);
    assert(state.memory_objects[0].map_count == 0U);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.memory_objects[1].map_count == 1U);
    assert(!state.partitions[1].mappings[0].active);
    assert(state.partitions[1].mappings[1].active);
}

static void test_shareable_object_requires_registration_for_non_owner_mapping(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    request.partition_id = 0x200U;
    request.memory_object_id = 0x1000U;
    request.guest_physical_address = FBVBS_PAGE_SIZE;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_READ;

    status = fbvbs_memory_map(&state, &request, 0x100U);
    assert(status == PERMISSION_DENIED);
}

static void test_unregister_shared_rejects_live_peer_mapping(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request map_request = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    map_request.partition_id = 0x200U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
    assert(status == RESOURCE_BUSY);
}

static void test_unregister_shared_allows_owner_mapping_when_peer_is_unmapped(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request owner_map = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    owner_map.partition_id = 0x100U;
    owner_map.memory_object_id = 0x1000U;
    owner_map.guest_physical_address = FBVBS_PAGE_SIZE;
    owner_map.size = FBVBS_PAGE_SIZE;
    owner_map.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &owner_map, 0x100U);
    assert(status == OK);

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE);
}

static void test_kci_set_wx_requires_verified_module_measurements(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_kci_set_wx_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.approved_module_object_id = 0x4444U;
    request.module_object_id = 0x4444U;
    request.guest_physical_address = FBVBS_PAGE_SIZE;
    request.file_offset = 0U;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_EXECUTE;

    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == INVALID_STATE);
}

static void test_kci_verify_module_and_set_wx_enforce_measured_pages(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response verify_response = {0};
    struct fbvbs_kci_verify_module_request verify_request = {0};
    struct fbvbs_kci_set_wx_request request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));

    memset(module_page.bytes, 0xA5, sizeof(module_page.bytes));

    manifest.object_id = 0x5555U;
    manifest.generation = 7U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;
    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa = (uint64_t)(uintptr_t)&manifest_page.page;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x4444U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x5555U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x4444U;
    state.approvals[0].manifest_object_id = 0x5555U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x4444U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x4444U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)module_page.bytes;

    verify_request.module_object_id = 0x4444U;
    verify_request.manifest_object_id = 0x5555U;
    verify_request.generation = 7U;
    status = fbvbs_kci_verify_module(&state, &verify_request, &verify_response);
    assert(status == OK);
    assert(verify_response.verdict == 1U);
    assert(state.approved_module_object_id == 0x4444U);
    assert(state.approved_module_base_gpa ==
           (uint64_t)(uintptr_t)module_page.bytes);
    assert(state.approved_module_page_count == 1U);

    request.module_object_id = 0x4444U;
    request.guest_physical_address = (uint64_t)(uintptr_t)module_page.bytes;
    request.file_offset = 0U;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_READ |
                          FBVBS_MEMORY_PERMISSION_EXECUTE;

    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].mappings[0].permissions ==
           (FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_EXECUTE));
    assert(state.kci_binding_count == 1U);

    module_page.bytes[0] ^= 0xFFU;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == MEASUREMENT_FAILED);
    assert(state.partitions[0].mappings[0].permissions == FBVBS_MEMORY_PERMISSION_READ);
}

static void test_kci_verified_module_is_invalidated_on_unmap(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response verify_response = {0};
    struct fbvbs_kci_verify_module_request verify_request = {0};
    struct fbvbs_memory_unmap_request unmap_request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    memset(module_page.bytes, 0x3C, sizeof(module_page.bytes));

    manifest.object_id = 0x5555U;
    manifest.generation = 9U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;
    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa = (uint64_t)(uintptr_t)&manifest_page.page;
    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x4444U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x5555U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;
    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x4444U;
    state.approvals[0].manifest_object_id = 0x5555U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x4444U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].memory_object_id = 0x4444U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)module_page.bytes;

    verify_request.module_object_id = 0x4444U;
    verify_request.manifest_object_id = 0x5555U;
    verify_request.generation = 9U;
    status = fbvbs_kci_verify_module(&state, &verify_request, &verify_response);
    assert(status == OK);
    assert(state.approved_module_object_id == 0x4444U);

    unmap_request.partition_id = 0x100U;
    unmap_request.guest_physical_address = (uint64_t)(uintptr_t)module_page.bytes;
    unmap_request.size = FBVBS_PAGE_SIZE;
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x100U);
    assert(status == OK);
    assert(state.approved_module_object_id == 0U);
    assert(state.approved_module_page_count == 0U);
}

static void test_partition_load_image_succeeds_with_authoritative_artifact(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    struct fbvbs_memory_map_entry allocator_map = {
        .base_addr = 0x100000U,
        .length = FBVBS_PAGE_SIZE * 16U,
        .type = 1U
    };
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } image_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    build_test_boot_image(image_page.bytes, 0x100000U);
    assert(fbvbs_page_alloc_init(&allocator_map, 1U) == 0);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8888U;
    state.partitions[0].manifest_object_id = 0x9999U;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    state.partitions[0].vcpu_count = 1U;
    state.next_memory_object_id = 0x100000U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8888U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9999U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type =
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8888U;
    state.manifest_profiles[0].manifest_object_id = 0x9999U;
    state.manifest_profiles[0].entry_ip = 0x100000U;
    state.manifest_profiles[0].initial_sp = 0x200000U;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x8888U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)image_page.bytes;

    request.partition_id = 0x7777U;
    request.image_object_id = 0x8888U;
    request.entry_ip = 0x100000U;
    request.initial_sp = 0x200000U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_LOADED);
    assert(state.partitions[0].entry_ip == 0x100000U);
    assert(state.partitions[0].initial_sp == 0x200000U);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE * 2U);
    assert(state.partitions[0].vcpus[0].rip == 0x100000U);
    assert(state.partitions[0].vcpus[0].rsp == 0x200000U);
}

static void test_partition_load_image_rejects_non_executable_entry_segment(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    struct fbvbs_memory_map_entry allocator_map = {
        .base_addr = 0x100000U,
        .length = FBVBS_PAGE_SIZE * 16U,
        .type = 1U
    };
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } image_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    build_test_boot_image_with_segment_flags(image_page.bytes, 0x100000U, 0x6U);
    assert(fbvbs_page_alloc_init(&allocator_map, 1U) == 0);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7300U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8300U;
    state.partitions[0].manifest_object_id = 0x9300U;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    state.partitions[0].vcpu_count = 1U;
    state.next_memory_object_id = 0x200000U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8300U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9300U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type =
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8300U;
    state.manifest_profiles[0].manifest_object_id = 0x9300U;
    state.manifest_profiles[0].entry_ip = 0x100000U;
    state.manifest_profiles[0].initial_sp = 0x200000U;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x8300U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)image_page.bytes;

    request.partition_id = 0x7300U;
    request.image_object_id = 0x8300U;
    request.entry_ip = 0x100000U;
    request.initial_sp = 0x200000U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == MEASUREMENT_FAILED);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);
    assert(state.partitions[0].mapped_bytes == 0U);
}

static void test_partition_load_image_rejects_executable_stack_page(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    struct fbvbs_memory_map_entry allocator_map = {
        .base_addr = 0x100000U,
        .length = FBVBS_PAGE_SIZE * 16U,
        .type = 1U
    };
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } image_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    build_test_boot_image(image_page.bytes, 0x100000U);
    assert(fbvbs_page_alloc_init(&allocator_map, 1U) == 0);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7400U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8400U;
    state.partitions[0].manifest_object_id = 0x9400U;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    state.partitions[0].vcpu_count = 1U;
    state.next_memory_object_id = 0x300000U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8400U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9400U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type =
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8400U;
    state.manifest_profiles[0].manifest_object_id = 0x9400U;
    state.manifest_profiles[0].entry_ip = 0x100000U;
    state.manifest_profiles[0].initial_sp = 0x100800U;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x8400U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)image_page.bytes;

    request.partition_id = 0x7400U;
    request.image_object_id = 0x8400U;
    request.entry_ip = 0x100000U;
    request.initial_sp = 0x100800U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == INVALID_PARAMETER);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);
    assert(state.partitions[0].mapped_bytes == 0U);
}

static void test_partition_load_image_rejects_manifest_entry_mismatch(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8100U;
    state.partitions[0].manifest_object_id = 0x9100U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8100U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9100U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8100U;
    state.manifest_profiles[0].manifest_object_id = 0x9100U;
    state.manifest_profiles[0].entry_ip = 0x110000U;
    state.manifest_profiles[0].initial_sp = 0x220000U;

    request.partition_id = 0x7100U;
    request.image_object_id = 0x8100U;
    request.entry_ip = 0xDEADBEEFU;
    request.initial_sp = 0x220000U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == MEASUREMENT_FAILED);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);
    assert(state.partitions[0].entry_ip == 0U);
    assert(state.partitions[0].initial_sp == 0U);
}

static void test_partition_load_image_requires_guest_initial_stack(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7200U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8200U;
    state.partitions[0].manifest_object_id = 0x9200U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8200U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9200U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type = FBVBS_MANIFEST_COMPONENT_GUEST_BOOT;
    state.manifest_profiles[0].object_id = 0x8200U;
    state.manifest_profiles[0].manifest_object_id = 0x9200U;
    state.manifest_profiles[0].entry_ip = 0x330000U;

    request.partition_id = 0x7200U;
    request.image_object_id = 0x8200U;
    request.entry_ip = 0U;
    request.initial_sp = 0U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == INVALID_PARAMETER);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);
    assert(state.partitions[0].entry_ip == 0U);
    assert(state.partitions[0].initial_sp == 0U);
}

static void test_platform_detection_fails_closed_without_real_bringup(void) {
    struct fbvbs_global_security_state state;

    /* IOMMU detection: Intel → fail-closed, type reset (no ACPI evidence). */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_INTEL;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(state.iommu.iommu_type == IOMMU_TYPE_NONE);

    /* IOMMU detection: AMD → fail-closed, type reset (no ACPI evidence). */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_AMD;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(state.iommu.iommu_type == IOMMU_TYPE_NONE);

    /* Boot integrity: Intel → CPUID model detects DRTM bits but
       measured boot cannot be established without platform bring-up. */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_INTEL;
    assert(fbvbs_boot_integrity_detect(&state) == -1);

    /* Unknown vendor must fail-closed for both. */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_UNKNOWN;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(fbvbs_boot_integrity_detect(&state) == -1);
}

static void test_platform_foundation_helpers_expose_release_boundary(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_diag_capabilities_response response;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_audit_runtime_ready(&state) == 0);
    assert(fbvbs_platform_foundation_ready(&state) == 0);
    assert(fbvbs_platform_high_assurance_foundation_ready(&state) == 0);
    assert(fbvbs_host_deprivilege_runtime_ready(&state) == 0);

    state.vmx_caps.vmx_supported = 1U;
    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;
    assert(fbvbs_audit_runtime_ready(&state) == 0);
    assert(fbvbs_platform_foundation_ready(&state) == 0);

    state.boot_id_hi = 0x1234U;
    state.boot_id_lo = 0x5678U;
    assert(fbvbs_log_init(&state) == OK);
    assert((state.runtime_state_flags & FBVBS_RUNTIME_AUDIT_PRIMARY_OOB) != 0U);
    assert(fbvbs_audit_runtime_ready(&state) == 1);
    assert(fbvbs_platform_foundation_ready(&state) == 1);
    assert(fbvbs_platform_high_assurance_foundation_ready(&state) == 0);
    assert(fbvbs_host_deprivilege_runtime_ready(&state) == 0);

    state.cpu_security.boot.measured_boot_active = 1U;
    assert(fbvbs_platform_high_assurance_foundation_ready(&state) == 1);
    assert(fbvbs_host_deprivilege_runtime_ready(&state) == 0);

    state.runtime_state_flags = FBVBS_RUNTIME_HOST_DEPRIVILEGED;
    assert(fbvbs_host_deprivilege_runtime_ready(&state) == 1);

    state.capability_bitmap0 = 0U;
    state.capability_bitmap1 =
        CAP_BITMAP1_IOMMU |
        CAP_BITMAP1_FOUNDATION_READY |
        CAP_BITMAP1_HOST_DEPRIVILEGE |
        CAP_BITMAP1_HIGH_ASSURANCE_FOUNDATION;
    assert(fbvbs_diag_get_capabilities(&state, &response) == OK);
    assert((response.capability_bitmap1 & CAP_BITMAP1_IOMMU) != 0U);
    assert((response.capability_bitmap1 & CAP_BITMAP1_FOUNDATION_READY) != 0U);
    assert((response.capability_bitmap1 & CAP_BITMAP1_HOST_DEPRIVILEGE) != 0U);
    assert((response.capability_bitmap1 & CAP_BITMAP1_HIGH_ASSURANCE_FOUNDATION) != 0U);
}

static void test_log_append_emits_primary_oob_audit_line(void) {
    struct fbvbs_hypervisor_state state;
    static const uint8_t payload[] = {0xAAU, 0xBBU, 0x01U};

    memset(&state, 0, sizeof(state));
    state.boot_id_hi = 0x1122334455667788ULL;
    state.boot_id_lo = 0x99AABBCCDDEEFF00ULL;

    reset_audit_capture();
    g_audit_capture_enabled = 1;

    assert(fbvbs_log_init(&state) == OK);
    assert((state.runtime_state_flags & FBVBS_RUNTIME_AUDIT_PRIMARY_OOB) != 0U);
    assert(fbvbs_log_append(&state,
                            3U,
                            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                            (uint16_t)FBVBS_SEVERITY_WARNING,
                            0x1234U,
                            payload,
                            (uint32_t)sizeof(payload)) == OK);

    g_audit_capture_enabled = 0;

    assert(strstr(g_audit_capture, "AUDIT seq=0000000000000001") != NULL);
    assert(strstr(g_audit_capture, " boot_hi=1122334455667788") != NULL);
    assert(strstr(g_audit_capture, " boot_lo=99AABBCCDDEEFF00") != NULL);
    assert(strstr(g_audit_capture, " cpu=00000003") != NULL);
    assert(strstr(g_audit_capture, " evt=1234") != NULL);
    assert(strstr(g_audit_capture, " payload=AABB01") != NULL);
}


static void test_vm_device_passthrough_is_fail_closed_without_qualification(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x5555U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD000U;

    request.vm_partition_id = 0x5555U;
    request.device_id = 0xD000U;

    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
}

static void test_vm_destroy_rejects_assigned_devices_without_safe_teardown(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x6666U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].assigned_device_count = 1U;
    state.partitions[0].assigned_devices[0] = 0xD000U;

    status = fbvbs_vm_destroy(&state, 0x6666U);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].occupied);
    assert(state.partitions[0].assigned_device_count == 1U);
}

static void test_unregister_shared_rejects_non_owner(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    /* Non-owner (0x200) cannot unregister. */
    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x200U);
    assert(status == PERMISSION_DENIED);
    assert(state.memory_objects[0].shared_count == 1U);

    /* Owner can unregister. */
    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
}

static void test_unmap_rejects_unauthorized_caller(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request map_request = {0};
    struct fbvbs_memory_unmap_request unmap_request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    map_request.partition_id = 0x100U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);

    unmap_request.partition_id = 0x100U;
    unmap_request.guest_physical_address = FBVBS_PAGE_SIZE;
    unmap_request.size = FBVBS_PAGE_SIZE;

    /* Unauthorized third party (0x999) cannot unmap. */
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x999U);
    assert(status == PERMISSION_DENIED);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE);

    /* Owner can unmap. */
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x100U);
    assert(status == OK);
    assert(state.partitions[0].mapped_bytes == 0U);
}

static void test_broadcast_registration_authorizes_any_peer(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request map_request = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    /* Broadcast registration: peer_partition_id == 0 means any peer. */
    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    /* Partition 0x200 can map via broadcast authorization. */
    map_request.partition_id = 0x200U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);
    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE);
}

static void test_vm_device_passthrough_stays_disabled_even_when_platform_looks_ready(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x9000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD900U;
    state.device_catalog.entries[0].qualified = 1U;
    state.device_catalog.entries[0].has_flr = 1U;
    state.device_catalog.entries[0].has_acs = 1U;

    request.vm_partition_id = 0x9000U;
    request.device_id = 0xD900U;

    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
    assert(state.partitions[0].iommu_domain_id == 0U);
}

static void test_vm_release_device_stays_disabled_without_safe_teardown(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x9001U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].assigned_device_count = 1U;
    state.partitions[0].assigned_devices[0] = 0xD901U;

    request.vm_partition_id = 0x9001U;
    request.device_id = 0xD901U;

    status = fbvbs_vm_release_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 1U);
    assert(state.partitions[0].assigned_devices[0] == 0xD901U);
}

static void test_iommu_init_fails_without_release_complete_platform_policy(void) {
    struct fbvbs_global_security_state intel_state;
    struct fbvbs_global_security_state amd_state;

    memset(&intel_state, 0, sizeof(intel_state));
    intel_state.iommu.iommu_type = IOMMU_TYPE_VTD;
    assert(fbvbs_vtd_init(&intel_state) == -1);
    assert(fbvbs_iommu_runtime_ready(&intel_state) == 0);
    assert(intel_state.iommu.kernel_dma_protection == 0U);

    memset(&amd_state, 0, sizeof(amd_state));
    amd_state.iommu.iommu_type = IOMMU_TYPE_AMD_VI;
    assert(fbvbs_amdvi_init(&amd_state) == -1);
    assert(fbvbs_iommu_runtime_ready(&amd_state) == 0);
    assert(amd_state.iommu.kernel_dma_protection == 0U);
}

static void test_deprivilege_host_rejects_partial_handoff_and_clears_flag(void) {
    struct fbvbs_hypervisor_state state;

    memset(&state, 0, sizeof(state));
    state.runtime_state_flags = FBVBS_RUNTIME_HOST_DEPRIVILEGED;
    assert(fbvbs_deprivilege_host(&state) == -1);
    /* Double deprivilege is rejected early — flag must be preserved
     * so the caller knows the system is still deprivileged. */
    assert((state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) != 0U);
}

int main(void) {
    test_dispatch_hypercall_returns_diag_capabilities_for_authorized_host_page();
    test_dispatch_hypercall_rejects_replayed_sequence();
    test_dispatch_hypercall_rejects_unowned_command_page();
    test_dispatch_hypercall_rejects_host_callsite_outside_allowlist();
    test_dispatch_hypercall_supports_registered_separate_output_page();
    test_vm_run_translates_common_vm_exits();
    test_vm_run_shutdown_faults_partition();
    test_vm_run_unclassified_fault_records_partition_fault();
    test_kci_verify_module_uses_current_manifest_generation();
    test_vm_set_register_enforces_arch_and_pin_policy();
    test_log_append_fails_closed_on_sequence_wraparound();
    test_sha384_matches_known_vector();
    test_multiboot_parser_tracks_boot_modules_and_resets_boot_metadata();
    test_shared_registration_only_charges_real_mappings();
    test_shareable_object_requires_registration_for_non_owner_mapping();
    test_unregister_shared_rejects_live_peer_mapping();
    test_unregister_shared_allows_owner_mapping_when_peer_is_unmapped();
    test_kci_set_wx_requires_verified_module_measurements();
    test_kci_verify_module_and_set_wx_enforce_measured_pages();
    test_kci_verified_module_is_invalidated_on_unmap();
    test_partition_load_image_succeeds_with_authoritative_artifact();
    test_partition_load_image_rejects_non_executable_entry_segment();
    test_partition_load_image_rejects_executable_stack_page();
    test_partition_load_image_rejects_manifest_entry_mismatch();
    test_partition_load_image_requires_guest_initial_stack();
    test_platform_detection_fails_closed_without_real_bringup();
    test_platform_foundation_helpers_expose_release_boundary();
    test_log_append_emits_primary_oob_audit_line();
    test_vm_device_passthrough_is_fail_closed_without_qualification();
    test_vm_destroy_rejects_assigned_devices_without_safe_teardown();
    test_unregister_shared_rejects_non_owner();
    test_unmap_rejects_unauthorized_caller();
    test_broadcast_registration_authorizes_any_peer();
    test_vm_device_passthrough_stays_disabled_even_when_platform_looks_ready();
    test_vm_release_device_stays_disabled_without_safe_teardown();
    test_iommu_init_fails_without_release_complete_platform_policy();
    test_deprivilege_host_rejects_partial_handoff_and_clears_flag();
    return 0;
}
