CC ?= gcc
LD ?= ld
AS ?= as
QEMU ?= qemu-system-x86_64

BUILD_DIR := build
INCLUDES := -Iinclude
DEPFLAGS := -MMD -MP
BOOT_ARTIFACT_IDS := 1000 1100 1200 1300 1400 1500 1600 3000 3700
BOOT_ARTIFACT_FILES := $(addprefix $(BUILD_DIR)/boot-artifacts/fbvbs-artifact-,$(addsuffix .bin,$(BOOT_ARTIFACT_IDS)))

COMMON_WARNINGS := -Wall -Wextra -Werror -Wpedantic \
                   -Wconversion -Wsign-conversion \
                   -Wstrict-prototypes -Wmissing-prototypes \
                   -Wshadow -Wundef -std=c11

# Security hardening: prevent compiler from optimizing away safety checks
# Phase 0A-4: government-grade compiler hardening
HARDENING_FLAGS := -fno-strict-overflow \
                   -fno-delete-null-pointer-checks \
                   -fno-strict-aliasing \
                   -fstack-protector-strong \
                   -fno-common \
                   -mno-red-zone \
                   -fcf-protection=full

# ---------- source sets ----------

# Sources that compile without generated bindings
CORE_SOURCES := \
    src/cpu_security.c \
    src/vmx.c \
    src/memory.c \
    src/memory_utils.c \
    src/log.c

# All sources — constants now defined in fbvbs_abi.h
ALL_SOURCES := $(CORE_SOURCES) \
    src/command.c \
    src/partition.c \
    src/security.c \
    src/kernel.c \
    src/acpi.c \
    src/vm_policy.c \
    src/boot_multiboot.c \
    src/iommu_vtd.c \
    src/iommu_amdvi.c \
    src/early_init.c \
    src/vmcs_setup.c \
    src/hlat.c \
    src/vmx_controls.c \
    src/amd_npt.c \
    src/page_alloc.c \
    src/watchdog.c \
    src/apic.c \
    src/idt.c \
    src/mp_init.c

# UEFI sources (MS ABI, separate compilation flags)
UEFI_SOURCES := src/uefi_entry.c

# Frama-C WP sources.
FRAMA_C_WP_SOURCES := \
	src/cpu_security.c \
	src/vmx.c \
	src/memory.c \
	src/memory_utils.c \
	src/freestanding_runtime.c \
	src/log.c \
	src/vm_policy.c \
	src/boot_multiboot.c \
	src/watchdog.c \
	src/early_init.c \
	src/acpi.c \
	src/apic.c \
	src/idt.c \
	src/vmx_controls.c \
	src/vmcs_setup.c \
	src/hlat.c \
	src/kernel.c \
	src/command.c \
	src/security.c \
    src/partition.c \
    src/page_alloc.c \
    src/amd_npt.c \
    src/mp_init.c

# ---------- compiler flags ----------

HOST_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O2 $(INCLUDES)
ANALYZER_CFLAGS := $(HOST_CFLAGS) -fanalyzer
BAREMETAL_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O2 $(INCLUDES) \
                    -ffreestanding -fno-pie -fno-pic -m64 -mgeneral-regs-only \
                    -DFBVBS_BAREMETAL_BUILD
BAREMETAL_LDFLAGS := -nostdlib -static -no-pie \
                     -Wl,-T,fbvbs.ld -Wl,--build-id=none

# UEFI uses MS ABI and CHAR16 literals; relax -Wpedantic
UEFI_CFLAGS := -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
               -Wstrict-prototypes -Wmissing-prototypes \
               -Wshadow -Wundef -std=c11 \
               $(HARDENING_FLAGS) -O2 $(INCLUDES)
UEFI_ANALYZER_CFLAGS := $(UEFI_CFLAGS) -fanalyzer

ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(ALL_SOURCES))
UEFI_ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(UEFI_SOURCES))
HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host_%.o,$(ALL_SOURCES))
BAREMETAL_SOURCES := $(ALL_SOURCES) src/freestanding_runtime.c
BAREMETAL_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/baremetal_%.o,$(BAREMETAL_SOURCES))
BAREMETAL_ASM_OBJECTS := $(BUILD_DIR)/baremetal_boot.o
DEPFILES := $(ANALYZER_OBJECTS:.o=.d) \
	$(UEFI_ANALYZER_OBJECTS:.o=.d) \
	$(HOST_OBJECTS:.o=.d) \
	$(BAREMETAL_OBJECTS:.o=.d)

TEST_BINS := \
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests \
	$(BUILD_DIR)/fbvbs_policy_security_tests \
	$(BUILD_DIR)/fbvbs_fault_injection_tests \
	$(BUILD_DIR)/fbvbs_vmcs_setup_tests \
	$(BUILD_DIR)/fbvbs_vmx_controls_tests \
	$(BUILD_DIR)/fbvbs_early_init_tests \
	$(BUILD_DIR)/fbvbs_iommu_tests \
	$(BUILD_DIR)/fbvbs_vmx_handoff_tests

# ---------- Frama-C ----------

FRAMAC ?= $(shell \
	if command -v opam >/dev/null 2>&1; then \
		opam exec -- which frama-c 2>/dev/null || command -v frama-c; \
	else \
		command -v frama-c; \
	fi)
FRAMAC_WP_FLAGS := \
    -wp \
    -wp-model 'Typed+Cast' \
    -wp-rte \
    -kernel-warn-key annot-error=abort \
    -cpp-extra-args="-D__FRAMAC__ -Iinclude"
PROOF_SHARD_TIMEOUT ?= 1200
QEMU_MATRIX_SCRIPT := tools/qemu_smoke_matrix.py

# ---------- targets ----------

.PHONY: all clean analyze test proof frama-c-wp proof-smoke proof-shards fuzz-build fuzz-smoke coverage coverage-clean cppcheck traceability ci baremetal-elf baremetal-iso verify-baremetal-iso run-qemu-smoke run-qemu-kvm-smoke run-qemu-iommu-smoke run-qemu-matrix provenance sign-release release-readiness release-manifest release-evidence release-hypervisor

all: analyze

analyze: $(ANALYZER_OBJECTS) $(UEFI_ANALYZER_OBJECTS)
	@echo "GCC -fanalyzer: all $(words $(ALL_SOURCES) $(UEFI_SOURCES)) sources passed."

test: $(TEST_BINS)
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests
	$(BUILD_DIR)/fbvbs_policy_security_tests
	$(BUILD_DIR)/fbvbs_fault_injection_tests
	$(BUILD_DIR)/fbvbs_vmcs_setup_tests
	$(BUILD_DIR)/fbvbs_vmx_controls_tests
	$(BUILD_DIR)/fbvbs_early_init_tests
	$(BUILD_DIR)/fbvbs_iommu_tests
	$(BUILD_DIR)/fbvbs_vmx_handoff_tests

proof: frama-c-wp

frama-c-wp:
	@$(FRAMAC) -plugins | grep -q '^WP[[:space:]]' || { echo "Frama-C WP plugin is not installed in this environment."; exit 2; }
	$(FRAMAC) $(FRAMAC_WP_FLAGS) $(FRAMA_C_WP_SOURCES)

proof-smoke: | $(BUILD_DIR)
	@$(FRAMAC) -plugins | grep -q '^WP[[:space:]]' || { echo "Frama-C WP plugin is not installed in this environment."; exit 2; }
	rm -f $(BUILD_DIR)/proof-smoke.log
	timeout 90s $(FRAMAC) $(FRAMAC_WP_FLAGS) $(FRAMA_C_WP_SOURCES) \
		> $(BUILD_DIR)/proof-smoke.log 2>&1; \
	status=$$?; \
	test -f $(BUILD_DIR)/proof-smoke.log || { echo "proof-smoke log was not created"; exit 1; }; \
	cat $(BUILD_DIR)/proof-smoke.log; \
	if [ $$status -ne 0 ] && [ $$status -ne 124 ]; then \
		exit $$status; \
	fi; \
	grep -q "\\[wp\\].*Running WP plugin" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "annot-error" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "User Error" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "No default assigns clause" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "No code nor implicit assigns clause" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "Missing specification" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "Cast with incompatible pointers types" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "Missing RTE guards" $(BUILD_DIR)/proof-smoke.log || exit 1; \
	! grep -q "\\[kernel:asm:clobber\\]" $(BUILD_DIR)/proof-smoke.log || exit 1

proof-shards: | $(BUILD_DIR)
	@$(FRAMAC) -plugins | grep -q '^WP[[:space:]]' || { echo "Frama-C WP plugin is not installed in this environment."; exit 2; }
	rm -rf $(BUILD_DIR)/proof-shards
	mkdir -p $(BUILD_DIR)/proof-shards
	: > $(BUILD_DIR)/proof-shards-summary.txt
	@set -e; \
	for src in $(FRAMA_C_WP_SOURCES); do \
		base=$$(basename "$$src" .c); \
		log="$(BUILD_DIR)/proof-shards/$$base.log"; \
		set +e; \
		timeout $(PROOF_SHARD_TIMEOUT)s $(FRAMAC) $(FRAMAC_WP_FLAGS) "$$src" > "$$log" 2>&1; \
		status=$$?; \
		set -e; \
		test -f "$$log" || { echo "proof-shard log was not created: $$log"; exit 1; }; \
		grep -q "\\[wp\\].*Running WP plugin" "$$log" || exit 1; \
		! grep -q "annot-error" "$$log" || exit 1; \
		! grep -q "User Error" "$$log" || exit 1; \
		! grep -q "No default assigns clause" "$$log" || exit 1; \
		! grep -q "No code nor implicit assigns clause" "$$log" || exit 1; \
		! grep -q "Missing specification" "$$log" || exit 1; \
		! grep -q "Missing RTE guards" "$$log" || exit 1; \
		! grep -q "\\[kernel:asm:clobber\\]" "$$log" || exit 1; \
		! grep -q "\\[Timeout\\]" "$$log" || { echo "FAIL: $$base has WP timeouts"; exit 1; }; \
		goals=$$(awk '/Computing \[/{gsub(/.*Computing \[/,""); gsub(/ goals.*/,""); print}' "$$log" | tail -n 1); \
		if [ -z "$$goals" ]; then goals=0; fi; \
		printf "%s status=%s goals=%s log=%s\n" "$$base" "$$status" "$$goals" "$$log" >> $(BUILD_DIR)/proof-shards-summary.txt; \
		if [ $$status -ne 0 ]; then \
			echo "FAIL: $$base exited with status $$status"; exit $$status; \
		fi; \
	done
	cat $(BUILD_DIR)/proof-shards-summary.txt

clean:
	rm -rf $(BUILD_DIR)

# ---------- build rules ----------

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# UEFI sources need relaxed flags (MS ABI, CHAR16)
$(BUILD_DIR)/analyze_uefi_entry.o: src/uefi_entry.c | $(BUILD_DIR)
	$(CC) $(UEFI_ANALYZER_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/host_uefi_entry.o: src/uefi_entry.c | $(BUILD_DIR)
	$(CC) $(UEFI_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/analyze_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(ANALYZER_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/host_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/baremetal_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(BAREMETAL_CFLAGS) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIR)/baremetal_boot.o: src/boot.S | $(BUILD_DIR)
	$(AS) --64 $< -o $@

$(BUILD_DIR)/gen_boot_artifacts: tools/gen_boot_artifacts.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $< -o $@

$(BUILD_DIR)/fbvbs_leaf_boundary_tests: $(BUILD_DIR)/host_vmx.o tests/test_leaf_boundary.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_policy_security_tests: $(HOST_OBJECTS) tests/test_policy_security.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_fault_injection_tests: $(HOST_OBJECTS) tests/test_fault_injection.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_vmcs_setup_tests: $(HOST_OBJECTS) tests/test_vmcs_setup.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_vmx_controls_tests: $(HOST_OBJECTS) tests/test_vmx_controls.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_early_init_tests: $(HOST_OBJECTS) tests/test_early_init.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_iommu_tests: $(HOST_OBJECTS) tests/test_iommu.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_vmx_handoff_tests: $(HOST_OBJECTS) tests/test_vmx_handoff.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

-include $(DEPFILES)

$(BUILD_DIR)/fbvbs-baremetal.elf: $(BAREMETAL_ASM_OBJECTS) $(BAREMETAL_OBJECTS) | $(BUILD_DIR)
	$(CC) $(BAREMETAL_LDFLAGS) $^ -o $@

baremetal-elf: $(BUILD_DIR)/fbvbs-baremetal.elf

$(BUILD_DIR)/boot-artifacts.stamp: $(BUILD_DIR)/gen_boot_artifacts | $(BUILD_DIR)
	rm -rf $(BUILD_DIR)/boot-artifacts
	mkdir -p $(BUILD_DIR)/boot-artifacts
	$(BUILD_DIR)/gen_boot_artifacts $(BUILD_DIR)/boot-artifacts
	touch $@

$(BOOT_ARTIFACT_FILES): $(BUILD_DIR)/boot-artifacts.stamp

$(BUILD_DIR)/fbvbs-baremetal.iso: $(BUILD_DIR)/fbvbs-baremetal.elf grub/grub.cfg $(BUILD_DIR)/boot-artifacts.stamp | $(BUILD_DIR)
	rm -rf $(BUILD_DIR)/iso
	mkdir -p $(BUILD_DIR)/iso/boot/grub
	cp $(BUILD_DIR)/fbvbs-baremetal.elf $(BUILD_DIR)/iso/boot/fbvbs-baremetal.elf
	cp $(BOOT_ARTIFACT_FILES) $(BUILD_DIR)/iso/boot/
	cp grub/grub.cfg $(BUILD_DIR)/iso/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(BUILD_DIR)/iso >/dev/null

baremetal-iso: $(BUILD_DIR)/fbvbs-baremetal.iso

verify-baremetal-iso: $(BUILD_DIR)/fbvbs-baremetal.iso
	xorriso -indev $(BUILD_DIR)/fbvbs-baremetal.iso \
		-find /boot -type f -exec report_lba \
		> $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-baremetal.elf" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1000.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1100.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1200.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1300.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1400.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1500.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-1600.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-3000.bin" $(BUILD_DIR)/iso-file-list.txt
	grep -q "/boot/fbvbs-artifact-3700.bin" $(BUILD_DIR)/iso-file-list.txt

run-qemu-smoke: $(BUILD_DIR)/fbvbs-baremetal.iso
	python3 $(QEMU_MATRIX_SCRIPT) \
		--build-dir $(BUILD_DIR) \
		--iso $(BUILD_DIR)/fbvbs-baremetal.iso \
		--logs-dir $(BUILD_DIR)/qemu-smoke-logs \
		--output $(BUILD_DIR)/qemu-smoke-summary.txt \
		--case tcg-intel-iommu \
		--require-pass tcg-intel-iommu \
		--alias-log $(BUILD_DIR)/qemu-smoke.log

run-qemu-kvm-smoke: $(BUILD_DIR)/fbvbs-baremetal.iso
	python3 $(QEMU_MATRIX_SCRIPT) \
		--build-dir $(BUILD_DIR) \
		--iso $(BUILD_DIR)/fbvbs-baremetal.iso \
		--logs-dir $(BUILD_DIR)/qemu-smoke-logs \
		--output $(BUILD_DIR)/qemu-kvm-smoke-summary.txt \
		--case kvm-intel-iommu \
		--require-pass kvm-intel-iommu \
		--require-available kvm-intel-iommu \
		--alias-log $(BUILD_DIR)/qemu-kvm-smoke.log

run-qemu-iommu-smoke: $(BUILD_DIR)/fbvbs-baremetal.iso
	python3 $(QEMU_MATRIX_SCRIPT) \
		--build-dir $(BUILD_DIR) \
		--iso $(BUILD_DIR)/fbvbs-baremetal.iso \
		--logs-dir $(BUILD_DIR)/qemu-smoke-logs \
		--output $(BUILD_DIR)/qemu-iommu-summary.txt \
		--case tcg-intel-iommu \
		--case tcg-amd-iommu \
		--require-pass tcg-intel-iommu \
		--require-pass tcg-amd-iommu

run-qemu-matrix: $(BUILD_DIR)/fbvbs-baremetal.iso
	python3 $(QEMU_MATRIX_SCRIPT) \
		--build-dir $(BUILD_DIR) \
		--iso $(BUILD_DIR)/fbvbs-baremetal.iso \
		--logs-dir $(BUILD_DIR)/qemu-smoke-logs \
		--output $(BUILD_DIR)/qemu-matrix-summary.txt \
		--case tcg-intel-iommu \
		--case tcg-amd-iommu \
		--case kvm-intel-iommu \
		--require-pass tcg-intel-iommu \
		--require-pass tcg-amd-iommu

provenance: reproducible sbom | $(BUILD_DIR)
	python3 tools/generate_provenance.py --build-dir $(BUILD_DIR) --output $(BUILD_DIR)/provenance.json

sign-release: release-manifest release-evidence | $(BUILD_DIR)
	@test -n "$$FBVBS_RELEASE_SIGNING_KEY" || { echo "ERROR: set FBVBS_RELEASE_SIGNING_KEY to a PEM private key path"; exit 1; }
	python3 tools/sign_release_artifacts.py --build-dir $(BUILD_DIR) --key "$$FBVBS_RELEASE_SIGNING_KEY" $${FBVBS_RELEASE_SIGNING_CERT:+--cert "$$FBVBS_RELEASE_SIGNING_CERT"}

release-readiness: fuzz-smoke reproducible sbom provenance proof-smoke proof-shards baremetal-iso verify-baremetal-iso run-qemu-smoke run-qemu-iommu-smoke run-qemu-matrix | $(BUILD_DIR)
	python3 tools/release_readiness.py --build-dir $(BUILD_DIR) --output $(BUILD_DIR)/release-readiness.json

release-manifest: fuzz-smoke reproducible sbom provenance proof-smoke proof-shards baremetal-iso verify-baremetal-iso run-qemu-smoke run-qemu-iommu-smoke run-qemu-matrix release-readiness | $(BUILD_DIR)
	@printf "FBVBS retained-C release manifest\n" > $(BUILD_DIR)/release-manifest.txt
	@printf "Generated: %s\n" "$$(date -u -Iseconds)" >> $(BUILD_DIR)/release-manifest.txt
	@printf "Git HEAD: %s\n" "$$(git rev-parse HEAD 2>/dev/null || echo unknown)" >> $(BUILD_DIR)/release-manifest.txt
	@printf "\nArtifacts:\n" >> $(BUILD_DIR)/release-manifest.txt
	@for f in \
		$(BUILD_DIR)/fbvbs-baremetal.elf \
		$(BUILD_DIR)/fbvbs-baremetal.iso \
		$(BUILD_DIR)/iso-file-list.txt \
		$(BUILD_DIR)/qemu-smoke.log \
		$(BUILD_DIR)/qemu-smoke-summary.txt \
		$(BUILD_DIR)/qemu-iommu-summary.txt \
		$(BUILD_DIR)/qemu-matrix-summary.txt \
		$(BUILD_DIR)/fuzz-smoke.txt \
		$(BUILD_DIR)/proof-smoke.log \
		$(BUILD_DIR)/proof-shards-summary.txt \
		$(BUILD_DIR)/provenance.json \
		$(BUILD_DIR)/release-readiness.json \
		$(BUILD_DIR)/sbom.txt \
		$(BUILD_DIR)/repro_manifest_1.sha256 \
		$(BUILD_DIR)/repro_manifest_2.sha256; do \
		if [ -f "$$f" ]; then \
			printf "%s  %s\n" "$$(sha256sum "$$f" | cut -d' ' -f1)" "$$f" >> $(BUILD_DIR)/release-manifest.txt; \
		else \
			printf "MISSING  %s\n" "$$f" >> $(BUILD_DIR)/release-manifest.txt; \
			exit 1; \
		fi; \
	done
	@echo "Release manifest written to $(BUILD_DIR)/release-manifest.txt"

release-evidence: release-manifest | $(BUILD_DIR)
	python3 tools/release_evidence_bundle.py --build-dir $(BUILD_DIR) --output $(BUILD_DIR)/release-evidence.tar.gz

release-hypervisor:
	@$(MAKE) clean
	@$(MAKE) analyze test cppcheck fuzz-build fuzz-smoke coverage traceability reproducible sbom proof-smoke proof-shards baremetal-iso verify-baremetal-iso run-qemu-smoke run-qemu-iommu-smoke run-qemu-matrix
	@$(MAKE) provenance
	@$(MAKE) release-manifest
	@$(MAKE) release-evidence
	@echo "Standalone retained-C microhypervisor foundation gates passed; formal proof and release blockers are tracked separately."

# ---------- traceability (Phase 9-1, REQ-1000) ----------
traceability:
	python3 tools/traceability_matrix.py

# ---------- cppcheck static analysis (Phase 9-1, MISRA C evidence) ----------
# Runs cppcheck with all checks. 0 errors/warnings expected.
# Style findings are suppressed (const params in dispatch handlers,
# unused API functions called from asm/external code, model code conditions).

CPPCHECK_SOURCES := $(ALL_SOURCES) $(UEFI_SOURCES)

cppcheck:
	cppcheck --enable=warning,performance,portability --std=c11 \
		--suppress=missingIncludeSystem --suppress=unusedFunction \
		-Iinclude --force --quiet --error-exitcode=1 \
		$(CPPCHECK_SOURCES)
	@echo "cppcheck: 0 errors/warnings on $(words $(CPPCHECK_SOURCES)) sources."

# ---------- coverage (Phase 9-1, REQ-1005 MC/DC) ----------
# Builds all tests with gcov instrumentation and runs them to produce
# .gcda/.gcno files. Use `gcov -bc build/cov_*.gcno` for branch coverage.
# For HTML reports: lcov + genhtml (if available).

COV_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O0 -g \
              --coverage -fprofile-arcs -ftest-coverage $(INCLUDES)
COV_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/cov_%.o,$(ALL_SOURCES))

$(BUILD_DIR)/cov_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) -c $< -o $@

$(BUILD_DIR)/cov_policy_security_tests: $(COV_OBJECTS) tests/test_policy_security.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_fault_injection_tests: $(COV_OBJECTS) tests/test_fault_injection.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_leaf_boundary_tests: $(BUILD_DIR)/cov_vmx.o tests/test_leaf_boundary.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_vmcs_setup_tests: $(COV_OBJECTS) tests/test_vmcs_setup.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_vmx_controls_tests: $(COV_OBJECTS) tests/test_vmx_controls.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_early_init_tests: $(COV_OBJECTS) tests/test_early_init.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_iommu_tests: $(COV_OBJECTS) tests/test_iommu.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

$(BUILD_DIR)/cov_vmx_handoff_tests: $(COV_OBJECTS) tests/test_vmx_handoff.c | $(BUILD_DIR)
	$(CC) $(COV_CFLAGS) $^ -o $@ -lgcov

COV_TEST_BINS := \
	$(BUILD_DIR)/cov_leaf_boundary_tests \
	$(BUILD_DIR)/cov_policy_security_tests \
	$(BUILD_DIR)/cov_fault_injection_tests \
	$(BUILD_DIR)/cov_vmcs_setup_tests \
	$(BUILD_DIR)/cov_vmx_controls_tests \
	$(BUILD_DIR)/cov_early_init_tests \
	$(BUILD_DIR)/cov_iommu_tests \
	$(BUILD_DIR)/cov_vmx_handoff_tests

coverage-clean:
	rm -f $(BUILD_DIR)/cov_* $(BUILD_DIR)/*.gcda $(BUILD_DIR)/*.gcno $(BUILD_DIR)/*.gcov

coverage: coverage-clean $(COV_TEST_BINS)
	$(BUILD_DIR)/cov_leaf_boundary_tests
	$(BUILD_DIR)/cov_policy_security_tests
	$(BUILD_DIR)/cov_fault_injection_tests
	$(BUILD_DIR)/cov_vmcs_setup_tests
	$(BUILD_DIR)/cov_vmx_controls_tests
	$(BUILD_DIR)/cov_early_init_tests
	$(BUILD_DIR)/cov_iommu_tests
	$(BUILD_DIR)/cov_vmx_handoff_tests
	@echo "--- Branch coverage summary (security-critical files) ---"
	@cd $(BUILD_DIR) && for f in cov_partition.gcno cov_security.gcno cov_command.gcno \
		cov_log.gcno cov_vm_policy.gcno cov_vmx.gcno cov_watchdog.gcno cov_memory.gcno \
		cov_vmcs_setup.gcno cov_vmx_controls.gcno cov_early_init.gcno \
		cov_iommu_vtd.gcno cov_iommu_amdvi.gcno cov_kernel.gcno; do \
		[ -f "$$f" ] && gcov -bc "$$f" 2>/dev/null | head -4; \
	done
	@echo "--- Regression gate: no 0% line coverage on core modules ---"
	@cd $(BUILD_DIR) && fail=0; \
	for f in cov_command.gcno cov_vm_policy.gcno cov_vmx.gcno \
		cov_vmcs_setup.gcno cov_vmx_controls.gcno cov_kernel.gcno \
		cov_iommu_vtd.gcno cov_iommu_amdvi.gcno; do \
		[ -f "$$f" ] || continue; \
		summary=$$(gcov -bc "$$f" 2>/dev/null | head -4); \
		if echo "$$summary" | grep -q "Lines executed:0.00%"; then \
			echo "FAIL: $$f has 0% line coverage"; fail=1; \
		fi; \
	done; \
	if [ $$fail -ne 0 ]; then exit 1; fi
	@echo "--- Full .gcov files in $(BUILD_DIR)/ ---"

# ---------- reproducible build (Phase 9-3, REQ-1006) ----------
# Deterministic compilation: fixed timestamp, no debug paths, sorted inputs.
# SBOM generation: records compiler, flags, source hashes.

.PHONY: reproducible sbom framac-sync check-grub-cfg

REPRO_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O2 $(INCLUDES) \
                -ffile-prefix-map=$(CURDIR)=. \
                -fdebug-prefix-map=$(CURDIR)=. \
                -frandom-seed=fbvbs-v7 \
                -DFBVBS_BUILD_REPRODUCIBLE
REPRO_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/repro_%.o,$(ALL_SOURCES))

$(BUILD_DIR)/repro_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(REPRO_CFLAGS) -c $< -o $@

reproducible: | $(BUILD_DIR)
	@echo "Reproducible build: $(words $(REPRO_OBJECTS)) objects."
	@echo "Verifying determinism..."
	@rm -f $(REPRO_OBJECTS)
	@for src in $(ALL_SOURCES); do \
		obj=$(BUILD_DIR)/repro_$$(basename $$src .c).o; \
		$(CC) $(REPRO_CFLAGS) -c $$src -o $$obj; \
	done
	@sha256sum $(REPRO_OBJECTS) | sort > $(BUILD_DIR)/repro_manifest_1.sha256
	@rm -f $(REPRO_OBJECTS)
	@for src in $(ALL_SOURCES); do \
		obj=$(BUILD_DIR)/repro_$$(basename $$src .c).o; \
		$(CC) $(REPRO_CFLAGS) -c $$src -o $$obj; \
	done
	@sha256sum $(REPRO_OBJECTS) | sort > $(BUILD_DIR)/repro_manifest_2.sha256
	@if diff -q $(BUILD_DIR)/repro_manifest_1.sha256 $(BUILD_DIR)/repro_manifest_2.sha256 > /dev/null 2>&1; then \
		echo "PASS: Build is deterministic ($(words $(REPRO_OBJECTS)) objects identical)."; \
	else \
		echo "FAIL: Build is NOT deterministic. Differing objects:"; \
		diff $(BUILD_DIR)/repro_manifest_1.sha256 $(BUILD_DIR)/repro_manifest_2.sha256; \
		exit 1; \
	fi

sbom: $(REPRO_OBJECTS)
	@echo "# FBVBS SBOM (Software Bill of Materials)" > $(BUILD_DIR)/sbom.txt
	@echo "# Generated: $$(if [ -n "$$SOURCE_DATE_EPOCH" ]; then date -u -d "@$$SOURCE_DATE_EPOCH" -Iseconds; else git log -1 --format=%cI 2>/dev/null || date -u -Iseconds; fi)" >> $(BUILD_DIR)/sbom.txt
	@echo "" >> $(BUILD_DIR)/sbom.txt
	@echo "## Build Environment" >> $(BUILD_DIR)/sbom.txt
	@echo "Compiler: $$($(CC) --version | head -1)" >> $(BUILD_DIR)/sbom.txt
	@echo "Architecture: $$(uname -m)" >> $(BUILD_DIR)/sbom.txt
	@echo "Kernel: $$(uname -r)" >> $(BUILD_DIR)/sbom.txt
	@echo "CFLAGS: $(REPRO_CFLAGS)" >> $(BUILD_DIR)/sbom.txt
	@echo "" >> $(BUILD_DIR)/sbom.txt
	@echo "## Source Hashes (SHA-256)" >> $(BUILD_DIR)/sbom.txt
	@sha256sum $(ALL_SOURCES) >> $(BUILD_DIR)/sbom.txt
	@sha256sum include/*.h >> $(BUILD_DIR)/sbom.txt
	@echo "" >> $(BUILD_DIR)/sbom.txt
	@echo "## Object Hashes (SHA-256)" >> $(BUILD_DIR)/sbom.txt
	@sha256sum $(REPRO_OBJECTS) | sort >> $(BUILD_DIR)/sbom.txt
	@echo "SBOM written to $(BUILD_DIR)/sbom.txt"

# ---------- fuzz targets (Phase 9-1) ----------
# Build standalone fuzz harnesses for manual testing / crash replay.
# For AFL++: replace CC with afl-gcc-fast and add -fsanitize=address,undefined
# For libFuzzer: use clang with -fsanitize=fuzzer,address,undefined -DFUZZ_LIBFUZZER

FUZZ_CFLAGS := $(COMMON_WARNINGS) -O1 -g $(INCLUDES) -DFUZZ_TARGET \
               -Wno-missing-prototypes

fuzz-build: $(BUILD_DIR)/fuzz_command_page $(BUILD_DIR)/fuzz_multiboot2 $(BUILD_DIR)/fuzz_manifest $(BUILD_DIR)/fuzz_iommu $(BUILD_DIR)/fuzz_log_decoder $(BUILD_DIR)/fuzz_partition_loader

fuzz-smoke: fuzz-build | $(BUILD_DIR)
	python3 tools/fuzz_smoke.py --build-dir $(BUILD_DIR) --output $(BUILD_DIR)/fuzz-smoke.txt

$(BUILD_DIR)/fuzz_command_page: $(HOST_OBJECTS) fuzz/fuzz_command_page.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_manifest: $(HOST_OBJECTS) fuzz/fuzz_manifest.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_multiboot2: fuzz/fuzz_multiboot2.c src/boot_multiboot.c src/log.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_iommu: fuzz/fuzz_iommu.c src/iommu_vtd.c src/iommu_amdvi.c src/acpi.c src/page_alloc.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_log_decoder: fuzz/fuzz_log_decoder.c src/log.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_partition_loader: $(HOST_OBJECTS) fuzz/fuzz_partition_loader.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

# ---------- fuzz campaign (Phase 9-1, REQ-1004) ----------
# Fuzz campaign with crash triage.  --duration is in seconds (60s CI smoke).

fuzz-campaign: fuzz-build
	bash tools/fuzz_campaign.sh --duration 60 --output-dir $(BUILD_DIR)/fuzz-campaign

fuzz-triage: fuzz-campaign
	bash tools/fuzz_triage.sh --campaign-dir $(BUILD_DIR)/fuzz-campaign

# ---------- __FRAMAC__ stub sync check ----------
# Detects drift between __FRAMAC__ stubs and production code.
framac-sync:
	python3 tools/check_framac_stubs.py --strict

# ---------- grub.cfg placeholder rejection ----------
# Rejects any grub.cfg that still contains PLACEHOLDER_ tokens.
check-grub-cfg:
	@if grep -v '^[[:space:]]*#' grub/grub.cfg | grep -q 'PLACEHOLDER_'; then \
		echo "ERROR: grub/grub.cfg contains PLACEHOLDER_ token(s) in active lines."; \
		echo "       Replace with a real hash from: grub-mkpasswd-pbkdf2 --iteration-count=100000"; \
		grep -n 'PLACEHOLDER_' grub/grub.cfg | grep -v '^[[:space:]]*[0-9]*:[[:space:]]*#'; \
		exit 1; \
	fi
	@echo "check-grub-cfg: no placeholder tokens found."

# ---------- CI gate (Phase 9-8, REQ-1000) ----------
# Runs all verification gates in sequence. Equivalent to the GitHub Actions pipeline.
ci: analyze test cppcheck fuzz-build fuzz-smoke coverage traceability reproducible sbom provenance framac-sync check-grub-cfg
	@echo "CI: All gates passed."
