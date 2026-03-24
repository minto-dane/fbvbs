CC ?= gcc
LD ?= ld

BUILD_DIR := build
INCLUDES := -Iinclude

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

# Frama-C WP sources: excludes memory_utils.c (void* incompatible
# with Typed+Cast model) and boot_multiboot.c (void* casts for
# Multiboot2 binary structure parsing)
FRAMA_C_WP_SOURCES := \
    src/cpu_security.c \
    src/vmx.c \
    src/memory.c \
    src/log.c \
    src/vm_policy.c \
    src/kernel.c \
    src/command.c \
    src/security.c \
    src/partition.c

# ---------- compiler flags ----------

HOST_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O2 $(INCLUDES)
ANALYZER_CFLAGS := $(HOST_CFLAGS) -fanalyzer

# UEFI uses MS ABI and CHAR16 literals; relax -Wpedantic
UEFI_CFLAGS := -Wall -Wextra -Werror -Wconversion -Wsign-conversion \
               -Wstrict-prototypes -Wmissing-prototypes \
               -Wshadow -Wundef -std=c11 \
               $(HARDENING_FLAGS) -O2 $(INCLUDES)
UEFI_ANALYZER_CFLAGS := $(UEFI_CFLAGS) -fanalyzer

ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(ALL_SOURCES))
UEFI_ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(UEFI_SOURCES))
HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host_%.o,$(ALL_SOURCES))

TEST_BINS := \
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests \
	$(BUILD_DIR)/fbvbs_policy_security_tests \
	$(BUILD_DIR)/fbvbs_fault_injection_tests

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
    -kernel-warn-key annot-error=abort \
    -cpp-extra-args="-Iinclude"

# ---------- targets ----------

.PHONY: all clean analyze test proof frama-c-wp fuzz-build coverage cppcheck traceability ci

all: analyze

analyze: $(ANALYZER_OBJECTS) $(UEFI_ANALYZER_OBJECTS)
	@echo "GCC -fanalyzer: all $(words $(ALL_SOURCES) $(UEFI_SOURCES)) sources passed."

test: $(TEST_BINS)
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests
	$(BUILD_DIR)/fbvbs_policy_security_tests
	$(BUILD_DIR)/fbvbs_fault_injection_tests

proof: frama-c-wp

frama-c-wp:
	@$(FRAMAC) -plugins | grep -q '^WP[[:space:]]' || { echo "Frama-C WP plugin is not installed in this environment."; exit 2; }
	$(FRAMAC) $(FRAMAC_WP_FLAGS) $(FRAMA_C_WP_SOURCES)

clean:
	rm -rf $(BUILD_DIR)

# ---------- build rules ----------

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# UEFI sources need relaxed flags (MS ABI, CHAR16)
$(BUILD_DIR)/analyze_uefi_entry.o: src/uefi_entry.c | $(BUILD_DIR)
	$(CC) $(UEFI_ANALYZER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/host_uefi_entry.o: src/uefi_entry.c | $(BUILD_DIR)
	$(CC) $(UEFI_CFLAGS) -c $< -o $@

$(BUILD_DIR)/analyze_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(ANALYZER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/host_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(BUILD_DIR)/fbvbs_leaf_boundary_tests: $(BUILD_DIR)/host_vmx.o tests/test_leaf_boundary.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_policy_security_tests: $(HOST_OBJECTS) tests/test_policy_security.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_fault_injection_tests: $(HOST_OBJECTS) tests/test_fault_injection.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

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

coverage: $(BUILD_DIR)/cov_policy_security_tests $(BUILD_DIR)/cov_fault_injection_tests
	$(BUILD_DIR)/cov_policy_security_tests
	$(BUILD_DIR)/cov_fault_injection_tests
	@echo "--- Branch coverage summary (security-critical files) ---"
	@cd $(BUILD_DIR) && for f in cov_partition.gcno cov_security.gcno cov_command.gcno \
		cov_log.gcno cov_vm_policy.gcno cov_watchdog.gcno cov_memory.gcno; do \
		[ -f "$$f" ] && gcov -bc "$$f" 2>/dev/null | head -4; \
	done
	@echo "--- Full .gcov files in $(BUILD_DIR)/ ---"

# ---------- reproducible build (Phase 9-3, REQ-1006) ----------
# Deterministic compilation: fixed timestamp, no debug paths, sorted inputs.
# SBOM generation: records compiler, flags, source hashes.

.PHONY: reproducible sbom

REPRO_CFLAGS := $(COMMON_WARNINGS) $(HARDENING_FLAGS) -O2 $(INCLUDES) \
                -ffile-prefix-map=$(CURDIR)=. \
                -fdebug-prefix-map=$(CURDIR)=. \
                -frandom-seed=fbvbs-v7 \
                -DFBVBS_BUILD_REPRODUCIBLE
REPRO_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/repro_%.o,$(ALL_SOURCES))

$(BUILD_DIR)/repro_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(REPRO_CFLAGS) -c $< -o $@

reproducible: $(REPRO_OBJECTS)
	@echo "Reproducible build: $(words $(REPRO_OBJECTS)) objects."
	@echo "Verifying determinism..."
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
	@echo "# Generated: $$(date -Iseconds)" >> $(BUILD_DIR)/sbom.txt
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

fuzz-build: $(BUILD_DIR)/fuzz_command_page $(BUILD_DIR)/fuzz_multiboot2 $(BUILD_DIR)/fuzz_manifest $(BUILD_DIR)/fuzz_iommu $(BUILD_DIR)/fuzz_log_decoder

$(BUILD_DIR)/fuzz_command_page: $(HOST_OBJECTS) fuzz/fuzz_command_page.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_manifest: $(HOST_OBJECTS) fuzz/fuzz_manifest.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_multiboot2: fuzz/fuzz_multiboot2.c src/boot_multiboot.c src/log.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_iommu: fuzz/fuzz_iommu.c src/iommu_vtd.c src/iommu_amdvi.c src/page_alloc.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

$(BUILD_DIR)/fuzz_log_decoder: fuzz/fuzz_log_decoder.c src/log.c src/memory_utils.c | $(BUILD_DIR)
	$(CC) $(FUZZ_CFLAGS) $^ -o $@

# ---------- CI gate (Phase 9-8, REQ-1000) ----------
# Runs all verification gates in sequence. Equivalent to the GitHub Actions pipeline.
ci: analyze test cppcheck fuzz-build coverage traceability reproducible
	@echo "CI: All gates passed."
