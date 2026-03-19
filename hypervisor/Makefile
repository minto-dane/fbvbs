CC ?= gcc
LD ?= ld

BUILD_DIR := build
INCLUDES := -Iinclude

COMMON_WARNINGS := -Wall -Wextra -Werror -Wpedantic \
                   -Wconversion -Wsign-conversion \
                   -Wstrict-prototypes -Wmissing-prototypes \
                   -Wshadow -Wundef -std=c11

# Security hardening: prevent compiler from optimizing away safety checks
HARDENING_FLAGS := -fno-strict-overflow \
                   -fno-delete-null-pointer-checks \
                   -fno-strict-aliasing

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
    src/boot_multiboot.c

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

ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(ALL_SOURCES))
HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host_%.o,$(ALL_SOURCES))

TEST_BINS := \
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests \
	$(BUILD_DIR)/fbvbs_policy_security_tests

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

.PHONY: all clean analyze test proof frama-c-wp

all: analyze

analyze: $(ANALYZER_OBJECTS)
	@echo "GCC -fanalyzer: all $(words $(ALL_SOURCES)) sources passed."

test: $(TEST_BINS)
	$(BUILD_DIR)/fbvbs_leaf_boundary_tests
	$(BUILD_DIR)/fbvbs_policy_security_tests

proof: frama-c-wp

frama-c-wp:
	@$(FRAMAC) -plugins | grep -q '^WP[[:space:]]' || { echo "Frama-C WP plugin is not installed in this environment."; exit 2; }
	$(FRAMAC) $(FRAMAC_WP_FLAGS) $(FRAMA_C_WP_SOURCES)

clean:
	rm -rf $(BUILD_DIR)

# ---------- build rules ----------

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/analyze_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(ANALYZER_CFLAGS) -c $< -o $@

$(BUILD_DIR)/host_%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(BUILD_DIR)/fbvbs_leaf_boundary_tests: $(BUILD_DIR)/host_vmx.o tests/test_leaf_boundary.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(BUILD_DIR)/fbvbs_policy_security_tests: $(HOST_OBJECTS) tests/test_policy_security.c | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) $^ -o $@
