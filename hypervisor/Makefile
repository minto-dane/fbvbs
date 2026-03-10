CC ?= gcc
LD ?= ld

BUILD_DIR := build
INCLUDES := -Iinclude -I../generated/bindings
COMMON_WARNINGS := -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wundef -std=c11
LEAF_SOURCES := src/vmx.c
RETAINED_C_CHECK := python3 tools/check_retained_c_subset.py
RETAINED_C_PROOF := python3 tools/prove_leaf_vmx_contracts.py

HOST_CFLAGS := $(COMMON_WARNINGS) -O2 $(INCLUDES)
ANALYZER_CFLAGS := $(HOST_CFLAGS) -fanalyzer
ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(LEAF_SOURCES))

HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host_%.o,$(LEAF_SOURCES))

TEST_BIN := $(BUILD_DIR)/fbvbs_leaf_boundary_tests
GENERATED_HEADER := ../generated/bindings/fbvbs_abi_v1.h

.PHONY: all clean test analyze proof check-retained-c

all: $(GENERATED_HEADER) $(TEST_BIN)

test: $(GENERATED_HEADER) $(TEST_BIN)
	$(RETAINED_C_CHECK)
	$(TEST_BIN)
	$(RETAINED_C_PROOF)

analyze: $(GENERATED_HEADER) $(ANALYZER_OBJECTS)
	$(RETAINED_C_CHECK)

proof: $(GENERATED_HEADER)
	$(RETAINED_C_CHECK)
	$(RETAINED_C_PROOF)

check-retained-c: $(GENERATED_HEADER)
	$(RETAINED_C_CHECK)

clean:
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(GENERATED_HEADER):
	python3 -m fbvbs_spec generate --source ../plan/fbvbs-design.md --output ../generated >/dev/null

$(BUILD_DIR)/host_%.o: src/%.c $(GENERATED_HEADER) | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(BUILD_DIR)/analyze_%.o: src/%.c $(GENERATED_HEADER) | $(BUILD_DIR)
	$(CC) $(ANALYZER_CFLAGS) -c $< -o $@

$(TEST_BIN): $(HOST_OBJECTS) tests/test_leaf_boundary.c
	$(CC) $(HOST_CFLAGS) $^ -o $@
