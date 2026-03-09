CC ?= gcc
LD ?= ld

BUILD_DIR := build
INCLUDES := -Iinclude -I../generated/bindings
COMMON_WARNINGS := -Wall -Wextra -Werror -Wpedantic -Wconversion -Wsign-conversion -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wundef -std=c11
COMMON_SOURCES := \
	src/kernel.c \
	src/partition.c \
	src/command.c \
	src/security.c \
	src/log.c \
	src/memory.c \
	src/vm_policy.c \
	src/vmx.c

HOST_CFLAGS := $(COMMON_WARNINGS) -O2 $(INCLUDES)
BARE_CFLAGS := $(COMMON_WARNINGS) -O2 -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -mno-red-zone $(INCLUDES)
ANALYZER_CFLAGS := $(HOST_CFLAGS) -fanalyzer
ANALYZER_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/analyze_%.o,$(COMMON_SOURCES))

HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host_%.o,$(COMMON_SOURCES))
BARE_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/bare_%.o,$(COMMON_SOURCES))

TEST_BIN := $(BUILD_DIR)/fbvbs_hypervisor_tests
KERNEL_BIN := $(BUILD_DIR)/fbvbs_hypervisor.elf
BOOT_OBJECT := $(BUILD_DIR)/boot.o
GENERATED_HEADER := ../generated/bindings/fbvbs_abi_v1.h

.PHONY: all clean test analyze

all: $(GENERATED_HEADER) $(KERNEL_BIN) $(TEST_BIN)

test: $(GENERATED_HEADER) $(TEST_BIN)
	$(TEST_BIN)

analyze: $(GENERATED_HEADER) $(ANALYZER_OBJECTS)

clean:
	rm -rf $(BUILD_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(GENERATED_HEADER):
	python3 -m fbvbs_spec generate --source ../plan/fbvbs-design.md --output ../generated >/dev/null

$(BUILD_DIR)/host_%.o: src/%.c $(GENERATED_HEADER) | $(BUILD_DIR)
	$(CC) $(HOST_CFLAGS) -c $< -o $@

$(BUILD_DIR)/bare_%.o: src/%.c $(GENERATED_HEADER) | $(BUILD_DIR)
	$(CC) $(BARE_CFLAGS) -c $< -o $@

$(BUILD_DIR)/analyze_%.o: src/%.c $(GENERATED_HEADER) | $(BUILD_DIR)
	$(CC) $(ANALYZER_CFLAGS) -c $< -o $@

$(BOOT_OBJECT): src/boot.S | $(BUILD_DIR)
	$(CC) -c -x assembler-with-cpp $< -o $@

$(TEST_BIN): $(HOST_OBJECTS) tests/test_hypervisor.c
	$(CC) $(HOST_CFLAGS) $^ -o $@

$(KERNEL_BIN): $(BARE_OBJECTS) $(BOOT_OBJECT) linker.ld
	$(LD) -T linker.ld -o $@ $(BOOT_OBJECT) $(BARE_OBJECTS)
