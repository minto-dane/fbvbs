#include "fbvbs_hypervisor.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FBVBS_GENERATED_BOOT_IMAGE_SIZE FBVBS_PAGE_SIZE
#define FBVBS_GENERATED_BOOT_MODULE_SIZE FBVBS_PAGE_SIZE
#define FBVBS_ELF_ET_EXEC 2U
#define FBVBS_ELF_EM_X86_64 62U
#define FBVBS_ELF_PT_LOAD 1U
#define FBVBS_ELF_PF_X 0x1U
#define FBVBS_ELF_PF_R 0x4U
#define FBVBS_ELF_SYNTHETIC_CODE_OFFSET 0x100U
#define FBVBS_ELF_SYNTHETIC_CODE_SIZE 0x40U

struct fbvbs_generated_boot_artifact {
    uint64_t object_id;
    uint32_t object_kind;
    uint64_t entry_ip;
};

struct fbvbs_generated_elf64_ehdr {
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

struct fbvbs_generated_elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

static const struct fbvbs_generated_boot_artifact g_generated_boot_artifacts[] = {
    {0x1000U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x400000U},
    {0x1100U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x401000U},
    {0x1200U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x402000U},
    {0x1300U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x403000U},
    {0x1400U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x500000U},
    {0x1500U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x501000U},
    {0x1600U, FBVBS_ARTIFACT_OBJECT_IMAGE, 0x404000U},
    {0x3000U, FBVBS_ARTIFACT_OBJECT_MODULE, 0U},
    {0x3700U, FBVBS_ARTIFACT_OBJECT_MODULE, 0U},
};

static void build_synthetic_boot_image(
    uint8_t buffer[FBVBS_GENERATED_BOOT_IMAGE_SIZE],
    uint64_t object_id,
    uint64_t entry_ip
)
{
    struct fbvbs_generated_elf64_ehdr ehdr;
    struct fbvbs_generated_elf64_phdr phdr;
    uint32_t index;

    memset(buffer, 0, FBVBS_GENERATED_BOOT_IMAGE_SIZE);
    memset(&ehdr, 0, sizeof(ehdr));
    memset(&phdr, 0, sizeof(phdr));

    ehdr.e_ident[0] = 0x7FU;
    ehdr.e_ident[1] = (uint8_t)'E';
    ehdr.e_ident[2] = (uint8_t)'L';
    ehdr.e_ident[3] = (uint8_t)'F';
    ehdr.e_ident[4] = 2U;
    ehdr.e_ident[5] = 1U;
    ehdr.e_ident[6] = 1U;
    ehdr.e_type = FBVBS_ELF_ET_EXEC;
    ehdr.e_machine = FBVBS_ELF_EM_X86_64;
    ehdr.e_version = 1U;
    ehdr.e_entry = entry_ip;
    ehdr.e_phoff = sizeof(struct fbvbs_generated_elf64_ehdr);
    ehdr.e_ehsize = (uint16_t)sizeof(struct fbvbs_generated_elf64_ehdr);
    ehdr.e_phentsize = (uint16_t)sizeof(struct fbvbs_generated_elf64_phdr);
    ehdr.e_phnum = 1U;

    phdr.p_type = FBVBS_ELF_PT_LOAD;
    phdr.p_flags = FBVBS_ELF_PF_R | FBVBS_ELF_PF_X;
    phdr.p_offset = FBVBS_ELF_SYNTHETIC_CODE_OFFSET;
    phdr.p_vaddr = entry_ip;
    phdr.p_paddr = entry_ip;
    phdr.p_filesz = FBVBS_ELF_SYNTHETIC_CODE_SIZE;
    phdr.p_memsz = FBVBS_PAGE_SIZE;
    phdr.p_align = FBVBS_PAGE_SIZE;

    memcpy(buffer, &ehdr, sizeof(ehdr));
    memcpy(
        &buffer[sizeof(struct fbvbs_generated_elf64_ehdr)],
        &phdr,
        sizeof(phdr)
    );

    for (index = 0U; index < FBVBS_ELF_SYNTHETIC_CODE_SIZE; ++index) {
        buffer[FBVBS_ELF_SYNTHETIC_CODE_OFFSET + index] =
            (uint8_t)(0x90U + (uint8_t)((object_id + index) & 0x0FU));
    }
}

static void build_synthetic_module_payload(
    uint8_t buffer[FBVBS_GENERATED_BOOT_MODULE_SIZE],
    uint64_t object_id
)
{
    uint32_t index;

    for (index = 0U; index < FBVBS_GENERATED_BOOT_MODULE_SIZE; ++index) {
        buffer[index] = (uint8_t)(((object_id >> (index % 8U)) + index) & 0xFFU);
    }
}

static int write_artifact_file(
    const char *output_dir,
    const struct fbvbs_generated_boot_artifact *artifact
)
{
    char path[512];
    FILE *file;
    int written;

    if (output_dir == NULL || artifact == NULL) {
        return -1;
    }

    written = snprintf(
        path,
        sizeof(path),
        "%s/fbvbs-artifact-%04llx.bin",
        output_dir,
        (unsigned long long)artifact->object_id
    );
    if (written <= 0 || (size_t)written >= sizeof(path)) {
        return -1;
    }

    file = fopen(path, "wb");
    if (file == NULL) {
        fprintf(stderr, "failed to open %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (artifact->object_kind == FBVBS_ARTIFACT_OBJECT_IMAGE) {
        uint8_t buffer[FBVBS_GENERATED_BOOT_IMAGE_SIZE];

        build_synthetic_boot_image(buffer, artifact->object_id, artifact->entry_ip);
        if (fwrite(buffer, sizeof(buffer), 1U, file) != 1U) {
            fprintf(stderr, "failed to write %s\n", path);
            fclose(file);
            return -1;
        }
    } else if (artifact->object_kind == FBVBS_ARTIFACT_OBJECT_MODULE) {
        uint8_t buffer[FBVBS_GENERATED_BOOT_MODULE_SIZE];

        build_synthetic_module_payload(buffer, artifact->object_id);
        if (fwrite(buffer, sizeof(buffer), 1U, file) != 1U) {
            fprintf(stderr, "failed to write %s\n", path);
            fclose(file);
            return -1;
        }
    } else {
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "failed to close %s: %s\n", path, strerror(errno));
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    uint32_t index;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <output-dir>\n", argv[0]);
        return 1;
    }

    for (index = 0U;
         index < (uint32_t)(sizeof(g_generated_boot_artifacts) /
                            sizeof(g_generated_boot_artifacts[0]));
         ++index) {
        if (write_artifact_file(argv[1], &g_generated_boot_artifacts[index]) != 0) {
            return 1;
        }
    }

    return 0;
}
