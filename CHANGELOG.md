# Changelog

## Unreleased

- Added a standalone Multiboot2 bare-metal build and QEMU smoke path for the microhypervisor.
- Added freestanding runtime support, ACPI table discovery, and GRUB ISO packaging.
- Hardened the boot path against accidental NX reapplication over `.text`.
- Documented the standalone hypervisor release boundary separately from the wider FBVBS stack.
