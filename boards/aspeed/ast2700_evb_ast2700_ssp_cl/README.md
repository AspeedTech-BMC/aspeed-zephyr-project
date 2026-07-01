# AST2700 EVB SSP Chainload Board (`ast2700_evb_ast2700_ssp_cl`)

## Overview

Chainload flow: **BootMCU → SSP mcuboot → SSP irot**

```
BootMCU flash (FLSH bundle)
  └─ entry 0x100c: ssp-mcuboot.bin   ← replaces original ssp-irot
        │
        │  BootMCU loads mcuboot to DRAM 0xac000000
        │  SSP starts executing from DRAM 0x0
        ▼
SSP mcuboot (runs from DRAM 0x0 - 0x7FFFF)
  - reads irot-signed.bin from fmc_cs0 @ 0x7A00000
  - verifies ECDSA-P256 signature
  - copies to DRAM 0x80000
  - jumps to 0x80000
        │
        ▼
SSP irot (runs from DRAM 0x80000+)
```

**Why this board exists:**  
Original flow (`ast2700_evb_ast2700_ssp`) embeds irot inside the CPTRA-signed FLSH
bundle. Any irot update requires re-signing the entire bundle. This board decouples
irot from the signed bundle: mcuboot in the bundle is stable; irot in fmc_cs0 is
updated independently with its own ECDSA-P256 signature.

## Flash Layout

```
SSP fmc_cs0 (128MB SPI NOR):
  0x0000000  FLSH bundle (ast2700-manifest-flash.bin, ~58MB)
             Contains: caliptra-fw, soc-manifest, bootmcu, DDR training,
                       ATF, OP-TEE, U-Boot, ssp-mcuboot, kernel FIT...
  ...
  0x7A00000  slot0: irot-signed.bin (2MB)   ← primary
  0x7C00000  slot1: irot-signed.bin (2MB)   ← OTA secondary
  0x7E00000  scratch (128KB)
```

## SSP DRAM Layout

```
0x00000000 - 0x0007FFFF  mcuboot code (512KB, loaded by BootMCU)
0x00080000 - 0x000FFFFF  irot code    (512KB, loaded by mcuboot)
0x00100000 - 0x001FFFFF  irot data    (1024KB)
0x00200000 -             nc region    (CPTRA IPC buffers, DMA)
```

---

## Build

### 1. Build mcuboot

```bash
west build -p always \
    -b ast2700_evb_ast2700_ssp_cl/ast2700/ssp \
    boot/zephyr \
    -- -DCONFIG_BOOT_SIGNATURE_KEY_FILE=\"root-ec-p256.pem\"

# Output: build/zephyr/zephyr.bin
```

The signing key (`root-ec-p256.pem`) is embedded at build time so mcuboot can verify irot.
For production, replace with your own ECDSA-P256 private key.

### 2. Build irot (chainload variant)

```bash
west build -p always \
    -b ast2700_evb_ast2700_ssp_cl/ast2700/ssp \
    apps/aspeed-irot

# Output: build/zephyr/zephyr.bin
```

### 3. Sign irot with imgtool

```bash
MCUBOOT_DIR=workspace/bootloader/mcuboot
IROT_BIN=workspace/aspeed-zephyr-project/build/zephyr/zephyr.bin

imgtool sign \
    --key ${MCUBOOT_DIR}/root-ec-p256.pem \
    --header-size 0x800 \
    --align 8 \
    --version 1.0.0 \
    --slot-size 0x200000 \
    --load-addr 0x80000 \
    ${IROT_BIN} \
    irot-signed.bin
```

Key must match `CONFIG_BOOT_SIGNATURE_KEY_FILE` used when building mcuboot.

- `--header-size 0x800`: irot vector table is ALIGN(0x800) in linker script
- `--load-addr 0x80000`: irot DRAM execution address
- No `--pad-header`: irot built with `CONFIG_BOOTLOADER_MCUBOOT=y` (header gap already in binary)

---

## Integration

### Flash irot to SSP fmc_cs0

Write `irot-signed.bin` to slot0 at offset `0x7A00000` of SSP fmc_cs0:
Write `irot-signed.bin` to slot1 at offset `0x7C00000` of SSP fmc_cs0:

---

## Key Files

| File | Description |
|------|-------------|
| `boot/zephyr/boards/ast2700_evb_ast2700_ssp_cl_ast2700_ssp.conf` | mcuboot Kconfig (ECDSA-P256, BOOT_RAM_LOAD, slot addresses) |
| `boot/zephyr/boards/ast2700_evb_ast2700_ssp_cl_ast2700_ssp.overlay` | mcuboot DTS (fmc_cs0 partitions, dram_ro_region) |
| `apps/aspeed-irot/boards/ast2700_evb_ast2700_ssp_cl_ast2700_ssp.conf` | irot Kconfig (CONFIG_BOOTLOADER_MCUBOOT=y) |
| `apps/aspeed-irot/boards/ast2700_evb_ast2700_ssp_cl_ast2700_ssp.overlay` | irot DTS (dram_ro_region @ 0x80000) |
| `bootloader/mcuboot/root-ec-p256.pem` | Test signing key (replace for production) |
