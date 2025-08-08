# Intel PFR Firmware Signing and Capsule Generation Guide (Intel PFR / BHS)

This guide describes how to use Intel's **`intel-server-prot-spdm`** tools to build, sign, and generate various Intel PFR firmware capsules — including **AFM**, **BMC**, **Decommission**, and **Key Cancellation** types.

## Prepare the environment
After cloning the repo below, install the appropriate `intelprot-*.whl` per the upstream README.
```bash
pip3 install crccheck
pip3 install ecdsa
git clone https://github.com/intel/intel-server-prot-spdm.git
```

---

## Build AFM Capsule

### Generate AFM manifest template
```bash
python3 -m intelprot.capsule -start_afm -p bhs
```

This will generate a sample manifest (e.g., `bhs_afm_manifest_cap.json`). Edit it and provide the required platform fields, commonly including:

- `root_private_key`, `csk_private_key`: paths to your private key files.
- `smbus_addr`, `bus_id`, `binding_spec`: the bus info
- Other platform-required properties

### Build AFM image
```bash
python3 -m intelprot.capsule afm -a bhs_afm_manifest_cap.json
```
When complete, capsules are written to **`AFM/`** (capsule variants).

---

## Build Signed BMC Image

### Generate BMC manifest template
```bash
python3 -m intelprot.bmc -start_build -r bhs
```
This will generate a sample manifest (e.g., `bhs_pfr_bmc_manifest.json`). Edit it and provide the following fields:

- `root_private_key`, `csk_private_key` — paths to your private key files.
- `mtd_firmware` — path to the **full-size** BMC image to be signed.
- `csk_id`, `svn` — security parameters (CSK identifier and Security Version Number).
- `image-parts` — BMC partition / layout information.
- Other platform-required properties.

### Build the signed BMC image (full-size & capsule)
Place your **full-size BMC image** and the edited manifest JSON in the same directory, then run:
```bash
python3 -m intelprot.bmc -m bhs_pfr_bmc_manifest.json -r bhs
```
When complete, images are written to **`Output/`** (both full-size and capsule variants).

---

## Build Decommission capsule

### Build Decommission capsule
Run the following command:
```bash
python3 -m intelprot.capsule decomm -rk rk384_prv.pem -csk csk384_prv.pem -id 0
```

The output file (e.g., `decomm_cap_cskid0_signed_pfr3.bin`) will appear
in the **current directory**.

---

## Build Key Cancellation capsule

### Build Key Cancellation capsule
Run the following command:
```bash
python3 -m intelprot.capsule kcc -rk rk384_prv.pem -id csk384_prv.pem -id 0 -type cpld_cap
```

The output file (e.g., `kcc_cpld_cap_csk0_signed_pfr3.bin`) will appear
in the **current directory**.

### Valid Type Names

|   PC Type    | Value |
|--------------|-------|
|`cpld_cap`    | 0x100 |
|`pch_pfm`     | 0x101 |
|`pch_cap`     | 0x102 |
|`bmc_pfm`     | 0x103 |
|`bmc_cap`     | 0x104 |
