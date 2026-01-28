# Required Packages
- [cerberus](https://github.com/AspeedTech-BMC/cerberus)

## Dependencies
- [pycryptodome](https://pypi.org/project/pycryptodome/)

Download cerberus pfr signing utility and its dependencies.

```
git clone https://github.com/AspeedTech-BMC/cerberus
pip3 install pycryptodome
```

# Keys
## RSA 2048
- root private key: `prikey_2048.pem`
- root public key: `pubkey_2048.pem`
- csk private keys: `pricsk0_2048.pem - pricsk15_2048.pem`
- csk public keys: `pubcsk0_2048.pem - pubcsk15_2048.pem`

# Create ROT firmware recovery/update image
## rot_recovery_image_generator.config
- Xml: `rot_recovery_image.xml`
- InputImage: `zephyr.bin`
- Output: `rot_recovery_image.bin`

## rot_recovery_image.xml
- image format type: `2`

## Run
- Copy your zephyr.bin to `cerberus/tools/recovery_tools`.
- Copy keys, config and xml from keys and recovery_tools to `cerberus/tools/recovery_tools`.
- Sign the image (make sure inpute image, keys, config and xml in recovery tool location.)
- It should be signed by CSK keys.

```
python3 recovery_image_generator.py rot_recovery_image_generator.config
```

rot_recovery_image.bin is the signed ast1060 firmware update/recovery image.

# Create decommission image
## decommission_image_generator.config
- Xml: `decommission_image.xml`
- Output: `decommission_image.bin`

## decommission_image.xml
- image format type: `5`

## Run
- Copy keys, config and xml from keys and key_management_tools to `cerberus/tools/key_management_tools`.
- Sign the image (make sure keys, config and xml in key management tool location.)
- It should be signed by root key.

```
python3 key_management_tool.py decommission_image_generator.config
```

decommission_image.bin is the signed ROT decommission image.

# Create BIOS firmware recovery/update image

All sample configuration files are stored in
`aspeed-zephyr-project/apps/aspeed-pfr/tools/amd/bios`.

Users could modify the sample files based on their requirements.
The AMD BIOS file can be downloaded from the AMD Support Site.

## Create BIOS PFM

### pch_pfm_generator.config

-   Xml: `pch_cerberus_pfm.xml`
-   InputImage: `AMD BIOS file`
-   Output: `output_pch_pfm.bin`

## Run

-   Copy your AMD BIOS file to
    `aspeed-zephyr-project/apps/aspeed-pfr/tools/amd/bios`.
-   Copy keys, config and xml from cerberus tools to the same directory.
-   Generate BIOS PFM.

```
    python3 <PATH of cerberus>/tools/manifest_tools/pfm_generator.py pch_pfm_generator.config
```

`output_pch_pfm.bin` is the generated BIOS PFM.

## Insert PFM to BIOS file

In this example, the PFM is inserted to offset `0xba0000`. If another
offset is used, update the `seek` value.

    dd if=./output_pch_pfm.bin bs=1 seek=12189696 conv=notrunc of=<AMD BIOS file>

## Create BIOS recovery image

### pch_recovery_image_generator.config

-   Xml: `pch_recovery_image.xml`
-   InputImage: `AMD BIOS file with PFM`
-   Output: `pch_recovery_image.bin`

## Run

-   Copy your AMD BIOS file (with PFM) to
    `aspeed-zephyr-project/apps/aspeed-pfr/tools/amd/bios`.
-   Copy keys, config and xml from cerberus tools to the same directory.
-   Generate BIOS recovery image.

```
    python3 <PATH of cerberus>/tools/recovery_tools/recovery_image_generator.py pch_recovery_image_generator.config
```

`pch_recovery_image.bin` is the signed BIOS recovery image.

## Partition layout

The below layout is based on 128MB BIOS flash.

``` text
+----------------------------+ <--- 0x00000000
|   Active Region (32MB)     |
+----------------------------+ <--- 0x02000000
|   Recovery Region (32MB)   |
+----------------------------+ <--- 0x04000000
|   Staging Region (32MB)    |
+----------------------------+ <--- 0x06000000
|   Reserved                 |
+----------------------------+
```

## Note

-   In the AMD CRB platform, two BIOS flashes (64MB each) are used for
    the two CPUs. In this example, they are combined into a single 128MB
    image.
-   The Venice platform supports converting a 2*1 platform to a 1*2
    platform. When PFR is enabled, this conversion is not supported
    because two PFR instances are required to manage the firmware and
    flash for the two CPUs.
-   The default AMD BIOS image size is 32MB. The recovery image will add
    some overhead and cause the final image size to exceed 32MB.
    In this example, the BIOS image is truncated slightly to fit the
    flash layout because the BIOS source code is not available.
-   The proper way to handle this is to adjust the BIOS image size
    through BIOS code so that the final image fits the flash layout.

