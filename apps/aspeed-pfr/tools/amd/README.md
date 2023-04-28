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

