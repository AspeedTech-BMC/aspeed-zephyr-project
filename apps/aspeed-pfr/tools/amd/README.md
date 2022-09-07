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

```
python3 recovery_image_generator.py rot_recovery_image_generator.config
```

rot_recovery_image.bin is the signed ast1060 firmware update/recovery image.

