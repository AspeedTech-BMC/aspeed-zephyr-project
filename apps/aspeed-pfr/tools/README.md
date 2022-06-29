# Required Packages
- [intel-pfr-signing-utility](https://github.com/Intel-BMC/intel-pfr-signing-utility)

It is required to use this tool to sign ROT unsigned capsule.

# Keys
## secp256r1 (ECDSA 256)
- root private key: `rk_prv.pem`
- root public key: `rk_pub.pem`
- csk private key: `csk_prv.pem`
- csk public key: `csk_pub.pem`

# XML config file
## rot_update_capsule.xml
- svn: `1`
- pc_type: `0`
- csk_id: `0`

It is used for ROT update capsule creation.

## rot_dcc_capsule.xml
- pc_type: `512`
- csk_id: `0`

It is used for ROT decommission capsule creation.

# Create ROT update capsule
This python script, `rot_update_capsule.py`, update ROT unsigned capsule and sign it with XML configure file.

## Usage
python3 rot_update_capsule.py -h

```
usage: rot_update_capsule.py [-h] [-t [input sign tool]] [-c [input xml]]
                             [-i [input image]] [-o [output image]]

sign ROT update capsule

optional arguments:
  -h, --help            show this help message and exit
  -t [input sign tool], --input_sign_tool [input sign tool]
                        sign tool
  -c [input xml], --input_xml [input xml]
                        xml configure file, default is rot_update_capsule.xml
  -i [input image], --input_img [input image]
                        raw image to be signed
  -o [output image], --out_img [output image]
                        output image, default is rot_update_capsule_signed.bin
```

## Run
- raw image: `zephyr.bin`
- pfr sign tool: `intel-pfr-signing-utility`
- XML config file: `rot_update_capsule.xml`

The following example places above files in this directory.

```
python3 ./rot_update_capsule.py -t ./intel-pfr-signing-utility -i ./zephyr.bin
```

The ROT update capsule will be created in `update-output/rot_update_capsule_signed.bin`

# Create ROT decommission capsule
This python script, `rot_dcc_capsule.py`, create ROT unsigned payload and sign it with XML configure file. The payload consists of 128 bytes of 0s.

## Usage
python3 rot_dcc_capsule.py -h

```
usage: rot_dcc_capsule.py [-h] [-t [input sign tool]] [-c [input xml]]
                          [-o [output image]]

create ROT dcc capsule

optional arguments:
  -h, --help            show this help message and exit
  -t [input sign tool], --input_sign_tool [input sign tool]
                        sign tool
  -c [input xml], --input_xml [input xml]
                        xml configure file, default is rot_dcc_capsule.xml
  -o [output image], --out_img [output image]
                        output image, default is rot_dcc_capsule_signed.bin
```

## Run
- pfr sign tool: `intel-pfr-signing-utility`
- XML config file: `rot_dcc_capsule.xml`

The following example places above files in this directory.

```
python3 ./rot_dcc_capsule.py -t ./intel-pfr-signing-utility
```

The ROT decommission capsule will be created in `dss-output/rot_dcc_capsule_signed.bin`

