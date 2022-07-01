# Required Packages
- [intel-pfr-signing-utility](https://github.com/Intel-BMC/intel-pfr-signing-utility)

It is required to use this tool to sign unsigned capsule.

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

## kcc_capsule.xml
- without `cskey` element in `block1`
- `pc_type`: `0` key cancellation for ROT update capsule

```
0 ROT Update Capsule (0x100 + 0 = 0x100)
1 PCH PFM (0x100 + 1 = 0x101)
2 PCH Update Capsule (0x100 + 2 = 0x102)
3 BMC PFM (0x100 + 3 = 0x103)
4 BMC Update Capsule (0x100 + 4 = 0x104)
```

According to the Intel PFR spec, pc_type should be 0x100 to 0x104. However, if `cskkey` element does not exist in XML config file, the `intel-pfr-signing-utility` sign tool will automatically add `0x100`. Therefore, the sign tool will add `0x100` in signature if `pc_tpye` is `0` in XML configure file.

It is used for key cancellation capsule creation.

# Create ROT update capsule
This python script, `rot_update_capsule.py`, creates ROT unsigned capsule and sign it with XML configure file.

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
This python script, `rot_dcc_capsule.py`, creates ROT unsigned payload and sign it with XML configure file. The payload consists of 128 bytes of 0s.

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

# Create key cancellation capsule
This python script, `kcc_capsule.py`, creates unsigned payload and sign it with XML configure file. The payload consists of key cancellation ID(4 bytes) and 124 bytes of 0s.

## Usage
python3 kcc_capsule.py -h

```
usage: kcc_capsule.py [-h] -t [input sign tool] [-c [input xml]]
                      [-o [output image]] [-k [csk id]]

create kcc capsule

optional arguments:
  -h, --help            show this help message and exit
  -t [input sign tool], --input_sign_tool [input sign tool]
                        sign tool
  -c [input xml], --input_xml [input xml]
                        xml configure file, default is kcc_capsule.xml
  -o [output image], --out_img [output image]
                        output image, default is kcc_csk(id)_cap_signed.bin
  -k [csk id], --csk_id [csk id]
                        key cancellation CSK id (0-127), default is 0
```

## Run
- pfr sign tool: `intel-pfr-signing-utility`
- XML config file: `kcc_capsule.xml`
- Key cancellation Id: `0`

The following example places above files in this directory.

```
python3 ./kcc_capsule.py  -t ./intel-pfr-signing-utility -k 0
```

The key cancellation capsule will be created in `kcc-output/kcc_csk0_cap_signed.bin` for CSK ID `0`.
