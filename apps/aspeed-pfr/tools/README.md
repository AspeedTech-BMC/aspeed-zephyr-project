# Create ROT update capsule
This python script, `rot_update_capsule.py`, update ROT unsigned capsule and sign it with XML configure file.

## Required Packages
- [intel-pfr-signing-utility](https://github.com/Intel-BMC/intel-pfr-signing-utility)

It is required to use this tool to sign ROT update capsule.

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
                        xml configure file
  -i [input image], --input_img [input image]
                        raw image to be signed
  -o [output image], --out_img [output image]
                        output image

```

## Keys
- root private key: `rk_prv.pem`
- root public key: `rk_pub.pem`
- csk private key: `csk_prv.pem`
- csk public key: `csk_pub.pem`

## XML config file
- svn: `2`
- pc_type: `0`
- csk_id: `1`

## Run
- raw image: `zephyr.bin`
- pfr sign tool: `intel-pfr-signing-utility`
- XML config file: `pfr_config.xml`

The following example places above files in this directory.

```
python3 rot_update_capsule.py -t ./intel-pfr-signing-utility -i ./zephyr.bin -c ./pfr_config.xml
```

The ROT update capsule will be created in `output/rot_signed.bin`

