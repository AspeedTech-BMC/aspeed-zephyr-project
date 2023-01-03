# Required Packages
- [intel-pfr-signing-utility](https://github.com/Intel-BMC/intel-pfr-signing-utility)

Download intel pfr signing utility and compile.

# Keys
## secp256r1 (ECDSA 256)
- root private key: `rk_prv.pem`
- root public key: `rk_pub.pem`
- csk private key: `csk_prv.pem`
- csk public key: `csk_pub.pem`

## secp384r1 (ECDSA 384)
- root private key: `rk384_prv.pem`
- root public key: `rk384_pub.pem`
- csk private key: `csk384_prv.pem`
- csk public key: `csk384_pub.pem`

# Create ROT update capsule
## rot_update_capsule.xml and rot_update_capsule_secp384r1.xml
- svn: `1`
- pc_type: `0`
- csk_id: `0`

## Run
- Sign the image

```
intel-pfr-signing-utility -c rot_update_capsule.xml -o zephyr_signed.bin zephyr.bin -v
```

zephy_signed.bin is the signed ast1060 firmware capsule.

# Create decommission capsule
## dcc.xml and dcc_secp384r1.xml
- pc_type: `512`
- csk_id: `0`

## Run
- Create unsigned payload which consists of 128 bytes of 0s.

```
dd if=/dev/zero of=dcc.bin count=128 bs=1
```

- Sign the image

```
intel-pfr-signing-utility -c dcc.xml -o dcc_signed.bin dcc.bin -v
```

dcc_signed.bin is the signed ROT decommission capsule.

# Create key cancellation certificate
## kcc.xml and kcc_secp384r1.xml
- without `cskey` element in `block1`
- `pc_type`: `0` key cancellation for ROT update capsule

```
0 ROT Update Capsule (0x100 + 0 = 0x100)
1 PCH PFM (0x100 + 1 = 0x101)
2 PCH Update Capsule (0x100 + 2 = 0x102)
3 BMC PFM (0x100 + 3 = 0x103)
4 BMC Update Capsule (0x100 + 4 = 0x104)
```

According to the Intel PFR spec, pc_type should be 0x100 to 0x104.
However, if `cskkey` element does not exist in XML config file, the `intel-pfr-signing-utility` sign tool will automatically add `0x100`.
Therefore, the sign tool will add `0x100` in signature if `pc_tpye` is `0` in XML configure file.

## Run
- Create unsigned payload which consists 4 bytes of the cancellation ID of the CSK key being canceled (0 - 127) and 124 bytes reserved data of 0s.

The following command set the cancellation ID to "1"

```
echo -n -e \\x01\\x00\\x00\\x00 > kcc.bin
dd if=/dev/zero oflag=append conv=notrunc of=kcc.bin bs=1 count=124
```

- Modify the xml to set your own pc_type.
- Sign the image

```
intel-pfr-signing-utility -c kcc.xml -o kcc_signed.bin kcc.bin -v
```

kcc_signed.bin is the signed key cancellation certificate.

# Create AFM image and capsule
The AFM image and capsule can be build with `intel_pfr` python module. We provide an example config file `afm_spdm-emu.json` for attesting spdm-emu in BMC side.

```
python3 -m intel_pfr.capsule afm -a afm_spdm-emu.json
```

**NOTICE** ast1060-dcscm machine only allocates 64KB AFM active partition by default, but `intel_pfr` module will always generate 128KB capsule. User could patch capsule.py:L61 to change the size, or user could enlarge AFM partition for storing more AFM measurement.

