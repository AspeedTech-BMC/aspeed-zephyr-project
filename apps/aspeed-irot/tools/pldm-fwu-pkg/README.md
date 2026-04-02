# PLDM Firmware Update Package
## Environment Setup
```
python3 -m venv .venv
source .venv/bin/activate
pip install bitarray
```

## Image Generation
The example of metadata-irot.json:
```
{
    "PackageHeaderInformation": {
        "PackageHeaderIdentifier": "F018878CCB7D49439800A02F059ACA02",
        "PackageHeaderFormatVersion": 1,
        "PackageReleaseDateTime": "2023-10-12 00:00:00",
        "PackageVersionString": "v11.01"
    },
    "FirmwareDeviceIdentificationArea": [
        {
            "DeviceUpdateOptionFlags": [],
            "ComponentImageSetVersionString": "v11.01",
            "ApplicableComponents": [0],
            "Descriptors": [
                {
                    "DescriptorType": 1,
                    "DescriptorData": "0000a015"
                }
            ]
        }
    ],
    "ComponentImageInformationArea": [
        {
            "ComponentClassification": 10,
            "ComponentIdentifier": 9984,
            "ComponentOptions": [1],
            "ComponentComparisonStamp": "0xFFFFFFFE",
            "RequestedComponentActivationMethod": [3],
            "ComponentVersionString": "v01.01"
        }
    ]
}
```

The command line generate the package:
```
./img.py irot.pkg metadata-irot.json image-bmc
```

## PLDM Firmware Update Agent
In our test environment, we cross compile [CodeConstruct/mctp-rs]() with aarch64 and copy pldm-fw into BMC.
```
cargo build --release --target aarch64-unknown-linux-musl
scp target/aarch64-unknown-linux-musl/release/pldm-fw root@${BMC_IP}:/tmp/pldm-fw
```

## PLDM Firmware Update through ASPEED-iROT
### From BMC side:

Setup MCTP Network
```bash
mctp link set mctpmbox0 up
mctp addr add 11 dev mctpmbox0
mctp route add 10 via mctpmbox0
ip link set dev mctpmbox0 mtu 32768
```

Check if ASPEED-iROT supports PLDM Firmware Update
```bash
pldm-fw inventory 10
Device: iana:15a00000
Firmware Parameters:
  Active version:  ..
  Pending version:
  Update caps: [0x0]: none
    * Device will revert to previous component on failure
    * Does not require restarting update on failure
    * Host functionality is not reduced during update
    * Device cannot accept a partial update
    * Device unable to update while host OS active
    * Downgrades may be restricted
    * Device components do not have security revision numbers
  Components:
    [0]
      Classification:  Firmware
      Index:           0
      Identifier:      0x2700
      Active Version:  ast2700-image
      Pending Version:
      Activation:      [0x2] SelfContained
      Update caps:     [0x0]
    [1]
      Classification:  Firmware
      Index:           0
      Identifier:      0x2701
      Active Version:  Mbed TLS 3.6.2
      Pending Version:
      Activation:      [0x2] SelfContained
      Update caps:     [0x0]
```

Let's assume that the package locates in /tmp/irot.pkg
Sending the package and starts the upgrade:
```
pldm-fw update 10 /tmp/irot.pkg
Proposed update:
Device: iana:15a00000
Update:
  Package version: v11.01
  Apply to index:  0
  Components to update:
    0: id 2700, version v01.01

Confirm update (y,N)? y
Checking FD state, expected: Idle
Checking FD state, expected: LearnComponents
Checking FD state, expected: ReadyXfer
Data request: offset 0x00000000, len 0x8000,  0% 29.41 MB/sec, 00:00:01 remaining
Data request: offset 0x00008000, len 0x8000,  0% 3.64 MB/sec, 00:00:15 remaining
Data request: offset 0x00010000, len 0x8000,  0% 2.82 MB/sec, 00:00:20 remaining
Data request: offset 0x00018000, len 0x8000,  0% 2.53 MB/sec, 00:00:22 remaining
Data request: offset 0x00020000, len 0x8000,  0% 2.39 MB/sec, 00:00:24 remaining
Data request: offset 0x00028000, len 0x8000,  0% 2.30 MB/sec, 00:00:25 remaining
Data request: offset 0x00030000, len 0x8000,  0% 2.24 MB/sec, 00:00:25 remaining
Data request: offset 0x00038000, len 0x8000,  0% 2.20 MB/sec, 00:00:26 remaining
# ... skip
Data request: offset 0x036f0000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x036f8000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03700000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03708000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03710000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03718000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03720000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03728000, len 0x8000, 99% 1.96 MB/sec, 00:00:00 remaining
Data request: offset 0x03730000, len 0x7858, 100% 1.96 MB/sec, 00:00:00 remaining
Transfer complete, elapsed: TimeDelta { secs: 29, nanos: 659768235 }, sz_done: 57899096
Data request: offset 0x00000000, len 0x0, 100% 0 B/sec, 00:00:00 remaining
Firmware verify request received
Firmware apply request received with code: 00
Firmware apply request accepted, waiting for completion
Firmware apply request sent, waiting for completion
Checking FD state, expected: ReadyXfer
Firmware update completed successfully
Component 9984 (v01.01) updated successfully
All components updated successfully
Components updated, activating...
Checking FD state, expected: ReadyXfer
...

```
### Log from ASPEED-iROT side
```
[14:42:34.671,000] <inf> pldm: Get status
                               00 00 00 03 00 65 00 00  00 00 00                |.....e.. ...
[14:42:34.676,000] <inf> pldm: max transfer size(32768), number of component(1), max_outstanding_transfer_req(1)
[14:42:34.676,000] <inf> pldm: packet data length(0), component sting type(1) length(6)
[14:42:34.676,000] <inf> pldm: Component image version:
                               76 31 31 2e 30 31                                |v11.01
[14:42:34.681,000] <inf> pldm: Get status
                               00 01 00 03 00 65 00 00  00 00 00                |.....e.. ...
[14:42:34.686,000] <inf> pldm: Received component class: ah id: 9984 with version:
[14:42:34.686,000] <inf> pldm:
                               76 30 31 2e 30 31                                |v01.01
[14:42:34.691,000] <inf> pldm: Get status
                               00 02 01 03 00 65 00 00  00 00 00                |.....e.. ...
[14:42:34.696,000] <inf> pldm: Update component class 0xa id: 9984 image_size: 0x3737858 version:
[14:42:34.696,000] <inf> pldm:
                               76 30 31 2e 30 31                                |v01.01
[14:42:34.698,000] <inf> pldm: Component 9984 start update process...
[14:42:34.698,000] <inf> pldm_fw_update_sd_ast2700_image: AST2700 image pre-update, size=57899096
[14:42:37.681,000] <inf> pldm: package loaded: 10%
[14:42:40.652,000] <inf> pldm: package loaded: 20%
[14:42:43.622,000] <inf> pldm: package loaded: 30%
[14:42:46.576,000] <inf> pldm: package loaded: 40%
[14:42:49.545,000] <inf> pldm: package loaded: 50%
[14:42:52.516,000] <inf> pldm: package loaded: 60%
[14:42:55.471,000] <inf> pldm: package loaded: 70%
[14:43:04.359,000] <inf> pldm: All data has been transferred for component 9984
[14:43:04.359,000] <inf> pldm: Component 9984 update success!
[14:43:04.359,000] <inf> pldm: Transfer complete
[14:43:04.502,000] <err> cptra_ipc: cptra_ipc_receive failed
[14:43:04.502,000] <err> cptra_api: set_auth_manifest failed, ret:0xffffffff
[14:43:04.502,000] <err> cptra_soc_manifest_v1: set_auth_manifest failed
[14:43:04.599,000] <inf> cptra_api: Caliptra IPC authorize_and_stash...
[14:43:04.620,000] <dbg> cptra_api: cptra_authorize_and_stash:   Send IPC Caliptra authorize_and_stash is successful
[14:43:04.620,000] <dbg> cptra_api: cptra_authorize_and_stash:   output: chksum=0xfffffcd7, fips_status=0x0
[14:43:04.620,000] <dbg> cptra_api: cptra_authorize_and_stash:   auth_req_result: 0xdeadc0de
[14:43:06.004,000] <inf> cptra_api: Caliptra IPC authorize_and_stash...
[14:43:06.024,000] <dbg> cptra_api: cptra_authorize_and_stash:   Send IPC Caliptra authorize_and_stash is successful
[14:43:06.024,000] <dbg> cptra_api: cptra_authorize_and_stash:   output: chksum=0xfffffcd7, fips_status=0x0
[14:43:06.024,000] <dbg> cptra_api: cptra_authorize_and_stash:   auth_req_result: 0xdeadc0de
[14:43:06.024,000] <inf> cptra_api: cptra_authorize_and_stash: Pass
# ... skip
[14:43:36.056,000] <inf> cptra_api: Caliptra IPC authorize_and_stash...
[14:43:36.090,000] <dbg> cptra_api: cptra_authorize_and_stash:   Send IPC Caliptra authorize_and_stash is successful
[14:43:36.091,000] <dbg> cptra_api: cptra_authorize_and_stash:   output: chksum=0xfffffcd7, fips_status=0x0
[14:43:36.091,000] <dbg> cptra_api: cptra_authorize_and_stash:   auth_req_result: 0xdeadc0de
[14:43:36.091,000] <inf> cptra_api: cptra_authorize_and_stash: Pass
[14:43:36.091,000] <inf> pldm_fw_update_sd_ast2700_image: AST2700 image validation passed
[14:43:36.091,000] <inf> pldm: Verify complete 0
[14:43:36.096,000] <inf> pldm: Apply complete
[14:43:43.063,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x0 size=0x100000
[14:43:50.199,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x100000 size=0x100000
[14:43:57.361,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x200000 size=0x100000
[14:44:04.556,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x300000 size=0x100000
[14:44:11.711,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x400000 size=0x100000
[14:44:18.787,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x500000 size=0x100000
[14:44:25.854,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x600000 size=0x100000
[14:44:32.911,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x700000 size=0x100000
[14:44:39.757,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x800000 size=0x100000
[14:44:46.589,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x900000 size=0x100000
[14:44:53.448,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0xa00000 size=0x100000
[14:45:00.288,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0xb00000 size=0x100000
# ... skip
[14:49:01.910,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x2e00000 size=0x100000
[14:49:08.759,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x2f00000 size=0x100000
[14:49:15.757,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3000000 size=0x100000
[14:49:22.742,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3100000 size=0x100000
[14:49:29.695,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3200000 size=0x100000
[14:49:36.661,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3300000 size=0x100000
[14:49:43.672,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3400000 size=0x100000
[14:49:50.653,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3500000 size=0x100000
[14:49:57.667,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3600000 size=0x100000
[14:49:59.534,000] <inf> pldm_fw_update_sd_ast2700_image: programmed fmc@0 offset=0x3700000 size=0x37858
[14:49:59.589,000] <inf> pldm_fw_update_sd_ast2700_image: AST2700 image post-update complete
[14:49:59.594,000] <inf> pldm: Get status
                               00 02 05 01 00 65 00 00  00 00 00                |.....e.. ...
[14:49:59.599,000] <inf> pldm: Get status
                               00 02 05 01 00 65 00 00  00 00 00                |.....e.. ...
[14:49:59.604,000] <inf> pldm_fw_update_sd_ast2700_image: AST2700 image activate
[14:49:59.604,000] <inf> pldm: Activate firmware
```

