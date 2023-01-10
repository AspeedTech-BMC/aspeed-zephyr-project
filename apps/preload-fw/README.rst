# ASPEED Preload Firmware

ASPEED preload firmware supports following features:  
- Program OTP image for writing public key to OTP
- Generate vault key by HW TRNG and write to OTP
- Enable secure boot and CDI by updating OTP
- Send device id certificate request to HSM (WIP)
- Receive, verify and store signed certificate chain to AST1060 internal flash
- Provide mailbox commands for ROT firmware replacement

Please note that all OTP operation are simulated in ast1060 internal flash.

## Bootup Flow

AST1060 should be bootup 3 times in manufactureing process

### First Bootup
In first bootup, secure boot is not enabled. Preload firmware generates vault key for CDI generation, write public key to OTP and enables secure boot.

```
BPc00
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***
I: Starting bootloader
I: RAM loading to 0x30000 is succeeded.
I: Bootloader chainload address offset: 0x20000
I: Secure boot is not enabled, bypass DICE process
I: Jumping to the first image slot
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***


ST: Power On
[1;32m[00:00:00.090,000] <inf> main: *** ASPEED Preload FW version v01.01 Board:ast1060_dcscm_dice ***
[00:00:00.220,000] <inf> otp: Generating vault key...
[00:00:01.913,000] <inf> otp: Secureboot is enabled successfully
[00:00:01.913,000] <inf> otp: CDI is enabled successfully
[00:00:01.913,000] <inf> otp: OTP image is erased

```

### Second Bootup
First mutable code check secure boot is enabled, it generates alias and device id certificate.
Preload firmware sends device id certificate signing request to HSM and waiting for HSM to
generate signed certificate chain. The signed certificate chain will be stored in ast1060 internal flash

```
BPc00
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***
I: Starting bootloader
I: RAM loading to 0x30000 is succeeded.
I: Bootloader chainload address offset: 0x20000
I: Secure boot is enabled, DICE process start
I: fmc_cs0 = 0x142d8
hash_device_firmware 0x25548
sha_start 0x25560 1
sha_free 0x25560
I: Generate Alias certificate
I: Generate Device ID certificate
I: Jumping to the first image slot
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***


ST: Power On
[1;32m[00:00:00.090,000] <inf> main: *** ASPEED Preload FW version v01.01 Board:ast1060_dcscm_dice ***
[00:00:00.091,000] <inf> main: Secure boot is enabled, handling certificate
[00:00:00.092,000] <inf> main: Sending DeviceID certificate request to HSM...
[00:00:00.092,000] <inf> main: Received certificate chain from HSM, verifying
[00:00:00.664,000] <inf> cert: Certificate chain verify successful
[00:00:00.664,000] <inf> main: Replace CSR by certificate chain
[00:00:00.761,000] <inf> main: Certificate chain is updated successfully
```

### Third Bootup
Device id is provisined, preload firmware verifies certificate chain and waiting for ROT firmware replacement

```
BPc00
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***
I: Starting bootloader
I: RAM loading to 0x30000 is succeeded.
I: Bootloader chainload address offset: 0x20000
I: Secure boot is enabled, DICE process start
I: fmc_cs0 = 0x142d8
hash_device_firmware 0x25548
sha_start 0x25560 1
sha_free 0x25560
I: Device ID certificate was generated and is valid
I: Jumping to the first image slot
*** Booting Zephyr OS build v00.01.07-51-g40bb65a82da2  ***


ST: Power On
[1;32m[00:00:00.090,000] <inf> main: *** ASPEED Preload FW version v01.01 Board:ast1060_dcscm_dice ***
[00:00:00.091,000] <inf> main: Secure boot is enabled, handling certificate
[00:00:00.092,000] <inf> main: Verify certificate chain...
[00:00:00.664,000] <inf> cert: Certificate chain verify successful
[00:00:00.700,000] <inf> gpio_ctrl: release BMC
[00:00:00.725,000] <inf> gpio_ctrl: release PCH
[00:00:00.725,000] <inf> main: Ready for ROT firmware replacement
```
