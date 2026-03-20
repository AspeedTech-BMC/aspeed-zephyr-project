# obmf-demo

This application provides an LSTP-over-USB demo for bring-up with NVIDIA's
LSTP host driver.

## Environment Setup

- Connect the AST1030 USB port to the AST2700 `usb2d` port.
- Boot AST2700 and run:

```sh
lsusb
```

- Confirm the ASPEED LSTP USB device is enumerated:

```text
Bus 001 Device 002: ID 0955:cf11 ASPEED LSTP-USB
```

- Check the host-side LSTP driver status:

```sh
dmesg | grep lstp
```

- Expected output should include lines similar to:

```text
[    3.622569] usbcore: registered new interface driver lstp
[    4.126144] lstp 1-1:1.0: lstp_init_channels: LSTP v1: device Management discovered with 3 channels
[    4.212402] lstp 1-1:1.0: lstp_spi_init: ch_1: Initialized
[    5.119588] lstp 1-1:1.0: lstp_i2c_start: I2C channel 2 registered as Management_I2C6
...
[    5.130496] lstp 1-1:1.0: lstp_probe: LSTP device initialized successfully
[    5.776016] i2c i2c-22: lstp_i2c_write: ch_2: Write request to addr=0x48 failed (-5)
[    5.877128] i2c i2c-22: lstp_i2c_write: ch_2: Write request to addr=0x49 failed (-5)
```

## Validation

- Read the LM75 register from AST2700 through the LSTP I2C channel:

```sh
i2cget -y 22 -a 0x4d 2
```

- Expected result:

```text
0x4b
```

- Verify the same value directly on AST1030 I2C6:

```sh
iic read_byte I2C_6 0x4d 2
```

- Expected result:

```text
Output: 0x4b
```
