# aspeed-obmf

This application provides an LSTP-over-USB demo for bring-up with NVIDIA's
LSTP host driver.

## Source layout

The core (`lstp/`) and UART (`uart/`) are always built. The other channel
directories are built when their Kconfig option is set:

| Directory | Built when | Contents |
| --------- | ---------- | -------- |
| `lstp/` | always | LSTP core: USB transport, router, task thread, channel registry |
| `uart/` | always | UART channel; VUART (`CONFIG_OBMF_ESPI_UART_VUART`), shell (`CONFIG_OBMF_LSTP_UART_SHELL`) or plain backend |
| `spi/` | `CONFIG_OBMF_LSTP_SPI_CHANNEL` | Read-only SPI channel served through the flash API |
| `i2c/` | `CONFIG_OBMF_LSTP_I2C_CHANNEL` | I2C channel |
| `gpio/` | `CONFIG_OBMF_LSTP_GPIO_CHANNEL` | GPIO channel, including eSPI virtual-wire pins |
| `mtd/` | `CONFIG_OBMF_LSTP_MTD_CLIENT` | Remote MTD client over LSTP SPI and its shell |
| `espi/` | `CONFIG_OBMF_ESPI_BRIDGE` | AST1040 eSPI bridge, OOB, SAFS and the MMIO (`CONFIG_OBMF_ESPI_MMIO`) channel, `obmf espi` shell |

`main.c` and the `obmf` shell root (`obmf_shell.c`) stay at the top of `src/`.

Dependencies only point down: `lstp/` includes nothing outside itself, the
channel directories include only `lstp/`, and `espi/` may also use `uart/`
and `gpio/`. A header from another directory is included with its directory
(`#include "lstp/lstp_router.h"`), so the dependency is visible at the include
site.

Apart from the legacy channel-0 SPI reroute and the SPI-backed remote MTD
transaction, the core does not name any channel. A channel module defines a
`struct lstp_channel` with `LSTP_CHANNEL_DEFINE()` (`lstp/lstp_channel.h`),
giving its `LSTP_*_CHANNEL_ID` from `lstp/lstp_backend.h` and its init,
config, request and poll hooks; the router collects them at start-up. A
channel whose ID is `LSTP_CHANNEL_ID_NONE` is left out. To add a channel, give
it a slot in `lstp_backend.h`, a directory with its own `CMakeLists.txt`, and
an `add_subdirectory_ifdef()` line in the top-level `CMakeLists.txt` so the
channel directory is built when its Kconfig option is set.

## Environment Setup

- Connect the AST1030 USB port to the AST2700 `usb2d` port.
- Boot AST2700 and run:

```sh
lsusb
```

- Confirm the ASPEED LSTP USB device is enumerated:

```text
Bus 001 Device 002: ID 0955:cf11 ASPEED OBMF-USB
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

## Boards, channels and shell

Two AST1040 boards are supported. The interposer is the EVB plus a host eSPI
link (`boards/aspeed/ast1040_interposer` in this repository), and only it
builds the eSPI bridge:

| Board (`west build -b`) | Channels after management (ch0) |
| ----------------------- | -------------------------------- |
| `ast1040_evb/ast1040/cm4` | SPI (ch1), I2C (ch2), GPIO (ch3), UART (ch4, uart0 on CON5 through UDMA) |
| `ast1040_interposer/ast1040/cm4` | UART (ch1, host VUART 0x3F8), MMIO (ch2) |
| `ast1030_evb/ast1030` | SPI (ch1), I2C (ch2), GPIO (ch3, SGPIO, read-only), UART (ch4, uart3) |

Channel IDs are dense, so turning a channel on or off with
`CONFIG_OBMF_LSTP_{SPI,I2C,GPIO}_CHANNEL` shifts the IDs after it; update the
BMC device-tree IDs to match.

The BMC cannot change a GPIO's direction; it uses the direction this firmware
reports. `gpio-controllers` exports whole 32-pin banks, so outputs are an
allow-list: only pins in `gpio-output-lines` can be driven. Every other direct
GPIO is reported as an input and is never reconfigured; `gpio-input-lines`
marks the inputs that are configured at init and can take an IRQ (the EVB
drives GPIO108 and reads it back on GPIO113 through a jumper on J48 pins 1-2).
The AST1030 EVB lists no outputs, so its SGPIO pins are read-only.

Known limitation: the I2C SMBus block read (`READ_RECV_LEN`) clocks a fixed
1 + 32 bytes and returns only the 1 + count the target announced. Zephyr has
no receive-length read and the Aspeed controller driver always ends the last
message with STOP, so the read cannot stop at the count. Targets whose reads
have side effects (FIFOs, mailboxes, PMBus block reads with PEC) see the extra
bytes consumed.

With `CONFIG_SHELL`, commands are grouped under `obmf`:

| Group | Commands |
| ----- | -------- |
| `obmf espi` | Status, capabilities, vwire/vGPIO reads, register/Port I/O dumps, snoop, monitor, memtrace |
| `obmf stats` | LSTP drop/queue counters |
| `obmf vuart` | LSTP VUART registers |
| `obmf uart` | send, recv |
| `obmf mtd` | Remote MTD read/write/erase over LSTP SPI |

Use `obmf <group> --help` for syntax. `espi` requires `CONFIG_OBMF_ESPI_BRIDGE`;
`vuart` requires `CONFIG_OBMF_ESPI_UART_VUART`.
`mtd` requires `CONFIG_OBMF_LSTP_MTD_CLIENT=y` together with
`CONFIG_OBMF_LSTP_SPI_CHANNEL=y`; the remote MTD client is opt-in and defaults
to off. `uart` requires `CONFIG_OBMF_LSTP_UART_SHELL`. On the
EVB only `obmf stats` and `obmf mtd` exist.

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
