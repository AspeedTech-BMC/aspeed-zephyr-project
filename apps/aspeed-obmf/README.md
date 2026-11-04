# aspeed-obmf

This application provides an LSTP-over-USB demo for bring-up with NVIDIA's
LSTP host driver.

## Source layout

The core (`lstp/`) and UART (`uart/`) are always built. The other channel
directories are built when their Kconfig option is set:

| Directory | Built when | Contents |
| --------- | ---------- | -------- |
| `lstp/` | always | LSTP core: USB transport, router, task thread, channel registry |
| `uart/` | always | UART channel; shell (`CONFIG_OBMF_LSTP_UART_SHELL`) or plain backend |
| `spi/` | `CONFIG_OBMF_LSTP_SPI_CHANNEL` | Read-only SPI channel served through the flash API |
| `mtd/` | `CONFIG_OBMF_LSTP_MTD_CLIENT` | Remote MTD client over LSTP SPI and its shell |

`main.c` and the `obmf` shell root (`obmf_shell.c`) stay at the top of `src/`.

Dependencies only point down: `lstp/` includes nothing outside itself, the
channel directories include only `lstp/`. A header from another directory is included with its directory
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

## Boards, channels and shell

The boards export these channels:

| Board (`west build -b`) | Channels after management (ch0) |
| ----------------------- | -------------------------------- |
| `ast1040_evb/ast1040/cm4` | SPI (ch1), UART (ch2, uart0 on CON5 through UDMA) |
| `ast1030_evb/ast1030` | SPI (ch1), UART (ch2, uart3) |

Channel IDs are dense, so turning a channel on or off with
`CONFIG_OBMF_LSTP_SPI_CHANNEL` shifts the IDs after it; update the
BMC device-tree IDs to match.

With `CONFIG_SHELL`, commands are grouped under `obmf`:

| Group | Commands |
| ----- | -------- |
| `obmf stats` | LSTP drop/queue counters |
| `obmf uart` | send, recv |
| `obmf mtd` | Remote MTD read/write/erase over LSTP SPI |

Use `obmf <group> --help` for syntax. `mtd` requires `CONFIG_OBMF_LSTP_MTD_CLIENT=y` together with
`CONFIG_OBMF_LSTP_SPI_CHANNEL=y`; the remote MTD client is opt-in and defaults
to off. `uart` requires `CONFIG_OBMF_LSTP_UART_SHELL`. On the
EVB only `obmf stats` and `obmf mtd` exist.
