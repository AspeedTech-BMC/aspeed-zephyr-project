# ASPEED PFR Tools

## amd

Utilities for generating amd solution images, please refer to README.md in the sub folder for more information.

## intel

Utilities for generating intel-pfr solution images, please refer to README.md in the sub folder for more information.

## spi_filter_checker.py

The whitelist command defined in device tree below doesn't mean other commands are in the black list and will be blocked by spi monitor, as the spi monitor only check the first 6 bits of spi command.
```
&spim1 {
	allow-cmds = [03 13 0b 0c 6b 6c 01 05 35 06 04 20 21 9f 5a b7 e9 32 34 d8 dc 02 12 3b 3c 70 bb bc];
    }
```

The tool is used to check whther spi monitor can distinguish all white list commands from all black list commands.

### Usage
Replace the array of `white_list_cmds` and `black_list_cmds` in `spi_filter_checker.py`  
For example:

```python

white_list_cmds = [
        0x03, 0x13, 0x0b, 0x0c, 0x6b, 0x6c, 0x01, 0x05, 0x35, 0x06, 0x04, 0x20, 0x21, 0x9f, 0x5a, 0xb7, 0xe9, 0x32, 0x34, 0xd8, 0xdc, 0x02, 0x12, 0x15, 0x31, 0x3b, 0x3c
]

black_list_cmds = [
        0x18, 0x2f, 0x33, 0xc1
]

```

Run spi_filter_checker.py
```
# python3 spi_filter_checker.py

Illegal parameterization: EARLY_COMPARE_COMMAND_BITS not large enough to distinguish all permitted SPI commands from all forbidden one-byte SPI commands
White list command: 0x32
Black list command: 0x33
Illegal parameterization: EARLY_COMPARE_COMMAND_BITS not large enough to distinguish all permitted SPI commands from all forbidden one-byte SPI commands
White list command: 0x31
Black list command: 0x33
```

The tool will compare white list commands with black list commands and list commands that can't be blocked.

