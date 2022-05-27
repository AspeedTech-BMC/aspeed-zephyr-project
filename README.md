# Introduction
This repository provides fimware applications for AST1030 and AST1060, these
applications are developing on top of [Zephyr BSP](https://github.com/AspeedTech-BMC/zephyr).


# Building ASPEED-PFR firmware
```
west init -m https://github.com/AspeedTech-BMC/aspeed-zephyr-project --mr aspeed-master workspace
cd workspace
west update
west build -b ast1060_evb -p auto aspeed-zephyr-project/apps/aspeed-pfr
```
