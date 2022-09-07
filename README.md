# Introduction
This repository provides fimware applications for AST1030 and AST1060, these
applications are developing on top of [Zephyr BSP](https://github.com/AspeedTech-BMC/zephyr).


# Building ASPEED-PFR firmware

```
west init -m https://github.com/AspeedTech-BMC/aspeed-zephyr-project --mr aspeed-master workspace
cd workspace
west update
```

## AST2600 L board

```
west build -b ast1060_evb -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 DCSCM board

```
west build -b ast1060_dcscm -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 Dual Flash

```
west build -b ast1060_dual_flash -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 DCSCM board for AMD

```
west build -b ast1060_dcscm_amd -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 Dual Flash for AMD

```
west build -b ast1060_dual_flash_amd -p auto aspeed-zephyr-project/apps/aspeed-pfr
```
