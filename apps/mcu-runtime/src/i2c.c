/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <zephyr/logging/log.h>
#include <scu.h>
#include <ast_loader.h>

LOG_MODULE_REGISTER(ast_i2c, CONFIG_SOC_FMC_LOG_LEVEL);
struct i2c_hci g_i2c_hci;
#define DEV_DATA(dev)	((struct i2c_hci *)((dev)->data))

struct i2c_hci  {
	uint32_t index;
	uint16_t slave_addr_disable;
	uint16_t slave_addr_enable;
	mem_addr_t global_regs;
	mem_addr_t base_regs;
	uint32_t irq_status;
};

struct i2c_recovey_packet {
	uint8_t command;
	uint8_t len;
	uint8_t payload[255];
};

/* Bootrom only supoort this two command*/
enum ocp_recovery_command {
	OCP_REC_CTRL = 0x26,
	OCP_INDIRECT_DATA = 0x2B,
};

#define OCP_REC_CTRL_BYTES 3
#define OCP_REC_CTRL_CMS_BYTE 0
#define OCP_REC_CTRL_IMG_SEL_BYTE 1
#define OCP_REC_CTRL_IMG_SEL_CMS 0x1
#define OCP_REC_CTRL_IMG_SEL_CIMAGE 0x2
#define OCP_REC_CTRL_ACTIVATE_BYTE 2
#define OCP_REC_CTRL_ACTIVATE_REC_IMG 0xF

#define SCU1_REG	0x14c02000

#define SCU1_OTPCFG	(SCU1_REG + 0x880)
#define SCU1_OTPCFG_15_14		(SCU1_OTPCFG + 0x1c)
#define SCU1_OTPCFG15_I3C_I2C_CH	GENMASK(19, 16)
#define SCU1_OTPCFG15_I2C_SLAVE_ADDR	GENMASK(31, 24)

#define SCU1_PINMUX_GRP_V	(SCU1_REG + 0x454)
#define SCU1_PINMUX_GRP_W	(SCU1_REG + 0x458)
#define SCU1_PINMUX_GRP_X	(SCU1_REG + 0x45c)
#define SCU1_PINMUX_GRP_I	(SCU1_REG + 0x420)

#define SCU1_RSTCTL2		(SCU1_REG + 0x220)
#define SCU1_RSTCTL2_I2C	BIT(15)

#define SCU1_RSTCTL2_CLR	(SCU1_REG + 0x224)
#define SCU1_RSTCTL2_CLR_I2C	BIT(15)

#define SCU1_CLKGATE1		(SCU1_REG + 0x240)
#define SCU1_CLKGATE1_I2C	BIT(15)

#define SCU1_CLKGATE1_CLR	(SCU1_REG + 0x244)
#define SCU1_CLKGATE1_CLR_I2C	BIT(15)

/* global register */
#define I2CG_MIRQ		0x00
#define I2CG_SIRQ		0x04
#define I2CG_CTRL		0x0C

#define I2CG_CTRL_NEW_REG	BIT(2)
#define I2CG_CTRL_NEW_CLK_DIV	BIT(1)

#define I2CG_AC_CTRL		0x10
#define I2CG_FIFO_CFG0		0x14
#define I2CG_FIFO_CFG1		0x18
#define I2C_FIFO_DEFAULT	0x66666666

#define I2C_MULTI_FUN1		0x11
#define I2C_MULTI_FUN2		0x22

/* 0x00 : I2CC Master/Slave Function Control Register  */
#define I2CC_FUN_CTRL		0x00
#define I2CC_SLAVE_EN		BIT(1)

/* 0x04 : I2CC Master/Slave Clock and AC Timing Control Register #1 */
#define I2CC_AC_TIMING		0x04
#define I2CC_AC_VAL		0x344063 /* Real */

/* 0x20 : I2CS Slave Interrupt Control Register   */
#define I2CS_IER			0x20
/* 0x24 : I2CS Slave Interrupt Status Register	 */
#define I2CS_ISR			0x24

#define I2CS_WAIT_TX		BIT(25)
#define I2CS_RX_STOP		BIT(4)
#define I2CS_RX_DONE		BIT(2)

/* 0x28 : I2CS Slave CMD/Status Register   */
#define I2CS_CMD_STS		0x28
#define I2CS_PKT_MODE_EN	BIT(16)
#define I2CS_RX_DMA_EN		BIT(9)
#define I2CS_AUTO_NAK	(BIT(24) | BIT(25))
#define I2CS_FIRE_CMD (I2CS_AUTO_NAK | I2CS_PKT_MODE_EN | I2CS_RX_DMA_EN)

/* 0x2C : I2CS DMA Length   */
#define I2CS_DMA_LEN		0x2C
#define I2CS_DMA_RX_LEN_SET		0x1030000

/* I2CS Slave DMA Rx Buffer Register   */
#define I2CS_RX_DMA			0x3C
/* I2CS Slave DMA Rx Buffer Register   */
#define I2CS_RX_DMA_H		0x6C

/* 0x40 : I2CS Address 1  */
#define I2CS_ADDR_1		0x40
#define I2CS_EN_ADDR		0xEAE9
#define I2CS_DIS_ADDR		0x6A69
#define I2CS_ENABLE_ADDR0	0x80

/* 0x40 : I2CS Address 2  */
#define I2CS_ADDR_2		0x44

/* 0x4C : I2CS lebgth   */
#define I2CS_LENGTH		0x4C

#define I2C_BUFFER_SIZE 260 /* over 255 for one single interrupt */

#define I2C_REG(x)      (0x14c0f000 + 0x100 * (x))

#define i2c_reg_read(r)		sys_read32(hci->base_regs + (r))
#define i2c_reg_write(r, v)		sys_write32(v, hci->base_regs + (r))
#define i2c_g_reg_write(r, v)		sys_write32(v, hci->global_regs + (r))

#define DBG(...)

uint8_t i2c_buff[I2C_BUFFER_SIZE];

#define field_prep(_mask, _val) (((_val) << (ffs(_mask) - 1)) & (_mask))

static void i2c_pinctrl_setting(uint8_t index)
{
	uint32_t mask, value, bit_shift, gpio_group;

	bit_shift = (index & 0x3) << 3;
	mask = GENMASK(7 + bit_shift, 0 + bit_shift);
	gpio_group = index >> 2;

	/* i2c0 - i2c11 are F1, i2c12 - i2c15 are F2 */
	if (gpio_group < 3)
		value = field_prep(mask, I2C_MULTI_FUN1);
	else
		value = field_prep(mask, I2C_MULTI_FUN2);

	switch (gpio_group) {
	case 0:
		clrsetbits_le32(SCU1_PINMUX_GRP_V, mask, value);
		break;
	case 1:
		clrsetbits_le32(SCU1_PINMUX_GRP_W, mask, value);
		break;
	case 2:
		clrsetbits_le32(SCU1_PINMUX_GRP_X, mask, value);
		break;
	case 3:
		clrsetbits_le32(SCU1_PINMUX_GRP_I, mask, value);
	default:
		break;
	}
}

int i2c_global_init(struct i2c_hci *hci)
{
	/* clear master slave irq registers */
	i2c_g_reg_write(I2CG_MIRQ, 0);
	i2c_g_reg_write(I2CG_SIRQ, 0);

	/* set control register */
	i2c_g_reg_write(I2CG_CTRL, (I2CG_CTRL_NEW_REG | I2CG_CTRL_NEW_CLK_DIV));

	/* clear ac timing */
	i2c_g_reg_write(I2CG_AC_CTRL, 0);

	/* sram fifo setting */
	i2c_g_reg_write(I2CG_FIFO_CFG0, I2C_FIFO_DEFAULT);
	i2c_g_reg_write(I2CG_FIFO_CFG1, I2C_FIFO_DEFAULT);

	return 0;
}

int i2c_device_init(struct i2c_hci *hci)
{
	/* disable slave address */
	i2c_reg_write(I2CS_ADDR_1, 0x0);
	i2c_reg_write(I2CS_ADDR_2, 0x0);

	/* enable slave control register */
	i2c_reg_write(I2CC_FUN_CTRL, I2CC_SLAVE_EN);

	/* set ac timing register */
	i2c_reg_write(I2CC_AC_TIMING, I2CC_AC_VAL);

	/* close slave interrupt and clear interrupt status */
	i2c_reg_write(I2CS_IER, 0x0);
	i2c_reg_write(I2CS_ISR, 0xFFFFFFFF);

	/* set slave dma rx base */
	i2c_reg_write(I2CS_RX_DMA, (uint32_t)(&i2c_buff));
	i2c_reg_write(I2CS_RX_DMA_H, 0x0);

	/* set slave dma rx length */
	i2c_reg_write(I2CS_DMA_LEN, I2CS_DMA_RX_LEN_SET);

	/* set slave address disable */
	i2c_reg_write(I2CS_ADDR_1, hci->slave_addr_disable);

	/* set slave cmd */
	i2c_reg_write(I2CS_CMD_STS, I2CS_FIRE_CMD);

	return 0;
}

void trigger_i2c_slave(struct i2c_hci *hci)
{
	/* set slave cmd */
	i2c_reg_write(I2CS_CMD_STS, I2CS_FIRE_CMD);
	/* clear interrupt status */
	i2c_reg_write(I2CS_ISR, hci->irq_status);
	i2c_reg_read(I2CS_ISR);
}

void clear_i2c_cmd_info(void)
{
	/* clear i2c command and length informaion */
	i2c_buff[0] = 0x0;
	i2c_buff[1] = 0x0;
}

int i2c_poll_in_forever(struct i2c_hci *hci, uint32_t *size)
{
	uint32_t status = 0, length = 0;

	while (true) {
		status = i2c_reg_read(I2CS_ISR);
		if (status & (I2CS_RX_DONE | I2CS_RX_STOP)) {
			length = i2c_reg_read(I2CS_LENGTH);
			*size = (length >> 16) & 0xFFFF;
			hci->irq_status = status;

			break;
		}
	}
	return 0;
}

static int i2c_init(struct device *dev)
{
	struct i2c_hci *hci = DEV_DATA(dev);
	uint32_t regval;

	/* get the otp setting for i2c recovery */
	regval = sys_read32(SCU1_OTPCFG_15_14);
	hci->index = FIELD_GET(SCU1_OTPCFG15_I3C_I2C_CH, regval);
	hci->slave_addr_disable = FIELD_GET(SCU1_OTPCFG15_I2C_SLAVE_ADDR, regval);

	/* fill the salve address */
	if (hci->slave_addr_disable < 0x8 || hci->slave_addr_disable > 0x77) {
		hci->slave_addr_disable = I2CS_DIS_ADDR;
		hci->slave_addr_enable = I2CS_EN_ADDR;
	} else {
		hci->slave_addr_enable = (hci->slave_addr_disable | I2CS_ENABLE_ADDR0);
	}

	/* initial register base */
	hci->global_regs = (mem_addr_t)I2C_REG(0);
	hci->base_regs = (mem_addr_t)I2C_REG(hci->index + 1);

	DBG("Choice I2C%d for recovery\n", hci->index);

	i2c_pinctrl_setting(hci->index);

	/* assert reset */
	sys_write32(SCU1_RSTCTL2_I2C, SCU1_RSTCTL2);
	sys_read32(SCU1_RSTCTL2);
	/* clk gate */
	sys_write32(SCU1_CLKGATE1_I2C, SCU1_CLKGATE1);
	sys_read32(SCU1_CLKGATE1);
	/* udelay(1); */
	/* de-assert reset and delay */
	/* clk ungate */
	sys_write32(SCU1_CLKGATE1_CLR_I2C, SCU1_CLKGATE1_CLR);
	sys_read32(SCU1_CLKGATE1_CLR);
	sys_write32(SCU1_RSTCTL2_CLR_I2C, SCU1_RSTCTL2_CLR);
	sys_read32(SCU1_RSTCTL2_CLR);
	/* mdelay(1); */

	/* set global register setting */
	i2c_global_init(hci);

	/* set device register setting */
	i2c_device_init(hci);

	return 0;
}

static int i2c_load(struct device *dev, uint32_t *dst, uint32_t *len)
{
	struct i2c_hci *hci = DEV_DATA(dev);
	uint32_t size, received_size = 0;
	uint8_t *io_sram_ptr = NULL;
	int ret = 0;
	struct i2c_recovey_packet const *hdr;

	io_sram_ptr = (uint8_t *)dst;

	DBG("dst: 0x%x, length: %x\n", (uint32_t)dst, len);
	DBG("i2c buf: 0x%x\n", (uint32_t)i2c_buff);

	/* clear buffer info */
	clear_i2c_cmd_info();

	/* set slave address enable */
	i2c_reg_write(I2CS_ADDR_1, hci->slave_addr_enable);

	while (1) {
		ret = i2c_poll_in_forever(hci, &size);
		if (!ret) {
			hdr = (struct i2c_recovey_packet *)i2c_buff;
			DBG("command: 0x%x, length: %x\n", hdr->command, hdr->len);
			DBG("got: 0x%x bytes\n", (uint32_t)size);
			for (uint32_t i = 0; i < hdr->len; i++)
				DBG("%x ", hdr->payload[i]);
			DBG("\n");

			if (hdr->command == OCP_REC_CTRL) {
				if (hdr->len != OCP_REC_CTRL_BYTES)
					continue;

				if (hdr->payload[OCP_REC_CTRL_CMS_BYTE] == 0 &&
				    hdr->payload[OCP_REC_CTRL_IMG_SEL_BYTE] == OCP_REC_CTRL_IMG_SEL_CMS &&
				    hdr->payload[OCP_REC_CTRL_ACTIVATE_BYTE] == OCP_REC_CTRL_ACTIVATE_REC_IMG) {
					/* set slave address disable */
					i2c_reg_write(I2CS_ADDR_1, hci->slave_addr_disable);

					/* Need clear status and trigger */
					trigger_i2c_slave(hci);
					break;
				}
			} else if (hdr->command == OCP_INDIRECT_DATA) {
				/* if received data bytes would not fit with package length */
				if (size >= hdr->len) {
					received_size += hdr->len;
					// if (received_size > len)
					//	return REC_ERR_LARGE_IMG_SZ;
					memcpy(io_sram_ptr, hdr->payload, hdr->len);
					io_sram_ptr += hdr->len;
				}

				/* clear buffer info */
				clear_i2c_cmd_info();
			}

			/* trigger next i2c command */
			trigger_i2c_slave(hci);
		} else {
			break;
		}
	}

	printf("received_size = %x\n", received_size);
	*len = received_size;

	return ret;
}

void i2c_deinit(void)
{
	/* assert reset */
	sys_write32(SCU1_RSTCTL2_I2C, SCU1_RSTCTL2);
	/* clk gate */
	sys_write32(SCU1_CLKGATE1_I2C, SCU1_CLKGATE1);
}

static struct ast_loader_ops booti2c_ops = {
	.init = i2c_init,
	.load = i2c_load,
};

int i2c_register(struct ast_loader *loader)
{
	struct device *dev;

	dev = (struct device *)device_get_binding("i2c@recovery");
	if (!dev) {
		LOG_ERR("No device named i2c");
		return -1;
	}

	loader->ops = &booti2c_ops;
	loader->dev = dev;

	LOG_DBG("I2C loader registered");

	return 0;
}

DEVICE_DEFINE(i2c, "i2c@recovery", NULL, NULL,
		&g_i2c_hci, NULL,
		POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		NULL);
