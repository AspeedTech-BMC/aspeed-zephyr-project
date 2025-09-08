/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VGA_AST2700_H
#define _VGA_AST2700_H

#include <scu_ast2700.h>

#define VGA_PACKER_CPU_BASE	(0x12c1d000)
#define VGA_RETIMER_CPU_BASE	(0x12c1d100)
#define VGA_PACKER_IO_BASE	(0x14c3a000)
#define VGA_RETIMER_IO_BASE	(0x14c3a100)

union VGA_PACKER_REG000 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_version:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x000}{Description : VGA_PACKER_REG000:VGA PACKER Version Register}{ini=0x00000110}*/

union VGA_PACKER_REG004 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_scratch_0:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x004}{Description : VGA_PACKER_REG004:VGA PACKER Scratch 0}{ini=0x00000000}*/

union VGA_PACKER_REG008 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_checksumreadonly:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x008}{Description : VGA_PACKER_REG008:VGA PACKER Checksum container}{ini=0x00000000}*/

union VGA_PACKER_REG00C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_scratch_1:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x00C}{Description : VGA_PACKER_REG00C:VGA PACKER Scratch 1}{ini=0x00000000}*/

union VGA_PACKER_REG010 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_enable:1;/*{ 0}*/
		uint32_t reg_vga_packer_enablescreenoff:1;/*{ 1}*/
		uint32_t reg_vga_packer_enablecolorbar:1;/*{ 2}*/
		uint32_t reg_vga_packer_useoriginalpolarity:1;/*{ 3}*/
		uint32_t reg_vga_packer_checksumtrigger:1;/*{ 4}*/
		uint32_t reg_vga_packer_checksumvalid:1;/*{ 5}*/
		uint32_t reg_vga_packer_useregbankpolarity:1;/*{ 6}*/
		uint32_t reg_vga_packer_dualpixelmode:1;/*{ 7}*/
		uint32_t reg_vga_packer_interlacemode:1;/*{ 8}*/
		uint32_t reg_vga_packer_hsyncpolarity:1;/*{ 9}*/
		uint32_t reg_vga_packer_vsyncpolarity:1;/*{10}*/
		uint32_t reg_vga_packer_fsyncpolarity:1;/*{11}*/
		uint32_t reg_vga_packer_depolarity:1;/*{12}*/
		uint32_t reg_vga_packer_hsyncoff:1;/*{13}*/
		uint32_t reg_vga_packer_vsyncfsyncoff:1;/*{14}*/
		uint32_t reg_vga_packer_deoff:1;/*{15}*/
		uint32_t reg_vga_packer_bypassvgaenc:1;/*{16}*/
		uint32_t reg_vga_packer_bypassvgadec:1;/*{17}*/
		uint32_t reg_vga_packer_loopbackmode:1;/*{18}*/
		uint32_t reg_vga_packer_overwriteloopbypass:1;/*{19}*/
		uint32_t reg_vga_packer_rgbordering:1;/*{20}*/
		uint32_t reg_vga_packer_overwritecpupll:1;/*{21}*/
		uint32_t reg_vga_packer_overwriteiopll:1;/*{22}*/
		uint32_t reserved31_23:9;/*{31:23}*/
	} fields;
}; /*{Offset:0x010}{Description : VGA_PACKER_REG010:VGA PACKER Control Register I}{ini=0x00030e00}*/

union VGA_PACKER_REG014 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_infifothreshold:8;/*{ 7: 0}*/
		uint32_t reg_vga_packer_outfifothreshold:8;/*{15: 8}*/
		uint32_t reserved31_16:16;/*{31:16}*/
	} fields;
}; /*{Offset:0x014}{Description : VGA_PACKER_REG014:VGA PACKER Control Register II}{ini=0x00001010}*/

union VGA_PACKER_REG018 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_c_sta_enc:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x018}{Description : VGA_PACKER_REG018:For VGA ENC counter part: Read-only}{ini=0x00000000}*/

union VGA_PACKER_REG01C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_c_cfg_enc:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x01C}{Description : VGA_PACKER_REG01C:For VGA ENC counter part: Read-write}{ini=0x0120f001}*/

union VGA_PACKER_REG020 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_enablevsynclinecount0interrupt_stat:1;/*{ 0}*/
		uint32_t reg_vga_packer_enablevsynclinecount1interrupt_stat:1;/*{ 1}*/
		uint32_t reg_vga_packer_enablevgadataunderflow_stat:1;/*{ 2}*/
		uint32_t reg_vga_packer_enablevgadataoverflow_stat:1;/*{ 3}*/
		uint32_t reg_vga_packer_ibi_msg_invalid_stat:1;/*{ 4}*/
		uint32_t reserved31_5:27;/*{31: 5}*/
	} fields;
}; /*{Offset:0x020}{Description : VGA_PACKER_REG020:Interrupt Status Register}{ini=0x00000000}*/

union VGA_PACKER_REG024 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_enablevsynclinecount0interrupt_stat_en:1;/*{ 0}*/
		uint32_t reg_vga_packer_enablevsynclinecount1interrupt_stat_en:1;/*{ 1}*/
		uint32_t reg_vga_packer_enablevgadataunderflow_stat_en:1;/*{ 2}*/
		uint32_t reg_vga_packer_enablevgadataoverflow_stat_en:1;/*{ 3}*/
		uint32_t reg_vga_packer_ibi_msg_invalid_stat_en:1;/*{ 4}*/
		uint32_t reserved31_5:27;/*{31: 5}*/
	} fields;
}; /*{Offset:0x024}{Description : VGA_PACKER_REG024:Interrupt Status Enable Register}{ini=0x00000000}*/

union VGA_PACKER_REG028 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_enablevsynclinecount0interrupt_signal_en:1;/*{ 0}*/
		uint32_t reg_vga_packer_enablevsynclinecount1interrupt_signal_en:1;/*{ 1}*/
		uint32_t reg_vga_packer_enablevgadataunderflow_signal_en:1;/*{ 2}*/
		uint32_t reg_vga_packer_enablevgadataoverflow_signal_en:1;/*{ 3}*/
		uint32_t reg_vga_packer_ibi_msg_invalid_signal_en:1;/*{ 4}*/
		uint32_t reserved31_5:27;/*{31: 5}*/
	} fields;
}; /*{Offset:0x028}{Description : VGA_PACKER_REG028:Interrupt Signal Enable Register}{ini=0x00000000}*/

union VGA_PACKER_REG02C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_enablevsynclinecount0interrupt_force:1;/*{ 0}*/
		uint32_t reg_vga_packer_enablevsynclinecount1interrupt_force:1;/*{ 1}*/
		uint32_t reg_vga_packer_enablevgadataunderflow_force:1;/*{ 2}*/
		uint32_t reg_vga_packer_enablevgadataoverflow_force:1;/*{ 3}*/
		uint32_t reg_vga_packer_ibi_msg_invalid_force:1;/*{ 4}*/
		uint32_t reserved31_5:27;/*{31: 5}*/
	} fields;
}; /*{Offset:0x02C}{Description : VGA_PACKER_REG02C:Interrupt Force Register}{ini=0x00000000}*/

union VGA_PACKER_REG030 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_h_total:14;/*{13: 0}*/
		uint32_t reserved15_14:2;/*{15:14}*/
		uint32_t reg_vga_packer_h_sync_end:14;/*{29:16}*/
		uint32_t reserved31_30:2;/*{31:30}*/
	} fields;
}; /*{Offset:0x030}{Description : VGA_PACKER_REG030:VGA PACKER CONTROL 3}{ini=0x00600320}*/

union VGA_PACKER_REG034 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_h_backporch_end:14;/*{13: 0}*/
		uint32_t reserved15_14:2;/*{15:14}*/
		uint32_t reg_vga_packer_h_display_end:14;/*{29:16}*/
		uint32_t reserved31_30:2;/*{31:30}*/
	} fields;
}; /*{Offset:0x034}{Description : VGA_PACKER_REG034:VGA PACKER CONTROL 4}{ini=0x03180090}*/

union VGA_PACKER_REG038 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_v_total:14;/*{13: 0}*/
		uint32_t reserved15_14:2;/*{15:14}*/
		uint32_t reg_vga_packer_v_sync_end:14;/*{29:16}*/
		uint32_t reserved31_30:2;/*{31:30}*/
	} fields;
}; /*{Offset:0x038}{Description : VGA_PACKER_REG038:VGA PACKER CONTROL 5}{ini=0x0002020d}*/

union VGA_PACKER_REG03C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_v_backporch_end:14;/*{13: 0}*/
		uint32_t reserved15_14:2;/*{15:14}*/
		uint32_t reg_vga_packer_v_display_end:14;/*{29:16}*/
		uint32_t reserved31_30:2;/*{31:30}*/
	} fields;
}; /*{Offset:0x03C}{Description : VGA_PACKER_REG03C:VGA PACKER CONTROL 6}{ini=0x020b0023}*/

union VGA_PACKER_REG040 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_patgen_select:2;/*{ 1: 0}*/
		uint32_t reserved7_2:6;/*{ 7: 2}*/
		uint32_t reg_vga_packer_patgen_testchannel:3;/*{10: 8}*/
		uint32_t reserved27_11:17;/*{27:11}*/
		uint32_t reg_vga_packer_patgen_enable:1;/*{28}*/
		uint32_t reserved31_29:3;/*{31:29}*/
	} fields;
}; /*{Offset:0x040}{Description : VGA_PACKER_REG040:VGA PACKER PATGEN}{ini=0x00000700}*/

union VGA_PACKER_REG044 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_wait_frame_config:16;/*{15: 0}*/
		uint32_t reg_vga_packer_wait_frame_hold:16;/*{31:16}*/
	} fields;
}; /*{Offset:0x044}{Description : VGA_PACKER_REG044:VGA PACKER WAIT_FRAME}{ini=0x00030003}*/

union VGA_PACKER_REG048 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_colorbarswitchhpoint:14;/*{13: 0}*/
		uint32_t reserved31_14:18;/*{31:14}*/
	} fields;
}; /*{Offset:0x048}{Description : VGA_PACKER_REG048:VGA PACKER ColorBarSwitchHPoint}{ini=0x00000fff}*/

union VGA_PACKER_REG04C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_framestartconfig:14;/*{13: 0}*/
		uint32_t reserved31_14:18;/*{31:14}*/
	} fields;
}; /*{Offset:0x04C}{Description : VGA_PACKER_REG04C:VGA PACKER Frame Start Config}{ini=0x00000000}*/

union VGA_PACKER_REG050 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_src_overwrite_select:2;/*{ 1: 0}*/
		uint32_t reserved27_2:26;/*{27: 2}*/
		uint32_t reg_vga_packer_src_overwrite_enable:1;/*{28}*/
		uint32_t reserved31_29:3;/*{31:29}*/
	} fields;
}; /*{Offset:0x050}{Description : VGA_PACKER_REG050:VGA PACKER SRC_OVERWRITE}{ini=0x00000000}*/

union VGA_PACKER_REG054 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_scratch_2:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x054}{Description : VGA_PACKER_REG054:VGA PACKER Scratch 2}{ini=0x00000000}*/

union VGA_PACKER_REG058 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_c_sta_dec:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x058}{Description : VGA_PACKER_REG058:For VGA DEC counter part: Read-only}{ini=0x00000000}*/

union VGA_PACKER_REG05C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_c_cfg_dec:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x05C}{Description : VGA_PACKER_REG05C:For VGA DEC counter part: Read-write}{ini=0x00000000}*/

union VGA_PACKER_REG060 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_syncreset:1;/*{ 0}*/
		uint32_t reserved31_1:31;/*{31: 1}*/
	} fields;
}; /*{Offset:0x060}{Description : VGA_PACKER_REG060:Write thru for sync reset}{ini=0x00000000}*/

union VGA_PACKER_REG064 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_force_clk_enable:1;/*{ 0}*/
		uint32_t reserved31_1:31;/*{31: 1}*/
	} fields;
}; /*{Offset:0x064}{Description : VGA_PACKER_REG064:Low power control}{ini=0x00000001}*/

union VGA_PACKER_REG068 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_vpll_postdiv:8;/*{ 7: 0}*/
		uint32_t reg_vga_packer_vpll_od:4;/*{11: 8}*/
		uint32_t reg_vga_packer_vpll_denum:6;/*{17:12}*/
		uint32_t reg_vga_packer_vpll_num:13;/*{30:18}*/
		uint32_t reg_vga_packer_vpll_toggle:1;/*{31}*/
	} fields;
}; /*{Offset:0x068}{Description : VGA_PACKER_REG068:IO Die PLL CONFIG}{ini=0x00041101}*/

union VGA_PACKER_REG06C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_vpll_bj:12;/*{11: 0}*/
		uint32_t reserved31_12:20;/*{31:12}*/
	} fields;
}; /*{Offset:0x06C}{Description : VGA_PACKER_REG06C:IO Die PLL CONFIG BJ}{ini=0x00000001}*/

union VGA_PACKER_REG070 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_debug:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x070}{Description : VGA_PACKER_REG070:VGA PACKER DEBUG}{ini=0x00000000}*/

union VGA_PACKER_REG074 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_dummy:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x074}{Description : VGA_PACKER_REG074:VGA PACKER DUMMY}{ini=0xbabecafe}*/

union VGA_PACKER_REG078 {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_monitor:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x078}{Description : VGA_PACKER_REG078:VGA PACKER MONITOR}{ini=0x00000000}*/

union VGA_PACKER_REG07C {
	uint32_t value;
	struct {
		uint32_t reg_vga_packer_monitor_mux:32;/*{31: 0}*/
	} fields;
}; /*{Offset:0x07C}{Description : VGA_PACKER_REG07C:VGA PACKER MONITOR MUX}{ini=0x00000000}*/

#ifndef __ASSEMBLY__
struct ast2700_vga_link {
	union VGA_PACKER_REG000 REG00;/*Offsert : 000, VGA PACKER Version Register*/
	union VGA_PACKER_REG004 REG04;/*Offsert : 004, VGA PACKER Scratch 0*/
	union VGA_PACKER_REG008 REG08;/*Offsert : 008, VGA PACKER Checksum container*/
	union VGA_PACKER_REG00C REG0C;/*Offsert : 00C, VGA PACKER Scratch 1*/
	union VGA_PACKER_REG010 REG10;/*Offsert : 010, VGA PACKER Control Register I*/
	union VGA_PACKER_REG014 REG14;/*Offsert : 014, VGA PACKER Control Register II*/
	union VGA_PACKER_REG018 REG18;/*Offsert : 018, For VGA ENC counter part: Read-only*/
	union VGA_PACKER_REG01C REG1C;/*Offsert : 01C, For VGA ENC counter part: Read-write*/
	union VGA_PACKER_REG020 REG20;/*Offsert : 020, Interrupt Status Register*/
	union VGA_PACKER_REG024 REG24;/*Offsert : 024, Interrupt Status Enable Register*/
	union VGA_PACKER_REG028 REG28;/*Offsert : 028, Interrupt Signal Enable Register*/
	union VGA_PACKER_REG02C REG2C;/*Offsert : 02C, Interrupt Force Register*/
	union VGA_PACKER_REG030 REG30;/*Offsert : 030, VGA PACKER CONTROL 3*/
	union VGA_PACKER_REG034 REG34;/*Offsert : 034, VGA PACKER CONTROL 4*/
	union VGA_PACKER_REG038 REG38;/*Offsert : 038, VGA PACKER CONTROL 5*/
	union VGA_PACKER_REG03C REG3C;/*Offsert : 03C, VGA PACKER CONTROL 6*/
	union VGA_PACKER_REG040 REG40;/*Offsert : 040, VGA PACKER PATGEN*/
	union VGA_PACKER_REG044 REG44;/*Offsert : 044, VGA PACKER WAIT_FRAME*/
	union VGA_PACKER_REG048 REG48;/*Offsert : 048, VGA PACKER ColorBarSwitchHPoint*/
	union VGA_PACKER_REG04C REG4C;/*Offsert : 04C, VGA PACKER Frame Start Config*/
	union VGA_PACKER_REG050 REG50;/*Offsert : 050, VGA PACKER SRC_OVERWRITE*/
	union VGA_PACKER_REG054 REG54;/*Offsert : 054, VGA PACKER Scratch 2*/
	union VGA_PACKER_REG058 REG58;/*Offsert : 058, For VGA DEC counter part: Read-only*/
	union VGA_PACKER_REG05C REG5C;/*Offsert : 05C, For VGA DEC counter part: Read-write*/
	union VGA_PACKER_REG060 REG60;/*Offsert : 060, Write thru for sync reset*/
	union VGA_PACKER_REG064 REG64;/*Offsert : 064, Low power control*/
	union VGA_PACKER_REG068 REG68;/*Offsert : 068, IO Die PLL CONFIG*/
	union VGA_PACKER_REG06C REG6C;/*Offsert : 06C, IO Die PLL CONFIG BJ*/
	union VGA_PACKER_REG070 REG70;/*Offsert : 070, VGA PACKER DEBUG*/
	union VGA_PACKER_REG074 REG74;/*Offsert : 074, VGA PACKER DUMMY*/
	union VGA_PACKER_REG078 REG78;/*Offsert : 078, VGA PACKER MONITOR*/
	union VGA_PACKER_REG07C REG7C;/*Offsert : 07C, VGA PACKER MONITOR MUX*/
};
#endif

int vga_init(struct ast2700_scu0 *scu);

#endif
