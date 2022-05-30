/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <stdint.h>

int pfr_spi_read(uint8_t device_id, uint32_t address,
		 uint32_t data_length, uint8_t *data);

int pfr_spi_write(uint8_t device_id, uint32_t address,
		  uint32_t data_length, uint8_t *data);

int pfr_spi_page_read_write(uint8_t device_id, uint32_t source_address, uint32_t target_address);

int pfr_spi_erase_4k(uint8_t device_id, uint32_t address);

int pfr_spi_erase_block(uint8_t device_id, uint32_t address);

int pfr_spi_erase_region(uint8_t device_id,
		bool support_block_erase, uint32_t start_addr, uint32_t nbytes);

int pfr_spi_region_read_write_between_spi(uint8_t src_dev, uint32_t src_addr,
		uint8_t dest_dev, uint32_t dest_addr, size_t length);

int pfr_spi_get_block_size(uint8_t device_id);

int esb_ecdsa_verify(struct pfr_manifest *manifest, uint32_t digest[], uint8_t pub_key[],
		     uint8_t signature[], uint8_t *auth_pass);

int get_buffer_hash(struct pfr_manifest *manifest, uint8_t *data_buffer, uint8_t length, uint8_t *hash_out);

int get_hash(struct manifest *manifest, struct hash_engine *hash_engine, uint8_t *hash_out,
	     size_t hash_length);

void print_buffer(uint8_t *string, uint8_t *buffer, uint32_t length);

int compare_buffer(uint8_t *buffer1, uint8_t *buffer2, uint32_t length);

void reverse_byte_array(uint8_t *data_buffer, uint32_t length);

int verify_signature(struct signature_verification *verification, const uint8_t *digest,
		     size_t length, const uint8_t *signature, size_t sig_length);

int pfr_cpld_update_reboot(void);

