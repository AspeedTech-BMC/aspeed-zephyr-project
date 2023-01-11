/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

struct spdm_buffer {
	size_t size;
	size_t write_ptr;
	size_t read_ptr;
	void *data;
};

int spdm_buffer_init(struct spdm_buffer *buffer, size_t size);
int spdm_buffer_resize(struct spdm_buffer *buffer, size_t size);
int spdm_buffer_release(struct spdm_buffer *buffer);

int spdm_buffer_append_array(struct spdm_buffer *buffer, void *data, size_t size);
int spdm_buffer_append_u8(struct spdm_buffer *buffer, uint8_t data);
int spdm_buffer_append_u16(struct spdm_buffer *buffer, uint16_t data);
int spdm_buffer_append_u24(struct spdm_buffer *buffer, uint32_t data);
int spdm_buffer_append_u32(struct spdm_buffer *buffer, uint32_t data);
int spdm_buffer_append_nonce(struct spdm_buffer *buffer);
int spdm_buffer_append_reserved(struct spdm_buffer *buffer, size_t size);

int spdm_buffer_get_array(struct spdm_buffer *buffer, void *data, size_t size);
int spdm_buffer_get_u8(struct spdm_buffer *buffer, uint8_t *data);
int spdm_buffer_get_u16(struct spdm_buffer *buffer, uint16_t *data);
int spdm_buffer_get_u24(struct spdm_buffer *buffer, uint32_t *data);
int spdm_buffer_get_u32(struct spdm_buffer *buffer, uint32_t *data);
int spdm_buffer_get_reserved(struct spdm_buffer *buffer, size_t size);
