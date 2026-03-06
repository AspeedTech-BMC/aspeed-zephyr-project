/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <image/firmware_manifest.h>


int simple_manifest_verify(const char* device_name, size_t offset)
{
	// Simple verification logic (placeholder)
	return 0; // Return 0 for success
}

int simple_load_image()
{
	// Simple image loading logic (placeholder)
	return 0; // Return 0 for success
}

struct simple_manifest {

};

struct firmware_manifest_handler simple_image_handler = {
	.manifest_context = NULL,
	.verify_manifest = simple_manifest_verify,
	.load_image = simple_load_image,
};

