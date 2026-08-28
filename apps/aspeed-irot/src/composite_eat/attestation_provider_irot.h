/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <composite_eat/types.h>

struct example_attestation_context {
    const struct composite_eat_der_certificate *certificates;
    size_t certificate_count;
};

int begin_identity(void *context, void **identity_handle,
                          struct composite_eat_attestation_identity *identity);


int hash_start_sha384(void *context, void **hash_handle);
int hash_update(void *context, void *hash_handle, const uint8_t *data, size_t length);
int hash_finish(void *context, void *hash_handle,
                       uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH]);
void hash_abort(void *context, void *hash_handle);
int sign_es384_digest(void *context, void *identity_handle,
                             const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                             uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]);
void end_identity(void *context, void *identity_handle);

