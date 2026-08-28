/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_EXAMPLE_PLATFORM_ATTESTATION_H
#define COMPOSITE_EAT_EXAMPLE_PLATFORM_ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#include "composite_eat/types.h"

/*
 * begin_identity pins one authorized signing identity. Certificate views stay
 * immutable and valid until end_identity. The identity handle is opaque and is
 * passed only to sign_es384_digest and end_identity.
 *
 * hash_finish consumes a successful hash operation; hash_abort ends an active
 * operation after any failure. sign_es384_digest returns fixed-width P-384
 * integers as raw r || s, 48 bytes each. All callbacks and context remain
 * immutable while the provider is in use.
 */
struct example_attestation_provider {
    void *context;
    int (*begin_identity)(void *context, void **identity_handle,
                          struct composite_eat_attestation_identity *identity);
    int (*hash_start_sha384)(void *context, void **hash_handle);
    int (*hash_update)(void *context, void *hash_handle, const uint8_t *data, size_t length);
    int (*hash_finish)(void *context, void *hash_handle,
                       uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH]);
    void (*hash_abort)(void *context, void *hash_handle);
    int (*sign_es384_digest)(void *context, void *identity_handle,
                             const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                             uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]);
    void (*end_identity)(void *context, void *identity_handle);
};

#endif
