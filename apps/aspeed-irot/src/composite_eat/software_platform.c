/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <string.h>

#include "composite_eat/token_builder.h"
#include "software_platform.h"

static void clear_bytes(void *data, size_t length) {
    volatile uint8_t *cursor = data;

    while (length-- > 0u) {
        *cursor++ = 0u;
    }
}

int example_generate_composite_eat(const struct example_attestation_provider *attestation_provider,
                                   const struct example_evidence_provider *evidence_provider,
                                   const struct composite_eat_generation_request *request,
                                   struct composite_eat_workspace *workspace, uint8_t *response,
                                   size_t response_capacity, size_t *response_length) {
    struct composite_eat_attestation_identity identity = {0};
    struct composite_eat_evidence_snapshot evidence = {0};
    struct composite_eat_prepared prepared = {0};
    void *identity_handle = NULL;
    void *evidence_handle = NULL;
    void *hash_handle = NULL;
    uint8_t thumbprint[COMPOSITE_EAT_SHA384_LENGTH] = {0};
    uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH] = {0};
    uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH] = {0};
    const uint8_t *part;
    size_t part_length;
    enum composite_eat_status status;
    int result = COMPOSITE_EAT_STATE_ERROR;
    bool identity_started = false;
    bool evidence_started = false;
    bool hash_started = false;

    if (workspace == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    composite_eat_clear(workspace, &prepared);
    if (response_length == NULL) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }
    *response_length = 0u;
    if ((response == NULL) && (response_capacity != 0u)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    if ((attestation_provider == NULL) || (attestation_provider->begin_identity == NULL) ||
        (attestation_provider->hash_start_sha384 == NULL) ||
        (attestation_provider->hash_update == NULL) ||
        (attestation_provider->hash_finish == NULL) || (attestation_provider->hash_abort == NULL) ||
        (attestation_provider->sign_es384_digest == NULL) ||
        (attestation_provider->end_identity == NULL) || (evidence_provider == NULL) ||
        (evidence_provider->begin_snapshot == NULL) || (evidence_provider->end_snapshot == NULL) ||
        (composite_eat_validate_generation_request(request) != COMPOSITE_EAT_OK)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    if (evidence_provider->begin_snapshot(evidence_provider->context, &evidence_handle,
                                          &evidence) != 0) {
        goto cleanup;
    }
    evidence_started = true;
    if (composite_eat_validate_evidence_snapshot(&evidence) != COMPOSITE_EAT_OK) {
        result = COMPOSITE_EAT_BAD_ARGUMENT;
        goto cleanup;
    }

    if (attestation_provider->begin_identity(attestation_provider->context, &identity_handle,
                                             &identity) != 0) {
        goto cleanup;
    }
    identity_started = true;
    if (composite_eat_validate_attestation_identity(&identity) != COMPOSITE_EAT_OK) {
        result = COMPOSITE_EAT_BAD_ARGUMENT;
        goto cleanup;
    }

    if (attestation_provider->hash_start_sha384(attestation_provider->context, &hash_handle) != 0) {
        goto cleanup;
    }
    hash_started = true;
    if ((attestation_provider->hash_update(attestation_provider->context, hash_handle,
                                           identity.certificates[0].data,
                                           identity.certificates[0].length) != 0) ||
        (attestation_provider->hash_finish(attestation_provider->context, hash_handle,
                                           thumbprint) != 0)) {
        goto cleanup;
    }
    hash_started = false;
    hash_handle = NULL;

    status = composite_eat_prepare(request, &evidence, &identity, thumbprint, workspace, &prepared);
    if (status != COMPOSITE_EAT_OK) {
        result = status;
        goto cleanup;
    }

    if (attestation_provider->hash_start_sha384(attestation_provider->context, &hash_handle) != 0) {
        goto cleanup;
    }
    hash_started = true;
    while ((status = composite_eat_signing_input_next(&prepared, &part, &part_length)) ==
           COMPOSITE_EAT_OK) {
        if (attestation_provider->hash_update(attestation_provider->context, hash_handle, part,
                                              part_length) != 0) {
            goto cleanup;
        }
    }
    if ((status != COMPOSITE_EAT_DONE) ||
        (attestation_provider->hash_finish(attestation_provider->context, hash_handle, digest) !=
         0)) {
        goto cleanup;
    }
    hash_started = false;
    hash_handle = NULL;

    if (attestation_provider->sign_es384_digest(attestation_provider->context, identity_handle,
                                                digest, signature) != 0) {
        goto cleanup;
    }
    result =
        composite_eat_finish(&prepared, signature, response, response_capacity, response_length);

cleanup:
    if (hash_started) {
        attestation_provider->hash_abort(attestation_provider->context, hash_handle);
    }
    if (identity_started) {
        attestation_provider->end_identity(attestation_provider->context, identity_handle);
    }
    if (evidence_started) {
        evidence_provider->end_snapshot(evidence_provider->context, evidence_handle);
    }
    clear_bytes(&identity_handle, sizeof(identity_handle));
    clear_bytes(&evidence_handle, sizeof(evidence_handle));
    clear_bytes(&hash_handle, sizeof(hash_handle));
    clear_bytes(&identity, sizeof(identity));
    clear_bytes(&evidence, sizeof(evidence));
    clear_bytes(thumbprint, sizeof(thumbprint));
    clear_bytes(digest, sizeof(digest));
    clear_bytes(signature, sizeof(signature));
    composite_eat_clear(workspace, &prepared);
    return result;
}
