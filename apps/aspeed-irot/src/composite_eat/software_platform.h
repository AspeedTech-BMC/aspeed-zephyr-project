/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_EXAMPLE_SOFTWARE_PLATFORM_H
#define COMPOSITE_EAT_EXAMPLE_SOFTWARE_PLATFORM_H

#include "platform_attestation.h"
#include "platform_evidence.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Demonstrate one complete synchronous RoT generation operation. Provider
 * failures return COMPOSITE_EAT_STATE_ERROR; SDK validation and encoding
 * failures are returned unchanged. response=NULL with zero capacity performs
 * a required-length query, but the providers still hash and sign the token.
 * Operation state and local cryptographic intermediates are overwritten before
 * return whenever workspace is non-NULL. A non-NULL response_length is set to
 * zero on errors other than BUFFER_TOO_SMALL. All output objects and buffers
 * must be distinct from each other and from provider-owned input storage.
 */
int example_generate_composite_eat(const struct example_attestation_provider *attestation_provider,
                                   const struct example_evidence_provider *evidence_provider,
                                   const struct composite_eat_generation_request *request,
                                   struct composite_eat_workspace *workspace, uint8_t *response,
                                   size_t response_capacity, size_t *response_length);

#ifdef __cplusplus
}
#endif

#endif
