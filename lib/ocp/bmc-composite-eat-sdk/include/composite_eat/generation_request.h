/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_GENERATION_REQUEST_H
#define COMPOSITE_EAT_GENERATION_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#include "composite_eat/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Decode one complete schema-version-1 generation request. The encoded input
 * and output object must not overlap. The decoder rejects tags, indefinite
 * containers, unknown or duplicate fields, invalid bounds, invalid identifiers,
 * and trailing data. A non-NULL output object is cleared on every failure.
 * Returns OK, BAD_ARGUMENT, MALFORMED_REQUEST, BAD_VERSION, or
 * TOO_MANY_RECORDS.
 */
enum composite_eat_status
composite_eat_generation_request_decode(const uint8_t *encoded, size_t encoded_length,
                                        struct composite_eat_generation_request *request);

/*
 * Encode one validated typed request as deterministic, definite-length CBOR.
 * encoded and encoded_length must not overlap request or each other.
 * Call with encoded=NULL and encoded_capacity=0 to query the required length.
 * COMPOSITE_EAT_BUFFER_TOO_SMALL leaves encoded untouched and sets
 * *encoded_length to the required capacity. Other failures set a non-NULL
 * *encoded_length to zero; encoded content is unspecified on encoding error.
 *
 * A successful RoT response is not decoded by this codec. Its response body is
 * the IETF-profiled CWT(COSE_Sign1) Composite EAT main token. Command status,
 * required response length, and transfer metadata belong to the platform
 * transport rather than to a second SDK wire schema.
 * Returns OK, BAD_ARGUMENT, BUFFER_TOO_SMALL, or ENCODING_ERROR.
 */
enum composite_eat_status
composite_eat_generation_request_encode(const struct composite_eat_generation_request *request,
                                        uint8_t *encoded, size_t encoded_capacity,
                                        size_t *encoded_length);

#ifdef __cplusplus
}
#endif

#endif
