/* SPDX-License-Identifier: Apache-2.0 */

#include <string.h>

#include "composite_eat/types.h"

static bool environment_valid(const uint8_t *environment, size_t length) {
    size_t index;

    if ((length < 5u) || (memcmp(environment, "env.", 4u) != 0) ||
        (environment[length - 1u] == '.')) {
        return false;
    }
    for (index = 4u; index < length; ++index) {
        uint8_t character = environment[index];

        if (character == '.') {
            if (environment[index - 1u] == '.') {
                return false;
            }
        } else if (!((character >= 'a' && character <= 'z') ||
                     (character >= '0' && character <= '9') || character == '-')) {
            return false;
        }
    }
    return true;
}

enum composite_eat_status
composite_eat_validate_generation_request(const struct composite_eat_generation_request *request) {
    size_t record;
    size_t previous;

    if ((request == NULL) || (request->version != COMPOSITE_EAT_GENERATION_REQUEST_VERSION) ||
        (request->nonce_length < COMPOSITE_EAT_MIN_NONCE_LENGTH) ||
        (request->nonce_length > COMPOSITE_EAT_MAX_NONCE_LENGTH) ||
        (request->record_count > COMPOSITE_EAT_MAX_DEVICE_RECORDS)) {
        return COMPOSITE_EAT_BAD_ARGUMENT;
    }

    for (record = 0; record < request->record_count; ++record) {
        const struct composite_eat_device_record *current = &request->records[record];

        if ((current->environment_length == 0u) ||
            (current->environment_length > COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH) ||
            (memchr(current->environment, '\0', current->environment_length) != NULL) ||
            !environment_valid(current->environment, current->environment_length)) {
            return COMPOSITE_EAT_BAD_ARGUMENT;
        }
        for (previous = 0; previous < record; ++previous) {
            const struct composite_eat_device_record *candidate = &request->records[previous];

            if ((candidate->environment_length == current->environment_length) &&
                (memcmp(candidate->environment, current->environment,
                        current->environment_length) == 0)) {
                return COMPOSITE_EAT_BAD_ARGUMENT;
            }
        }
    }

    return COMPOSITE_EAT_OK;
}
