/* SPDX-License-Identifier: Apache-2.0 */

#ifndef COMPOSITE_EAT_EXAMPLE_PLATFORM_EVIDENCE_H
#define COMPOSITE_EAT_EXAMPLE_PLATFORM_EVIDENCE_H

#include <stddef.h>

#include "composite_eat/types.h"

/*
 * A successful begin_snapshot pins one coherent, already serialized evidence
 * view. All returned buffers remain immutable and valid until end_snapshot.
 * Both callbacks and context remain immutable while the provider is in use.
 */
struct example_evidence_provider {
    void *context;
    int (*begin_snapshot)(void *context, void **snapshot_handle,
                          struct composite_eat_evidence_snapshot *evidence);
    void (*end_snapshot)(void *context, void *snapshot_handle);
};

#endif
