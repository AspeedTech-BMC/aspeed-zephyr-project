/*
 * Copyright (c) 2026 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <composite_eat/types.h>


struct test_context {
    const struct composite_eat_evidence_snapshot *evidence;
    const struct composite_eat_attestation_identity *identity;
    bool fail_hash_update;
};

struct example_evidence_context {
    const struct composite_eat_evidence_snapshot *evidence;
};

int begin_snapshot(void *context, void **snapshot_handle,
                          struct composite_eat_evidence_snapshot *evidence);
void end_snapshot(void *context, void *snapshot_handle);
