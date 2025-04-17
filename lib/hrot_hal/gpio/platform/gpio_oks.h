/*
 * Copyright (c) 2025 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdbool.h>

void AUXPowerGoodControl(bool assert);
void HPMStandbyReset(bool assert);
void S0AttestationDone(bool assert);
void S5AttestationDone(bool assert);
void BtgAttestationDone(bool assert);
void ClearBtgAttestation(void);
void ClearS0Attestation(void);
void ClearS5Attestation(void);
