/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef PFR_VERIFICATION_H
#define PFR_VERIFICATION_H


int authentication_image(void *AoData, void *EventContext);

// -- Active Region
int ActivePfmVerification(unsigned int ImageType,unsigned int ReadAddress);
int PfmSpiRegionVerification(unsigned int ImageId, unsigned int FlashSelect);

// -- Recovery Region
int RecoveryRegionVerification(int ImageType);

#endif /* PFR_VERIFICATION_H */
