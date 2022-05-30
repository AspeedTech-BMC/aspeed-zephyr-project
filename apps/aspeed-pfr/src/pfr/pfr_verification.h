/*
 * Copyright (c) 2022 ASPEED Technology Inc.
 *
 * SPDX-License-Identifier: MIT
 */

#pragma once


int authentication_image(void *AoData, void *EventContext);

// -- Active Region
int ActivePfmVerification(unsigned int ImageType, unsigned int ReadAddress);
int PfmSpiRegionVerification(unsigned int ImageId, unsigned int FlashSelect);

// -- Recovery Region
int RecoveryRegionVerification(int ImageType);

