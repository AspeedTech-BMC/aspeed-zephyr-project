# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE
	SPDMBuffer.c
	SPDMContext.c
	SPDMCrypto.c
	SPDMMain.c
	SPDMMctpBinding.c

	# Attester
	SPDMRequester.c
	RequestCmd/SPDMGetDigests.c
	RequestCmd/SPDMNegotiateAlgorithms.c
	RequestCmd/SPDMChallenge.c
	RequestCmd/SPDMGetCertificate.c
	RequestCmd/SPDMGetVersion.c
	RequestCmd/SPDMGetCapabilities.c
	RequestCmd/SPDMGetMeasurements.c

	# Attestee
	SPDMResponder.c
	ResponseCmd/SPDMDigests.c
	ResponseCmd/SPDMCapabilities.c
	ResponseCmd/SPDMAlgorithms.c
	ResponseCmd/SPDMMeasurements.c
	ResponseCmd/SPDMCertificate.c
	ResponseCmd/SPDMVersion.c
	ResponseCmd/SPDMChallengeAuth.c
	)

# Request Commands
