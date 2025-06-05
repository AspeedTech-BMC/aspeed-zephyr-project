// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) Aspeed Technology Inc.
 */

#include <sdram_ast2700.h>
#include <fmc_hdr.h>
#include <string.h>

static int fmc_hdr_v1_get_prebuilt(struct fmc_hdr_v1 *hdr, uint32_t type, uint32_t *ofst, uint32_t *size)
{
	struct fmc_hdr_preamble_v1 *preamble;
	struct fmc_hdr_body_v1 *body;
	uint32_t pb_size, pb_max, t, s, o;
	int i;

	preamble = &hdr->preamble;
	body = &hdr->body;
	pb_size = sizeof(body->pbs[0]);
	pb_max = sizeof(body->raz) / pb_size;

	for (i = 0, o = sizeof(*hdr) + body->fmc_size; i < pb_max; ++i) {
		t = body->pbs[i].type;
		s = body->pbs[i].size;

		/* skip if unrecognized, yet */
		if (t >= PBT_NUM) {
			o += s;
			continue;
		}

		/* prebuilt end mark */
		if (t == 0 && s == 0)
			break;

		/* return the prebuilt info if found */
		if (t == type) {
			*ofst += o;
			*size = s;

			goto found;
		}

		/* update offset for next prebuilt */
		o += s;
	}

	return 1;

found:
	return 0;
}

static int fmc_hdr_v2_get_prebuilt(struct fmc_hdr_v2 *hdr, uint32_t type, uint32_t *ofst, uint32_t *size, uint8_t *dgst)
{
	struct fmc_hdr_preamble_v2 *preamble;
	struct fmc_hdr_body_v2 *body;
	uint32_t pb_size, pb_max, t, s, o;
	uint8_t *d;
	int i;

	preamble = &hdr->preamble;
	body = &hdr->body;
	pb_size = sizeof(body->pbs[0]);
	pb_max = sizeof(body->raz) / pb_size;

	for (i = 0, o = sizeof(*hdr) + body->fmc_size; i < pb_max; ++i) {
		t = body->pbs[i].type;
		s = body->pbs[i].size;
		d = body->pbs[i].dgst;

		/* skip if unrecognized, yet */
		if (t >= PBT_NUM) {
			o += s;
			continue;
		}

		/* prebuilt end mark */
		if (t == 0 && s == 0)
			break;

		/* return the prebuilt info if found */
		if (t == type) {
			*ofst += o;
			*size = s;

			if (dgst)
				memcpy(dgst, d, HDR_DGST_LEN);

			goto found;
		}

		/* update offset for next prebuilt */
		o += s;
	}

	return 1;

found:
	return 0;
}

#define CHIP_REVID_AST2700A0    0x06000003
#define CHIP_REVID_AST2700A1    0x06010003

int fmc_hdr_get_prebuilt(uint32_t type, uint32_t *ofst, uint32_t *size, uint8_t *dgst)
{
	struct fmc_hdr_v1 *hdr_v1;
	struct fmc_hdr_v2 *hdr_v2;
	uint32_t rev_id = sys_read32(SCU1_REVISION_ID);
	uint32_t text_ofst = (rev_id == CHIP_REVID_AST2700A1) ? 0x20000 : 0x0;

	if (type >= PBT_NUM)
		return 1;

	if (!ofst || !size)
		return 1;

	*ofst = text_ofst;

	/* try version 1 */
	hdr_v1 = (struct fmc_hdr_v1 *)(CONFIG_SRAM_BASE_ADDRESS - sizeof(*hdr_v1));
	if (hdr_v1->preamble.magic == HDR_MAGIC && hdr_v1->preamble.version == 1)
		return fmc_hdr_v1_get_prebuilt(hdr_v1, type, ofst, size);

	/* try version 2 */
	hdr_v2 = (struct fmc_hdr_v2 *)(CONFIG_SRAM_BASE_ADDRESS - sizeof(*hdr_v2));
	if (hdr_v2->preamble.magic == HDR_MAGIC && hdr_v2->preamble.version == 2)
		return fmc_hdr_v2_get_prebuilt(hdr_v2, type, ofst, size, dgst);

	return 1;
}
