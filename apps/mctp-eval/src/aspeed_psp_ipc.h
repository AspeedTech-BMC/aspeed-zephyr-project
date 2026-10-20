/* Licensed under the Apache-2.0 license */

/*
 * PSP (Cortex-M4) <-> SS-MCU IPC protocol, for the PSP's C firmware.
 * Copy of caliptra-mcu-sw common/aspeed-ipc-protocol/include/aspeed_psp_ipc.h,
 * the C mirror of that crate's src/psp_spdm.rs, which holds the full
 * description of the descriptor and its rules.
 *
 * IPC bank 4 carries PSP -> SS-MCU, bank 5 SS-MCU -> PSP:
 *   IPI0: SPDM channel (REQUEST from the PSP, RESPONSE from the SS-MCU)
 *   IPI1: control (REQ_ACK and SYNC_ACK from the SS-MCU, RSP_ACK and SYNC
 *         from the PSP); each buffer has one owner, and an ACK hands it back
 *   IPI2: reserved for the callback channel, which needs a window of its own
 * Each IPI carries a 7-word descriptor; message bodies sit in a shared
 * window whose address each platform defines (on AST1080, the PSP's IPC
 * channel 0 window: requests in its TX half, responses in its RX half).
 */

#ifndef ASPEED_PSP_IPC_H_
#define ASPEED_PSP_IPC_H_

#define PSP_SPDM_IPI			0
#define PSP_SPDM_ACK_IPI		1
#define PSP_SPDM_CB_IPI			2

#define PSP_SPDM_SHM_SIZE		0x2000u
#define PSP_SPDM_REQ_OFFSET		0x0000u
#define PSP_SPDM_RSP_OFFSET		0x1000u
#define PSP_SPDM_BUF_SIZE		0x1000u

#define PSP_SPDM_MAX_MSG_SIZE		1024u

#define PSP_SPDM_OP_REQUEST		0x51445053u /* "SPDQ" */
#define PSP_SPDM_OP_RESPONSE		0x52445053u /* "SPDR" */
#define PSP_SPDM_OP_REQ_ACK		0x41445053u /* "SPDA" */
#define PSP_SPDM_OP_RSP_ACK		0x4b445053u /* "SPDK" */
#define PSP_SPDM_OP_SYNC		0x53445053u /* "SPDS" */
#define PSP_SPDM_OP_SYNC_ACK		0x59445053u /* "SPDY" */
#define PSP_SPDM_OP_CB_REQUEST		0x51435053u /* "SPCQ" */
#define PSP_SPDM_OP_CB_RESPONSE		0x52435053u /* "SPCR" */

#define PSP_SPDM_WORD_OP		0
#define PSP_SPDM_WORD_SEQ		1
#define PSP_SPDM_WORD_OFFSET		2
#define PSP_SPDM_WORD_LEN		3
#define PSP_SPDM_WORD_STATUS		4
#define PSP_SPDM_WORD_VERSION		5
#define PSP_SPDM_DESC_WORDS		7

#define PSP_SPDM_PROTO_VERSION		2u

#define PSP_SPDM_STATUS_OK		0u
#define PSP_SPDM_STATUS_REJECTED	1u
#define PSP_SPDM_STATUS_TOO_LARGE	2u
#define PSP_SPDM_STATUS_VERSION		3u

#endif /* ASPEED_PSP_IPC_H_ */
