#pragma once
#include <stdint.h>
#include <mctp.h>

uint8_t mctp_spdm_cmd_handler(void *mctp_p, uint8_t *buf, uint32_t len, mctp_ext_params ext_params);
