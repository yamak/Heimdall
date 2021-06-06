/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#ifndef HEIMDALL_H
#define HEIMDALL_H

#include "heimdall_config.h"
#include <tee_api_defines.h>
#include <stdint.h>


#define HASH_ALGO TEE_ALG_SHA256

typedef enum 
{
    HEIMDALL_SUCCESS=0,
    HEIMDALL_UNEXPECTED_DIGEST,
    HEIMDALL_UNREGISTERED_ELF,
    HEIMDALL_OTHER
} heimdall_return_t;

struct anomaly_info
{
    unsigned char expected_digest[DIGEST_SIZE];
    unsigned char unexpected_digest[DIGEST_SIZE];
    char elf_name[DNAME_INLINE_LEN];
    unsigned int page_number;
    char unregistered_elf_name[DNAME_INLINE_LEN];
};

heimdall_return_t heimdall_start(uint64_t init_task_addr);
const struct anomaly_info* heimdall_get_anomaly_info(void);

#endif //HEIMDALL
