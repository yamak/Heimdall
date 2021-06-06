/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#include <trace.h>
#include <kernel/pseudo_ta.h>
#include <kernel/panic.h>
#include <mm/tee_mm.h>
#include <mm/core_memprot.h>
#include "heimdall.h"

#define TA_HEIMDALL_UUID \
	{ 0xa20a9678, 0xb4e8, 0x11eb, \
		{ 0x85, 0x29, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03} }

#define TA_NAME		"heimdall.ta"

#define TA_HEIMDALL_CMD_START_VALUE		0

// L1 and L2 translation tables are statically allocated and initialized at boot.
// Because of these, physical address that will be used at run time must be registered.
register_phys_mem(MEM_AREA_RAM_NSEC,0x8000,0x10000000-0x8000);
register_phys_mem(MEM_AREA_RAM_NSEC,0x860000000,0x10000000);
register_phys_mem(MEM_AREA_RAM_NSEC,0x870000000,0x10000000);

/**
 * @brief start
 * This is start point of Heimdall. It takes virtual address
 * init_task via first element of params parameters.
 * @param param_types
 * @param params First element of this paramaeter contains
 * virtual address of init_task
 * @return
 */
static TEE_Result start(uint32_t param_types,
	TEE_Param params[4])
{
	const struct anomaly_info* current_anomaly;
	uint64_t init_task_addr;
	heimdall_return_t res;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("Bad parameters types: 0x%" PRIx32, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	init_task_addr = params[0].value.a | (uint64_t)(params[0].value.b)<<32;

    res = heimdall_start(init_task_addr); // Start heimdall

    if(res == HEIMDALL_SUCCESS) // If there isn't any anomaly
	{
		DMSG("No Anomaly Detected :)");
	}
    else if(res == HEIMDALL_UNEXPECTED_DIGEST) // If unexpected digest is detected
	{
        current_anomaly = heimdall_get_anomaly_info(); // Get anomaly info
        //Print Report
		DMSG("Unexpected Digest!!!");
		DMSG("***********Anomaly Report:***********");
		DMSG("Expected Digest:");
		DHEXDUMP(current_anomaly->expected_digest,DIGEST_SIZE);
		DMSG("Calculated Digest:");
		DHEXDUMP(current_anomaly->unexpected_digest,DIGEST_SIZE);
		DMSG("ELF Name:%s",current_anomaly->elf_name);
		DMSG("Page Number:%d",current_anomaly->page_number);
	}
    else if(res == HEIMDALL_UNREGISTERED_ELF) // If unregistered elf is detected
	{
        current_anomaly = heimdall_get_anomaly_info(); // Get anomaly info
        //Print Report.
		DMSG("Unauthorized ELF!!!");
		DMSG("ELF Name:%s",current_anomaly->unregistered_elf_name);
	}
	else
	{
		DMSG("Unknown Anomaly Detected!!!");
	}
	
	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *psess __unused,
				 uint32_t cmd, uint32_t ptypes,
				 TEE_Param params[4])
{

	switch (cmd) {
	case TA_HEIMDALL_CMD_START_VALUE:
		return start(ptypes, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

//Register TA
pseudo_ta_register(.uuid = TA_HEIMDALL_UUID, .name = TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
