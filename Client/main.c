/* Copyright 2021 Yusuf YAMAK. All Rights Reserved.
   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>

#define TA_HEIMDALL_UUID \
	{ 0xa20a9678, 0xb4e8, 0x11eb, \
		{ 0x85, 0x29, 0x02, 0x42, 0xac, 0x13, 0x00, 0x03} }

#define TA_HEIMDALL_CMD_START_VALUE		0

uint64_t find_init_task_addr(void)
{
    FILE* file;
    char buffer[30];
    const char* bashScript="cat /proc/kallsyms | grep \" init_task\" | awk '{print $1}'";
    file= popen(bashScript,"r");
    fgets(buffer, sizeof (buffer), file);
    fclose(file);
    return strtoull(buffer,NULL,16);

}

int main(void)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_HEIMDALL_UUID;
	uint32_t err_origin;
	uint64_t init_task_addr;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	init_task_addr=find_init_task_addr();
	op.params[0].value.a = init_task_addr&0xFFFFFFFF;
	op.params[0].value.b = (init_task_addr&0xFFFFFFFF00000000)>>32;


	printf("Invoking TA to start heimdall %d\n", op.params[0].value.a);
	res = TEEC_InvokeCommand(&sess, TA_HEIMDALL_CMD_START_VALUE, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
