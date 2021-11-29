/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef INC_MD5_H
#define INC_MD5_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

#define MD5_BLOCK_SIZE 64U
#define MD5_HASH_SIZE  16U

typedef struct _md5_ctx
{
	ULONG32 message[MD5_BLOCK_SIZE / 4U];
	ULONG64 length;
	ULONG32 hash[4U];
}
md5_ctx_t;


void md5_init(md5_ctx_t *const ctx);
void md5_update(md5_ctx_t *const ctx, const BYTE *msg, SIZE_T size);
void md5_final(md5_ctx_t *const ctx, BYTE *const result_out);

#endif
