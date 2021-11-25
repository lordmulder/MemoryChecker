/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef MD5_H
#define MD5_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

typedef BYTE md5_digest_t[16U];

typedef struct
{
	ULONG64 size;
	ULONG32 buffer[4U];
	BYTE input[64U];
	md5_digest_t digest;
}
md5_context_t;

void md5_init(md5_context_t *const ctx);
void md5_update(md5_context_t *const ctx, const BYTE* const input_buffer, const SIZE_T input_len);
const BYTE *md5_finalize(md5_context_t *const ctx);

#endif
