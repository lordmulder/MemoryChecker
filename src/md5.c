/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>

#include "md5.h"

#define A 0x67452301
#define B 0xefcdab89
#define C 0x98badcfe
#define D 0x10325476

#pragma warning(disable: 6386)

static ULONG32 S[] =
{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static ULONG32 K[] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))

static BYTE PADDING[] =
{
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static ULONG32 rotate_left(const ULONG32 x, const ULONG32 n)
{
	return (x << n) | (x >> (32 - n));
}

static void md5_step(ULONG32 *const buffer, const ULONG32 *const input)
{
	ULONG32 AA = buffer[0];
	ULONG32 BB = buffer[1];
	ULONG32 CC = buffer[2];
	ULONG32 DD = buffer[3];

	ULONG32 E;
	unsigned int j;

	for (unsigned int i = 0; i < 64; ++i) {
		switch (i / 16) {
		case 0:
			E = F(BB, CC, DD);
			j = i;
			break;
		case 1:
			E = G(BB, CC, DD);
			j = ((i * 5) + 1) % 16;
			break;
		case 2:
			E = H(BB, CC, DD);
			j = ((i * 3) + 5) % 16;
			break;
		default:
			E = I(BB, CC, DD);
			j = (i * 7) % 16;
			break;
		}

		ULONG32 temp = DD;
		DD = CC;
		CC = BB;
		BB = BB + rotate_left(AA + E + K[i] + input[j], S[i]);
		AA = temp;
	}

	buffer[0] += AA;
	buffer[1] += BB;
	buffer[2] += CC;
	buffer[3] += DD;
}

void md5_init(md5_context_t *const ctx)
{
	ctx->size      = (ULONG64)0;
	ctx->buffer[0] = (ULONG32)A;
	ctx->buffer[1] = (ULONG32)B;
	ctx->buffer[2] = (ULONG32)C;
	ctx->buffer[3] = (ULONG32)D;
}

void md5_update(md5_context_t *const ctx, const BYTE *const input_buffer, const SIZE_T input_len)
{
	ULONG32 input[16];
	unsigned int offset = ctx->size % 64;
	ctx->size += (ULONG64)input_len;

	for (SIZE_T i = 0; i < input_len; ++i)
	{
		ctx->input[offset++] = (BYTE)*(input_buffer + i);
		if (offset % 64 == 0)
		{
			for (unsigned int j = 0; j < 16; ++j)
			{
				input[j] =
					(ULONG32)(ctx->input[(j * 4) + 3]) << 24 |
					(ULONG32)(ctx->input[(j * 4) + 2]) << 16 |
					(ULONG32)(ctx->input[(j * 4) + 1]) <<  8 |
					(ULONG32)(ctx->input[(j * 4)]);
			}
			md5_step(ctx->buffer, input);
			offset = 0;
		}
	}
}

const BYTE *md5_finalize(md5_context_t *const ctx)
{
	ULONG32 input[16];
	unsigned int offset = ctx->size % 64;
	unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

	md5_update(ctx, PADDING, padding_length);
	ctx->size -= (ULONG64)padding_length;

	for (unsigned int j = 0; j < 14; ++j)
	{
		input[j] =
			(ULONG32)(ctx->input[(j * 4) + 3]) << 24 |
			(ULONG32)(ctx->input[(j * 4) + 2]) << 16 |
			(ULONG32)(ctx->input[(j * 4) + 1]) <<  8 |
			(ULONG32)(ctx->input[(j * 4)]);
	}
	input[14] = (ULONG32)(ctx->size * 8);
	input[15] = (ULONG32)((ctx->size * 8) >> 32);

	md5_step(ctx->buffer, input);

	for (unsigned int i = 0; i < 4; ++i)
	{
		ctx->digest[(i * 4) + 0] = (BYTE)((ctx->buffer[i] & 0x000000FF));
		ctx->digest[(i * 4) + 1] = (BYTE)((ctx->buffer[i] & 0x0000FF00) >>  8);
		ctx->digest[(i * 4) + 2] = (BYTE)((ctx->buffer[i] & 0x00FF0000) >> 16);
		ctx->digest[(i * 4) + 3] = (BYTE)((ctx->buffer[i] & 0xFF000000) >> 24);
	}

	return ctx->digest;
}
