/* md5.c - an implementation of the MD5 algorithm, based on RFC 1321.
 *
 * Copyright (c) 2007, Aleksey Kravchenko <rhash.admin@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE  INCLUDING ALL IMPLIED WARRANTIES OF  MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT,  OR CONSEQUENTIAL DAMAGES  OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE,  DATA OR PROFITS,  WHETHER IN AN ACTION OF CONTRACT,  NEGLIGENCE
 * OR OTHER TORTIOUS ACTION,  ARISING OUT OF  OR IN CONNECTION  WITH THE USE  OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#if !defined(_M_X64) && !defined(__x86_64__)
#error This program should be compiled as x86-64 binary!
#endif

#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include "md5.h"

#define LE32_COPY(to, index, from, length) memcpy((BYTE*)(to) + (index), (from), (length))
#define IS_ALIGNED_32(p) (0U == (3U & (uintptr_t)(p)))
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32U - (n))))

#define MD5_F(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | (~z)))

#define MD5_ROUND1(a, b, c, d, x, s, ac) \
{ \
	(a) += MD5_F((b), (c), (d)) + (x) + (ac); \
	(a) = ROTL32((a), (s)); \
	(a) += (b); \
}

#define MD5_ROUND2(a, b, c, d, x, s, ac) \
{ \
	(a) += MD5_G((b), (c), (d)) + (x) + (ac); \
	(a) = ROTL32((a), (s)); \
	(a) += (b); \
}

#define MD5_ROUND3(a, b, c, d, x, s, ac) \
{ \
	(a) += MD5_H((b), (c), (d)) + (x) + (ac); \
	(a) = ROTL32((a), (s)); \
	(a) += (b); \
}

#define MD5_ROUND4(a, b, c, d, x, s, ac) \
 { \
	(a) += MD5_I((b), (c), (d)) + (x) + (ac); \
	(a) = ROTL32((a), (s)); \
	(a) += (b); \
}

static void md5_process_block(ULONG32 state[4U], const ULONG32* const x)
{
	register ULONG32 a, b, c, d;
	a = state[0U];
	b = state[1U];
	c = state[2U];
	d = state[3U];

	MD5_ROUND1(a, b, c, d, x[0], 7, 0xd76aa478);
	MD5_ROUND1(d, a, b, c, x[1], 12, 0xe8c7b756);
	MD5_ROUND1(c, d, a, b, x[2], 17, 0x242070db);
	MD5_ROUND1(b, c, d, a, x[3], 22, 0xc1bdceee);
	MD5_ROUND1(a, b, c, d, x[4], 7, 0xf57c0faf);
	MD5_ROUND1(d, a, b, c, x[5], 12, 0x4787c62a);
	MD5_ROUND1(c, d, a, b, x[6], 17, 0xa8304613);
	MD5_ROUND1(b, c, d, a, x[7], 22, 0xfd469501);
	MD5_ROUND1(a, b, c, d, x[8], 7, 0x698098d8);
	MD5_ROUND1(d, a, b, c, x[9], 12, 0x8b44f7af);
	MD5_ROUND1(c, d, a, b, x[10], 17, 0xffff5bb1);
	MD5_ROUND1(b, c, d, a, x[11], 22, 0x895cd7be);
	MD5_ROUND1(a, b, c, d, x[12], 7, 0x6b901122);
	MD5_ROUND1(d, a, b, c, x[13], 12, 0xfd987193);
	MD5_ROUND1(c, d, a, b, x[14], 17, 0xa679438e);
	MD5_ROUND1(b, c, d, a, x[15], 22, 0x49b40821);

	MD5_ROUND2(a, b, c, d, x[1], 5, 0xf61e2562);
	MD5_ROUND2(d, a, b, c, x[6], 9, 0xc040b340);
	MD5_ROUND2(c, d, a, b, x[11], 14, 0x265e5a51);
	MD5_ROUND2(b, c, d, a, x[0], 20, 0xe9b6c7aa);
	MD5_ROUND2(a, b, c, d, x[5], 5, 0xd62f105d);
	MD5_ROUND2(d, a, b, c, x[10], 9, 0x2441453);
	MD5_ROUND2(c, d, a, b, x[15], 14, 0xd8a1e681);
	MD5_ROUND2(b, c, d, a, x[4], 20, 0xe7d3fbc8);
	MD5_ROUND2(a, b, c, d, x[9], 5, 0x21e1cde6);
	MD5_ROUND2(d, a, b, c, x[14], 9, 0xc33707d6);
	MD5_ROUND2(c, d, a, b, x[3], 14, 0xf4d50d87);
	MD5_ROUND2(b, c, d, a, x[8], 20, 0x455a14ed);
	MD5_ROUND2(a, b, c, d, x[13], 5, 0xa9e3e905);
	MD5_ROUND2(d, a, b, c, x[2], 9, 0xfcefa3f8);
	MD5_ROUND2(c, d, a, b, x[7], 14, 0x676f02d9);
	MD5_ROUND2(b, c, d, a, x[12], 20, 0x8d2a4c8a);

	MD5_ROUND3(a, b, c, d, x[5], 4, 0xfffa3942);
	MD5_ROUND3(d, a, b, c, x[8], 11, 0x8771f681);
	MD5_ROUND3(c, d, a, b, x[11], 16, 0x6d9d6122);
	MD5_ROUND3(b, c, d, a, x[14], 23, 0xfde5380c);
	MD5_ROUND3(a, b, c, d, x[1], 4, 0xa4beea44);
	MD5_ROUND3(d, a, b, c, x[4], 11, 0x4bdecfa9);
	MD5_ROUND3(c, d, a, b, x[7], 16, 0xf6bb4b60);
	MD5_ROUND3(b, c, d, a, x[10], 23, 0xbebfbc70);
	MD5_ROUND3(a, b, c, d, x[13], 4, 0x289b7ec6);
	MD5_ROUND3(d, a, b, c, x[0], 11, 0xeaa127fa);
	MD5_ROUND3(c, d, a, b, x[3], 16, 0xd4ef3085);
	MD5_ROUND3(b, c, d, a, x[6], 23, 0x4881d05);
	MD5_ROUND3(a, b, c, d, x[9], 4, 0xd9d4d039);
	MD5_ROUND3(d, a, b, c, x[12], 11, 0xe6db99e5);
	MD5_ROUND3(c, d, a, b, x[15], 16, 0x1fa27cf8);
	MD5_ROUND3(b, c, d, a, x[2], 23, 0xc4ac5665);

	MD5_ROUND4(a, b, c, d, x[0], 6, 0xf4292244);
	MD5_ROUND4(d, a, b, c, x[7], 10, 0x432aff97);
	MD5_ROUND4(c, d, a, b, x[14], 15, 0xab9423a7);
	MD5_ROUND4(b, c, d, a, x[5], 21, 0xfc93a039);
	MD5_ROUND4(a, b, c, d, x[12], 6, 0x655b59c3);
	MD5_ROUND4(d, a, b, c, x[3], 10, 0x8f0ccc92);
	MD5_ROUND4(c, d, a, b, x[10], 15, 0xffeff47d);
	MD5_ROUND4(b, c, d, a, x[1], 21, 0x85845dd1);
	MD5_ROUND4(a, b, c, d, x[8], 6, 0x6fa87e4f);
	MD5_ROUND4(d, a, b, c, x[15], 10, 0xfe2ce6e0);
	MD5_ROUND4(c, d, a, b, x[6], 15, 0xa3014314);
	MD5_ROUND4(b, c, d, a, x[13], 21, 0x4e0811a1);
	MD5_ROUND4(a, b, c, d, x[4], 6, 0xf7537e82);
	MD5_ROUND4(d, a, b, c, x[11], 10, 0xbd3af235);
	MD5_ROUND4(c, d, a, b, x[2], 15, 0x2ad7d2bb);
	MD5_ROUND4(b, c, d, a, x[9], 21, 0xeb86d391);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}

void md5_init(md5_ctx_t *const ctx)
{
	SecureZeroMemory(ctx, sizeof(md5_ctx_t));
	ctx->hash[0] = 0x67452301;
	ctx->hash[1] = 0xefcdab89;
	ctx->hash[2] = 0x98badcfe;
	ctx->hash[3] = 0x10325476;
}

void md5_update(md5_ctx_t *const ctx, const BYTE *msg, SIZE_T size)
{
	const ULONG32 index = (ULONG32)ctx->length & 63U;
	ctx->length += size;
	if (index)
	{
		const ULONG32 left = MD5_BLOCK_SIZE - index;
		LE32_COPY(ctx->message, index, msg, (size < left ? size : left));
		if (size < left)
		{
			return;
		}
		md5_process_block(ctx->hash, ctx->message);
		msg += left;
		size -= left;
	}
	while (size >= MD5_BLOCK_SIZE)
	{
		const ULONG32* aligned_message_block;
		if (IS_ALIGNED_32(msg))
		{
			aligned_message_block = (ULONG32*)msg;
		}
		else
		{
			LE32_COPY(ctx->message, 0, msg, MD5_BLOCK_SIZE);
			aligned_message_block = ctx->message;
		}
		md5_process_block(ctx->hash, aligned_message_block);
		msg += MD5_BLOCK_SIZE;
		size -= MD5_BLOCK_SIZE;
	}
	if (size)
	{
		LE32_COPY(ctx->message, 0, msg, size);
	}
}

void md5_final(md5_ctx_t *const ctx, BYTE *const result_out)
{
	ULONG32 index = ((ULONG32)ctx->length & 63U) >> 2;
	const ULONG32 shift = ((ULONG32)ctx->length & 3U) * 8U;
	ctx->message[index] &= ~(0xFFFFFFFFU << shift);
	ctx->message[index++] ^= 0x80U << shift;
	if (index > 14U)
	{
		while (index < 16U)
		{
			ctx->message[index++] = 0U;
		}
		md5_process_block(ctx->hash, ctx->message);
		index = 0;
	}
	while (index < 14U)
	{
		ctx->message[index++] = 0U;
	}
	ctx->message[14] = (ULONG32)(ctx->length << 3);
	ctx->message[15] = (ULONG32)(ctx->length >> 29);
	md5_process_block(ctx->hash, ctx->message);
	if (result_out)
	{
		LE32_COPY(result_out, 0U, &ctx->hash, 16U);
	}
}
