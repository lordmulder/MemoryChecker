/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdlib.h>
#include "random.h"

#define ASSERT(X) do { if(!(X)) abort(); } while(0)
#define RtlGenRandom SystemFunction036
BOOLEAN WINAPI RtlGenRandom(PVOID, ULONG);

void random_seed(rand_state_t *const state)
{
	RtlGenRandom(state, sizeof(rand_state_t));
}

ULONG32 random_next(rand_state_t *const state)
{
	const ULONG32 t = state->x ^ (state->x >> 2);
	state->x = state->y;
	state->y = state->z;
	state->z = state->w;
	state->w = state->v;
	state->v ^= (state->v << 4) ^ t ^ (t << 1);
	return (state->d += 0x000587C5) + state->v;
}

void random_bytes(rand_state_t *const state, BYTE* buffer, SIZE_T size)
{
	ASSERT((size % sizeof(ULONG32)) == 0U);
	while (size > 0U)
	{
		*((ULONG32*)buffer) = random_next(state);
		size -= sizeof(ULONG32);
		buffer += sizeof(ULONG32);
	}
}
