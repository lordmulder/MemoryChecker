/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define _CRT_RAND_S 1
#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdlib.h>
#include "random.h"

static inline void seed(ULONG32* const buffer)
{
	if (rand_s(buffer) != 0)
	{
		abort();
	}
}

void random_init(rand_state_t *const state)
{
	SecureZeroMemory(state, sizeof(rand_state_t));
	seed(&state->x);
	seed(&state->y);
	seed(&state->z);
	seed(&state->w);
	seed(&state->v);
	seed(&state->d);
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
