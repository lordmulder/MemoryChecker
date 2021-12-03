/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdlib.h>
#include "random.h"

#define ASSERT(X) do { if(!(X)) abort(); } while(0)

static BOOLEAN(APIENTRY* ptr_rtlgenrandom)(void*, ULONG) = NULL;

BOOL random_setup(void)
{
	const HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
	if (advapi32 != NULL)
	{
		ptr_rtlgenrandom = (BOOLEAN(APIENTRY*)(void*, ULONG)) GetProcAddress(advapi32, "SystemFunction036");
		if (ptr_rtlgenrandom)
		{
			return TRUE;
		}
	}
	return FALSE;
}

void random_init(rand_state_t* const state)
{
	if (!ptr_rtlgenrandom)
	{
		abort(); /*not set up yet!*/
	}
	ptr_rtlgenrandom(state, sizeof(rand_state_t));
}

ULONG32 random_next(rand_state_t* const state)
{
	const ULONG32 t = state->x ^ (state->x >> 2);
	state->x = state->y;
	state->y = state->z;
	state->z = state->w;
	state->w = state->v;
	state->v ^= (state->v << 4) ^ t ^ (t << 1);
	return (state->d += 0x000587C5) + state->v;
}

void random_bytes(rand_state_t* const state, BYTE* buffer, SIZE_T size)
{
	ASSERT((size % sizeof(ULONG32)) == 0U);
	while (size > 0U)
	{
		*((ULONG32*)buffer) = random_next(state);
		size -= sizeof(ULONG32);
		buffer += sizeof(ULONG32);
	}
}

#ifdef __GNUC__
static volatile PVOID _getusernamew = &GetUserNameW;
#endif
