/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef INC_RANDOM_H
#define INC_RANDOM_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

typedef struct
{
	ULONG32 x, y, z, w, v, d;
}
rand_state_t;

void random_init(rand_state_t *const state);
ULONG32 random_next(rand_state_t *const state);
BOOL random_setup(void);

#endif
