/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef INC_MEMCHCKR_ALLOCATE_H
#define INC_MEMCHCKR_ALLOCATE_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

typedef struct
{
	SIZE_T total;
	SIZE_T avail;
}
meminfo_t;

SIZE_T get_page_size();
BOOL change_working_set_size(const SIZE_T size);
meminfo_t get_physical_memory_info();
PVOID allocate_physical_memory(const SIZE_T size);

#endif