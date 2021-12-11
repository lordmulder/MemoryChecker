/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include "allocate.h"

SIZE_T get_page_size()
{
	SYSTEM_INFO info;
	SecureZeroMemory(&info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&info);
	return info.dwPageSize;
}

BOOL change_working_set_size(const SIZE_T size)
{
	return SetProcessWorkingSetSize(GetCurrentProcess(), size, size);
}

meminfo_t get_physical_memory_info()
{
	meminfo_t memory_info = { 0U, 0U };
	MEMORYSTATUSEX status;
	SecureZeroMemory(&status, sizeof(MEMORYSTATUSEX));
	status.dwLength = sizeof(MEMORYSTATUSEX);
	if (GlobalMemoryStatusEx(&status))
	{
		memory_info.total = status.ullTotalPhys;
		memory_info.avail = status.ullAvailPhys;
	}
	return memory_info;
}

PVOID allocate_physical_memory(const SIZE_T size)
{
	const PVOID addr = VirtualAllocEx(GetCurrentProcess(), NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_NOCACHE);
	if (addr)
	{
		if (VirtualLock(addr, size))
		{
			return addr;
		}
		free_physical_memory(addr);
	}
	return NULL;
}

void free_physical_memory(const PVOID addr)
{
	VirtualFree(addr, 0U, MEM_RELEASE);
}
