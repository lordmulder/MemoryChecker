/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef INC_MEMCHCKR_UTILS_H
#define INC_MEMCHCKR_UTILS_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

static inline SIZE_T get_max(const SIZE_T a, const SIZE_T b)
{
	return (a > b) ? a : b;
}

static inline SIZE_T get_min(const SIZE_T a, const SIZE_T b)
{
	return (a < b) ? a : b;
}

static inline SIZE_T bound(const SIZE_T min, const SIZE_T val, const SIZE_T max)
{
	return get_max(min, get_min(max, val));
}

static inline SIZE_T round_up(const SIZE_T number, const SIZE_T multiple)
{

	const SIZE_T remainder = number % multiple;
	if (remainder != 0U)
	{
		return number - remainder + multiple;
	}
	return number;
}

static inline SIZE_T get_cpu_count()
{
	SYSTEM_INFO info;
	SecureZeroMemory(&info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
}

static inline ULONG64 get_performance_frequency()
{
	LARGE_INTEGER value;
	if (QueryPerformanceFrequency(&value))
	{
		return value.QuadPart;
	}
	return 1U;
}

static inline ULONG64 query_performance_counter()
{
	LARGE_INTEGER value;
	if (QueryPerformanceCounter(&value))
	{
		return value.QuadPart;
	}
	return 0U;
}

#endif
