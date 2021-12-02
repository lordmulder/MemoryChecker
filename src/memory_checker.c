/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef _M_X64
#error This program should be compiled as x64 binary!
#endif

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <versionhelpers.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <process.h>
#include <io.h>
#include <time.h>
#include "random.h"
#include "md5.h"
#include "version.h"

#define MAX_CHUNKS 4096U
#define MAX_THREAD 32U
#define MIN_MEMORY (512U * 1024U * 1024U)
#define RW_BUFSIZE ((SIZE_T)16U)
#define UPDATE_INT 997U

/* ====================================================================== */
/* Typedefs                                                               */
/* ====================================================================== */

typedef struct
{
	SIZE_T total;
	SIZE_T avail;
}
meminfo_t;

typedef struct
{
	SIZE_T size;
	BYTE *addr;
}
chunk_t;

typedef enum
{
   MSGTYPE_NFO =  0,
   MSGTYPE_HDR =  1,
   MSGTYPE_PRG =  2,
   MSGTYPE_WRN =  4,
   MSGTYPE_ERR =  8,
   MSGTYPE_FIN = 16
}
msgtype_t;

typedef BYTE digest_t[MD5_HASH_SIZE];

/* ====================================================================== */
/* Globals                                                                */
/* ====================================================================== */

static const char* const BUILD_DATE = __DATE__;

static chunk_t CHUNKS[MAX_CHUNKS];
static digest_t DIGEST[MAX_CHUNKS];

static SIZE_T num_passes = 8U, num_chunks = 0U, num_threads = 0U;

static volatile LONG64 completed = 0LL;
static volatile LONG64 chk_error = 0LL;

static volatile BOOL debug_mode = FALSE, color_mode = TRUE, stop = FALSE;

/* ====================================================================== */
/* Utility Functions                                                      */
/* ====================================================================== */

static meminfo_t get_physical_memory_size()
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

static SIZE_T get_page_size()
{
	SYSTEM_INFO info;
	SecureZeroMemory(&info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&info);
	return info.dwPageSize;
}

static SIZE_T get_cpu_count()
{
	SYSTEM_INFO info;
	SecureZeroMemory(&info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
}

static BOOL set_process_priority(const BOOL high_priority)
{
	const DWORD current_priority = GetPriorityClass(GetCurrentProcess());
	if ((current_priority == REALTIME_PRIORITY_CLASS) || (current_priority == HIGH_PRIORITY_CLASS) || ((!high_priority) && (current_priority == ABOVE_NORMAL_PRIORITY_CLASS)))
	{
		return TRUE;
	}
	return SetPriorityClass(GetCurrentProcess(), high_priority ? HIGH_PRIORITY_CLASS : ABOVE_NORMAL_PRIORITY_CLASS);
}

static PVOID allocate_chunk(const SIZE_T size)
{
	const PVOID addr = VirtualAllocEx(GetCurrentProcess(), NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE | PAGE_NOCACHE);
	if (addr)
	{
		if (VirtualLock(addr, size))
		{
			return addr;
		}
		VirtualFree(addr, 0, MEM_RELEASE);
	}
	return NULL;
}

static LONG read_envvar(const wchar_t *const name, ULONG64 *const value)
{
	wchar_t buffer[64U], *end_ptr = NULL;
	const DWORD result = GetEnvironmentVariableW(name, buffer, 64U);
	if ((result > 0U) && (result < 64U))
	{
		*value = wcstoull(buffer, &end_ptr, 10);
		return ((*value) && (*end_ptr == L'\0')) ? 1L : (-1L);
	}
	else
	{
		return 0L; /*ERROR_ENVVAR_NOT_FOUND*/
	}
}

static void set_console_progress(const SIZE_T pass, const SIZE_T total, const double progress)
{
	wchar_t buffer[64U];
	if (total > 0U)
	{
		_snwprintf_s(buffer, 64U, _TRUNCATE, L"[%zu/%zu] %.1f%% - Memory Checker", pass, total, progress);
	}
	else
	{
		_snwprintf_s(buffer, 64U, _TRUNCATE, L"[%zu/\u221E] %.1f%% - Memory Checker", pass, progress);
	}
	SetConsoleTitleW(buffer);
}

static WORD get_text_attributes(const msgtype_t type)
{
	switch (type)
	{
	case MSGTYPE_HDR:
		return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
	case MSGTYPE_PRG:
		return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
	case MSGTYPE_WRN:
		return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
	case MSGTYPE_ERR:
		return FOREGROUND_RED | FOREGROUND_INTENSITY;
	case MSGTYPE_FIN:
		return FOREGROUND_GREEN | FOREGROUND_INTENSITY | FOREGROUND_INTENSITY;
	default:
		return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
	}
}

static BOOL print_msg(const msgtype_t type, const char* const text)
{
	static const WORD BACKGROUND_MASK = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;
	DWORD bytes_written;
	const HANDLE handle = (HANDLE)_get_osfhandle(_fileno(stdout));
	if (GetFileType(handle) == FILE_TYPE_CHAR)
	{
		if (color_mode)
		{
			CONSOLE_SCREEN_BUFFER_INFO info;
			memset(&info, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
			if (GetConsoleScreenBufferInfo(handle, &info))
			{
				const WORD bg_color = info.wAttributes & BACKGROUND_MASK;
				if (SetConsoleTextAttribute(handle, bg_color | get_text_attributes(type)))
				{
					const BOOL result = WriteConsoleA(handle, text, (DWORD)strlen(text), &bytes_written, NULL);
					SetConsoleTextAttribute(handle, info.wAttributes);
					return result;
				}
			}
		}
		return WriteConsoleA(handle, text, (DWORD)strlen(text), &bytes_written, NULL);
	}
	else
	{
		const BOOL result = WriteFile(handle, text, (DWORD)strlen(text), &bytes_written, NULL);
		if (result)
		{
			FlushFileBuffers(handle);
		}
		return result;
	}
}

static inline BOOL fprint_msg(const msgtype_t type, const char* const format, ...)
{
	char buffer[MAX_PATH];
	va_list ap;
	va_start(ap, format);
	_vsnprintf_s(buffer, MAX_PATH, _TRUNCATE, format, ap);
	va_end(ap);
	return print_msg(type, buffer);
}

static inline void DBG_print_chunk(const SIZE_T index, const SIZE_T size, const PVOID* const addr)
{
	char buffer[64U];
	_snprintf_s(buffer, 64U, _TRUNCATE, "[Memchkr] Memory: %04zX - %09zu - 0x%016zX\n", index, size, (ULONG_PTR)addr);
	OutputDebugStringA(buffer);
}

static inline void DBG_print_digest(const SIZE_T index, const BYTE* const digest, const BOOL read_mode)
{
	char buffer[64U];
	_snprintf_s(buffer, 64U, _TRUNCATE, "[Memchkr] Digest: %04zX - %s:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
		index, read_mode ? "RD" : "WR",
		digest[0U], digest[1U], digest[ 2U], digest[ 3U], digest[ 4U], digest[ 5U], digest[ 6U], digest[ 7U],
		digest[8U], digest[9U], digest[10U], digest[11U], digest[12U], digest[13U], digest[14U], digest[15U]);
	OutputDebugStringA(buffer);
}

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

static BOOL WINAPI console_ctrl_handler(const DWORD ctrl_type)
{
	switch (ctrl_type)
	{
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		stop = TRUE;
		return TRUE;
	default:
		return FALSE;
	}
}

static void print_app_logo(void)
{
	fprint_msg(MSGTYPE_HDR, "Memory Checker v%u.%02u-%u [%s], by LoRd_MuldeR <MuldeR2@GMX.de>\n", MEMCK_VERSION_MAJOR, (10U * MEMCK_VERSION_MINOR_HI) + MEMCK_VERSION_MINOR_LO, MEMCK_VERSION_PATCH, BUILD_DATE);
	print_msg(MSGTYPE_HDR, "This work has been released under the CC0 1.0 Universal license!\n\n");
}

/* ====================================================================== */
/* Thread                                                                 */
/* ====================================================================== */

static UINT32 thread_fill(void *const arg)
{
	md5_ctx_t md5_ctx;
	rand_state_t rand_state;
	SIZE_T chunk_idx, upd_counter = 0U;
	BYTE temp[RW_BUFSIZE];
	const SIZE_T id = (SIZE_T)arg;

	random_init(&rand_state);

	for (chunk_idx = id; (!stop) && (chunk_idx < num_chunks); chunk_idx += num_threads)
	{
		BYTE *const limit = CHUNKS[chunk_idx].addr + CHUNKS[chunk_idx].size;
		md5_init(&md5_ctx);
		for (BYTE *addr = CHUNKS[chunk_idx].addr; addr < limit; addr += RW_BUFSIZE)
		{
			random_bytes(&rand_state, temp, RW_BUFSIZE);
			memcpy(addr, temp, RW_BUFSIZE);
			md5_update(&md5_ctx, temp, RW_BUFSIZE);
			if (++upd_counter >= UPDATE_INT)
			{
				InterlockedAdd64(&completed, UPDATE_INT * RW_BUFSIZE);
				upd_counter = 0U;
			}
		}
		md5_final(&md5_ctx, DIGEST[chunk_idx]);
		if (debug_mode)
		{
			DBG_print_digest(chunk_idx, DIGEST[chunk_idx], FALSE);
		}
	}

	if (upd_counter > 0U)
	{
		InterlockedAdd64(&completed, upd_counter * RW_BUFSIZE);
	}

	return stop ? EXIT_FAILURE : EXIT_SUCCESS;
}

static UINT32 thread_check(void *const arg)
{
	md5_ctx_t md5_ctx;
	SIZE_T chunk_idx, upd_counter = 0U;
	BYTE digest[MD5_HASH_SIZE], temp[RW_BUFSIZE];
	const SIZE_T id = (SIZE_T)arg;

	for (chunk_idx = id; (!stop) && (chunk_idx < num_chunks); chunk_idx += num_threads)
	{
		BYTE *const limit = CHUNKS[chunk_idx].addr + CHUNKS[chunk_idx].size;
		md5_init(&md5_ctx);
		for (BYTE *addr = CHUNKS[chunk_idx].addr; addr < limit; addr += RW_BUFSIZE)
		{
			memcpy(temp, addr, RW_BUFSIZE);
			md5_update(&md5_ctx, (const BYTE*)&temp, RW_BUFSIZE);
			if (++upd_counter >= UPDATE_INT)
			{
				InterlockedAdd64(&completed, UPDATE_INT * RW_BUFSIZE);
				upd_counter = 0U;
			}
		}
		md5_final(&md5_ctx, digest);
		if (debug_mode)
		{
			DBG_print_digest(chunk_idx, digest, TRUE);
		}
		if (memcmp(digest, DIGEST[chunk_idx], MD5_HASH_SIZE) != 0)
		{
			InterlockedIncrement64(&chk_error);
		}
	}

	if (upd_counter > 0U)
	{
		InterlockedAdd64(&completed, upd_counter * RW_BUFSIZE);
	}

	return stop ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* ====================================================================== */
/* MAIN                                                                   */
/* ====================================================================== */

static int memchecker_main(const int argc, const wchar_t* const argv[])
{
	int exit_code = EXIT_FAILURE, arg_offset = 1;
	SIZE_T target_memory = 0U, allocated_memory = 0U, page_size = 0U;
	SIZE_T chunk_size = 0U, working_set_size = 0U, pass = 0U, chunk_idx = 0U, thread_idx = 0U;
	clock_t clock_total[2U] = { 0L, 0L }, clock_pass = 0L;
	BOOL batch_mode = FALSE, continuous_mode = FALSE, percent_mode = FALSE, high_priority = FALSE;
	meminfo_t phys_memory;
	HANDLE thread[MAX_THREAD];

	SetConsoleTitleW(L"Memory Checker");

	/* ----------------------------------------------------- */
	/* Parse parameters                                      */
	/* ----------------------------------------------------- */

	while (arg_offset < argc)
	{
		if ((!_wcsicmp(argv[arg_offset], L"-h")) || (!_wcsicmp(argv[arg_offset], L"/?")) || (!_wcsicmp(argv[arg_offset], L"-?")) || (!_wcsicmp(argv[arg_offset], L"--help")))
		{
			print_app_logo();
			print_msg(MSGTYPE_NFO, "Usage:\n");
			print_msg(MSGTYPE_NFO, "  MemoryChecker.exe [--batch] [--continuous] [<target_memory_size>[%]] [<threads>]\n\n");
			print_msg(MSGTYPE_NFO, "Default memory size to test is ~95% of the total physical memory.\n\n");
			return EXIT_SUCCESS;
		}
		if ((argv[arg_offset][0U] == L'-') && (argv[arg_offset][1U] == L'-'))
		{
			const wchar_t* const option = argv[arg_offset++] + 2U;
			if (option[0U] != L'\0')
			{
				if (!_wcsicmp(option, L"batch"))
				{
					batch_mode = TRUE;
					continue;
				}
				if (!_wcsicmp(option, L"continuous"))
				{
					continuous_mode = TRUE;
					continue;
				}
				if (!_wcsicmp(option, L"debug"))
				{
					debug_mode = TRUE;
					continue;
				}
				if (!_wcsicmp(option, L"monochrome"))
				{
					color_mode = FALSE;
					continue;
				}
				if (!_wcsicmp(option, L"high"))
				{
					high_priority = TRUE;
					continue;
				}
				print_app_logo();
				fprint_msg(MSGTYPE_ERR, "The specified option is unknown: \"--%S\"\n\n", option);
				return EXIT_FAILURE;
			}
		}
		break;
	}

	if (read_envvar(L"MEMCHCK_PASSES", &num_passes) < 0L)
	{
		print_app_logo();
		print_msg(MSGTYPE_ERR, "Number of passes specified in environment variable MEMCHCK_PASSES is invalid!\n\n");
		return EXIT_FAILURE;
	}

	print_app_logo(); /*always print the logo at this point*/

	if (arg_offset < argc)
	{
		const wchar_t *const value = argv[arg_offset++];
		wchar_t *end_ptr = NULL;
		target_memory = wcstoull(value, &end_ptr, 10);
		if ((!target_memory) || (end_ptr && (*end_ptr != L'%') && (*end_ptr != L'\0')))
		{
			fprint_msg(MSGTYPE_ERR, "The specified target memory size is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
		if (end_ptr && (*end_ptr == L'%'))
		{
			percent_mode = TRUE;
			if (target_memory > 100U)
			{
				print_msg(MSGTYPE_ERR, "Error: Cannot allocated more than 100% of the total physical memory!\n\n");
				return EXIT_FAILURE;
			}
		}
	}

	if (arg_offset < argc)
	{
		const wchar_t* const value = argv[arg_offset++];
		wchar_t* end_ptr = NULL;
		num_threads = wcstoull(value, &end_ptr, 10);
		if ((!num_threads) || (end_ptr && (*end_ptr != L'\0')))
		{
			fprint_msg(MSGTYPE_ERR, "The specified thread count is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
	}

	clock_total[0U] = clock();

	/* ----------------------------------------------------- */
	/* Get system properties                                 */
	/* ----------------------------------------------------- */

	if (!(page_size = get_page_size()))
	{
		print_msg(MSGTYPE_ERR, "System error: Failed to determine page size!\n\n");
		goto cleanup;
	}

	if ((page_size % RW_BUFSIZE) != 0)
	{
		fprint_msg(MSGTYPE_ERR, "System error: Page size is *not* a multiple of %zu bytes!\n\n", RW_BUFSIZE);
		goto cleanup;
	}

	phys_memory = get_physical_memory_size();
	if ((phys_memory.total < 1U) || (phys_memory.avail < 1U))
	{
		print_msg(MSGTYPE_ERR, "System error: Failed to determine physical memory size!\n\n");
		goto cleanup;
	}

	fprint_msg(MSGTYPE_NFO, "Total physical memory : %012zu (0x%010zX)\n", phys_memory.total, phys_memory.total);
	fprint_msg(MSGTYPE_NFO, "Avail physical memory : %012zu (0x%010zX)\n", phys_memory.avail, phys_memory.avail);

	if (phys_memory.total <= MIN_MEMORY)
	{
		print_msg(MSGTYPE_ERR, "\nError: Sorry, not enough physical memory!\n\n");
		goto cleanup;
	}

	if ((!target_memory) || percent_mode)
	{
		const double fraction = percent_mode ? (bound(1U, target_memory, 100U) / 100.0) : 0.92;
		target_memory = (SIZE_T) round(phys_memory.total * fraction);
	}
	else
	{
		if (target_memory > phys_memory.total)
		{
			print_msg(MSGTYPE_ERR, "\nError: Specified memory size exceeds the total physical memory size!\n\n");
			goto cleanup;
		}
	}

	target_memory = round_up(target_memory, page_size);
	fprint_msg(MSGTYPE_NFO, "Check physical memory : %012zu (0x%010zX)\n\n", target_memory, target_memory);

	if (!num_threads)
	{
		num_threads = bound(1U, get_cpu_count(), MAX_THREAD);
	}
	else
	{
		if (num_threads > MAX_THREAD)
		{
			print_msg(MSGTYPE_ERR, "Error: Specified number of threads exceeds allowable maximum!\n\n");
			goto cleanup;
		}
	}

	fprint_msg(MSGTYPE_NFO, "Threads count : %zu\n\n", num_threads);

	if (!random_setup())
	{
		print_msg(MSGTYPE_ERR, "System error: Failed to initialize the RtlGenRandom() function!\n\n");
		goto cleanup;
	}

	if (set_process_priority(high_priority))
	{
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	}
	else
	{
		print_msg(MSGTYPE_WRN, "WARNING: Failed to adjust process priority class!\n\n");
	}

	/* ----------------------------------------------------- */
	/* Allocated memory                                      */
	/* ----------------------------------------------------- */

	working_set_size = target_memory + ((IsWindowsVistaOrGreater() ? 128U : 4096U) * page_size);
	if (!SetProcessWorkingSetSize(GetCurrentProcess(), working_set_size, working_set_size))
	{
		print_msg(MSGTYPE_WRN, "WARNING: Failed to set working set size. Memory allocation is probably going to fail!\n\n");
	}

	print_msg(MSGTYPE_NFO, "Allocating memory, please be patient, this will take a while...\n");
	print_msg(MSGTYPE_PRG, "0.0%");
	set_console_progress(0, continuous_mode ? 0U : num_passes, 0.0);

	SecureZeroMemory(CHUNKS, sizeof(chunk_t) * MAX_CHUNKS);
	chunk_size = round_up(128U * 1024U * 1024U, page_size);

	while ((!stop) && (chunk_size >= page_size) && (allocated_memory < target_memory))
	{
		SIZE_T remaining = target_memory - allocated_memory;
		ULONG32 retry_counter = 0U;
		while ((!stop) && (remaining >= chunk_size) && (num_chunks < MAX_CHUNKS))
		{
			LPVOID addr = allocate_chunk(chunk_size);
			if (addr)
			{
				chunk_t *const current_chunk = &CHUNKS[num_chunks++];
				current_chunk->size = chunk_size;
				current_chunk->addr = addr;
				allocated_memory += chunk_size;
				remaining = (allocated_memory < target_memory) ? target_memory - allocated_memory : 0U;
				retry_counter = 0U;
				const double progress = 100.0 * ((double)allocated_memory / target_memory);
				fprint_msg(MSGTYPE_PRG, "\r%.1f%%", progress);
				set_console_progress(0, continuous_mode ? 0U : num_passes, progress);
				if (debug_mode)
				{
					DBG_print_chunk(num_chunks - 1U, chunk_size, addr);
				}
			}
			else
			{
				if (++retry_counter > 5U)
				{
					break; /*allocation has failed!*/
				}
				Sleep(1U);
			}
		}
		chunk_size = (chunk_size > page_size) ? round_up(chunk_size / 2U, page_size) : 0U;
	}

	if (stop)
	{
		print_msg(MSGTYPE_WRN, "\rInterrupted!\n\n");
		goto cleanup;
	}

	fprint_msg(MSGTYPE_FIN, "\r%.1f%% [OK]\n\n", 100.0 * ((double)allocated_memory / target_memory));
	set_console_progress(0, continuous_mode ? 0U : num_passes, 100.0);

	fprint_msg(MSGTYPE_NFO, "Allocated memory : %012zu (0x%010zX)\n\n", allocated_memory, allocated_memory);

	if (allocated_memory < target_memory)
	{
		print_msg(MSGTYPE_ERR, "Error: Failed to allocate the requested amount of physical memory!\n\n");
		print_msg(MSGTYPE_WRN, "NOTE: Please free up more physical memory or try again with a smaller target memory size.\n\n");
		goto cleanup;
	}

	/* ----------------------------------------------------- */
	/* Test memory                                           */
	/* ----------------------------------------------------- */

	for (pass = 0U; continuous_mode || (pass < num_passes); ++pass)
	{
		if (!continuous_mode)
		{
			fprint_msg(MSGTYPE_HDR, "--- [ Pass %zu of %zu ] ---\n\n", pass + 1U, (SIZE_T)num_passes);
		}
		else
		{
			fprint_msg(MSGTYPE_HDR, "--- [ Testing pass %zu ] ---\n\n", pass + 1U);
		}

		clock_pass = clock();

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Fill memory                               */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		print_msg(MSGTYPE_NFO, "Writing memory, please be patient, this will take a while...\n");
		print_msg(MSGTYPE_PRG, "0.0%");
		set_console_progress(pass + 1U, continuous_mode ? 0U : num_passes, 0.0);

		completed = 0LL;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE) _beginthreadex(NULL, 0, thread_fill, (PVOID)thread_idx, 0U, NULL);
			if (thread[thread_idx] == 0U)
			{
				print_msg(MSGTYPE_WRN, "\rFailed!\n\n");
				print_msg(MSGTYPE_ERR, "System error: Thread creation has failed!\n\n");
				while (thread_idx > 0U)
				{
					TerminateThread(thread[--thread_idx], EXIT_FAILURE);
					CloseHandle(thread[thread_idx]);
				}
				goto cleanup;
			}
		}

		while (!stop)
		{
			const DWORD result = WaitForMultipleObjects((DWORD)num_threads, thread, TRUE, UPDATE_INT);
			if ((result >= WAIT_OBJECT_0) && (result < WAIT_OBJECT_0 + num_threads))
			{
				break; /*completed*/
			}
			else if (result == WAIT_TIMEOUT)
			{
				const double progress = 100.0 * ((double)completed / allocated_memory);
				fprint_msg(MSGTYPE_PRG, "\r%.1f%%", progress);
				set_console_progress(pass + 1U, continuous_mode ? 0U : num_passes, 0.5 * progress);
			}
			else
			{
				print_msg(MSGTYPE_WRN, "\rFailed!\n\n");
				print_msg(MSGTYPE_ERR, "System error: Failed to wait for thread!\n\n");
				goto cleanup;
			}
		}

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			if (WaitForSingleObject(thread[thread_idx], 0U) != WAIT_OBJECT_0)
			{
				TerminateThread(thread[thread_idx], EXIT_FAILURE);
			}
			CloseHandle(thread[thread_idx]);
		}

		if (stop)
		{
			print_msg(MSGTYPE_WRN, "\rInterrupted!\n\n");
			goto cleanup;
		}

		fprint_msg(MSGTYPE_FIN, "\r%.1f%% [OK]\n\n", 100.0);

		if ((SIZE_T)completed != allocated_memory)
		{
			print_msg(MSGTYPE_WRN, "WARNING: Completed memory counter does not match total allocated memory!\n\n");
		}

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Check memory                              */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		print_msg(MSGTYPE_NFO, "Reading memory, please be patient, this will take a while...\n");
		print_msg(MSGTYPE_PRG, "0.0%");
		set_console_progress(pass + 1U, continuous_mode ? 0U : num_passes, 50.0);

		completed = 0LL;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE)_beginthreadex(NULL, 0, thread_check, (PVOID)thread_idx, 0U, NULL);
			if (thread[thread_idx] == 0U)
			{
				print_msg(MSGTYPE_WRN, "\rFailed!\n\n");
				print_msg(MSGTYPE_ERR, "System error: Thread creation has failed!\n\n");
				while (thread_idx > 0U)
				{
					TerminateThread(thread[--thread_idx], EXIT_FAILURE);
					CloseHandle(thread[thread_idx]);
				}
				goto cleanup;
			}
		}

		while (!stop)
		{
			const DWORD result = WaitForMultipleObjects((DWORD)num_threads, thread, TRUE, UPDATE_INT);
			if ((result >= WAIT_OBJECT_0) && (result < WAIT_OBJECT_0 + num_threads))
			{
				break; /*completed*/
			}
			else if (result == WAIT_TIMEOUT)
			{
				const double progress = 100.0 * ((double)completed / allocated_memory);
				fprint_msg(MSGTYPE_PRG, "\r%.1f%%", progress);
				set_console_progress(pass + 1U, continuous_mode ? 0U : num_passes, 50.0 + (0.5 * progress));
			}
			else
			{
				print_msg(MSGTYPE_WRN, "\rFailed!\n\n");
				print_msg(MSGTYPE_ERR, "System error: Failed to wait for thread!\n\n");
				goto cleanup;
			}
		}

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			if (WaitForSingleObject(thread[thread_idx], 0U) != WAIT_OBJECT_0)
			{
				TerminateThread(thread[thread_idx], EXIT_FAILURE);
			}
			CloseHandle(thread[thread_idx]);
		}

		if (chk_error != 0LL)
		{
			print_msg(MSGTYPE_WRN, "\rFailed!\n\n");
			fprint_msg(MSGTYPE_ERR, "Error: %lld hash check(s) have failed. Memory corrupted :-(\n\n", chk_error);
			goto cleanup;
		}

		if (stop)
		{
			print_msg(MSGTYPE_WRN, "\rInterrupted!\n\n");
			goto cleanup;
		}

		fprint_msg(MSGTYPE_FIN, "\r%.1f%% [OK]\n\n", 100.0);
		set_console_progress(pass + 1U, continuous_mode ? 0U : num_passes, 100.0);

		if ((SIZE_T)completed != allocated_memory)
		{
			print_msg(MSGTYPE_WRN, "WARNING: Completed memory counter does not match total allocated memory!\n\n");
		}

		fprint_msg(MSGTYPE_NFO, "Pass completed after %.1f seconds.\n\n", (clock() - clock_pass) / ((double)CLOCKS_PER_SEC));
	}

	/* ----------------------------------------------------- */
	/* Clean-up                                              */
	/* ----------------------------------------------------- */

	print_msg(MSGTYPE_HDR, "--- [ Completed ] ---\n\n");
	print_msg(MSGTYPE_FIN, "No errors have been detected during the test :-)\n\n");
	
	exit_code = EXIT_SUCCESS;

cleanup:

	clock_total[1U] = clock();

	print_msg(MSGTYPE_NFO, "Cleaning up... ");

	for (chunk_idx = 0U; chunk_idx < num_chunks; ++chunk_idx)
	{
		chunk_t *const current_chunk = &CHUNKS[chunk_idx];
		if (current_chunk->addr)
		{
			VirtualFree(current_chunk->addr, 0U, MEM_RELEASE);
		}
		current_chunk->addr = NULL;
	}

	fprint_msg(MSGTYPE_NFO, "Goodbye!\n\nTest run completed after %.1f seconds.\n\n", (clock_total[1U] - clock_total[0U]) / ((double)CLOCKS_PER_SEC));

	if (!(batch_mode || stop))
	{
		system("pause"); /*prevent terminal from closing*/
	}

	return exit_code;
}

int wmain(const int argc, const wchar_t *const argv[])
{
	__try
	{
		SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
		return memchecker_main(argc, argv);
	}
	__except(1)
	{
		const DWORD ex_code = GetExceptionCode();
		fprintf(stderr, "\n\nEXCEPTION: Something went seriously wrong! (Exception code: %lu)\n\n", ex_code);
		fflush(stderr);
	}
}
