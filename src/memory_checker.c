/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#if !defined(_M_X64) && !defined(__x86_64__)
#error This program should be compiled as x86-64 binary!
#endif

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <versionhelpers.h>
#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <math.h>
#include <process.h>
#include "utils.h"
#include "allocate.h"
#include "terminal.h"
#include "random.h"
#include "md5.h"
#include "version.h"

#define MAX_CHUNKS 8192U
#define MAX_THREAD 32U
#define MIN_MEMORY (512U * 1024U * 1024U)
#define RW_BUFSIZE ((SIZE_T)16U)
#define UPDATE_INT 997U

/* ====================================================================== */
/* Typedefs                                                               */
/* ====================================================================== */

typedef struct
{
	SIZE_T size;
	BYTE *addr;
}
chunk_t;

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

static void exception_handler(const DWORD ex_code)
{
	fprintf(stderr, "\n\nEXCEPTION: Something went seriously wrong! (Exception code: 0x%08lX)\n\n", ex_code);
	_Exit(-1);
}

static LONG unhandled_exception_filter(const PEXCEPTION_POINTERS ex_info)
{
	exception_handler(ex_info->ExceptionRecord->ExceptionCode);
	return 0L;
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

static void update_progress(const SIZE_T pass, const SIZE_T total, const double progress)
{
	if (total > 0U)
	{
		term_title_wsetf(L"[%llu/%llu] %.1f%% - Memory Checker", pass, total, progress);
	}
	else
	{
		term_title_wsetf(L"[%llu/\u221E] %.1f%% - Memory Checker", pass, progress);
	}
}

static inline void debug_chunk(const SIZE_T index, const SIZE_T size, const PVOID* const addr)
{
	dbg_printf("[Memchkr] Memory: %04llX - %09llu - 0x%016llX\n", index, size, (ULONG_PTR)addr);
}

static inline void debug_digest(const SIZE_T index, const BYTE* const digest, const BOOL read_mode)
{
	dbg_printf("[Memchkr] Digest: %04llX - %s:%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n",
		index, read_mode ? "RD" : "WR",
		digest[0U], digest[1U], digest[ 2U], digest[ 3U], digest[ 4U], digest[ 5U], digest[ 6U], digest[ 7U],
		digest[8U], digest[9U], digest[10U], digest[11U], digest[12U], digest[13U], digest[14U], digest[15U]);
}

static inline void print_app_logo(void)
{
	term_printf(MSGTYPE_CYN, "Memory Checker v%u.%02u-%u [%s], by LoRd_MuldeR <MuldeR2@GMX.de>\n", MEMCK_VERSION_MAJOR, (10U * MEMCK_VERSION_MINOR_HI) + MEMCK_VERSION_MINOR_LO, MEMCK_VERSION_PATCH, BUILD_DATE);
	term_puts(MSGTYPE_CYN, "This work has been released under the CC0 1.0 Universal license!\n\n");
}

/* ====================================================================== */
/* Threads                                                                */
/* ====================================================================== */

static UINT32 thread_fill_loop(const SIZE_T id)
{
	md5_ctx_t md5_ctx;
	rand_state_t rand_state;
	SIZE_T chunk_idx, upd_counter = 0U;
	BYTE temp[RW_BUFSIZE];

	if (!random_seed(&rand_state))
	{
		return EXIT_FAILURE;
	}

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
			debug_digest(chunk_idx, DIGEST[chunk_idx], FALSE);
		}
	}

	if (upd_counter > 0U)
	{
		InterlockedAdd64(&completed, upd_counter * RW_BUFSIZE);
	}

	return stop ? EXIT_FAILURE : EXIT_SUCCESS;
}

static UINT32 thread_check_loop(const SIZE_T id)
{
	md5_ctx_t md5_ctx;
	SIZE_T chunk_idx, upd_counter = 0U;
	BYTE digest[MD5_HASH_SIZE], temp[RW_BUFSIZE];

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
			debug_digest(chunk_idx, digest, TRUE);
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

static UINT32 thread_fill(void* const arg)
{
	int ret = EXIT_FAILURE;
#ifdef _MSC_VER
	__try
	{
		ret = thread_fill_loop((SIZE_T)((UINT_PTR)arg));
	}
	__except (1)
	{
		exception_handler(GetExceptionCode());
	}
#else
	ret = thread_fill_loop((SIZE_T)((UINT_PTR)arg));
#endif
	return ret;
}

static UINT32 thread_check(void* const arg)
{
	int ret = EXIT_FAILURE;
#ifdef _MSC_VER
	__try
	{
		ret = thread_check_loop((SIZE_T)((UINT_PTR)arg));
	}
	__except (1)
	{
		exception_handler(GetExceptionCode());
	}
#else
	ret = thread_check_loop((SIZE_T)((UINT_PTR)arg));
#endif
	return ret;
}

/* ====================================================================== */
/* MAIN                                                                   */
/* ====================================================================== */

static int memchecker_main(const int argc, const wchar_t* const argv[])
{
	int exit_code = EXIT_FAILURE, arg_offset = 1;
	SIZE_T target_memory = 0U, allocated_memory = 0U, page_size = 0U, chunk_size = 0U, pass = 0U, chunk_idx = 0U, thread_idx = 0U;
	ULONG64 clock_frequency = 1U, clock_total[2U] = { 0U, 0U }, clock_pass[2U] = { 0U, 0U };
	BOOL batch_mode = FALSE, continuous_mode = FALSE, percent_mode = FALSE, high_priority = FALSE;
	meminfo_t phys_memory;
	HANDLE thread[MAX_THREAD];

	term_init();
	term_title_wset(L"Memory Checker");

	/* ----------------------------------------------------- */
	/* Parse parameters                                      */
	/* ----------------------------------------------------- */

	while (arg_offset < argc)
	{
		if ((!_wcsicmp(argv[arg_offset], L"-h")) || (!_wcsicmp(argv[arg_offset], L"/?")) || (!_wcsicmp(argv[arg_offset], L"-?")) || (!_wcsicmp(argv[arg_offset], L"--help")))
		{
			print_app_logo();
			term_puts(MSGTYPE_WHT, "Usage:\n");
			term_puts(MSGTYPE_WHT, "  MemoryChecker.exe [--batch] [--continuous] [<target_memory_size>[%]] [<threads>]\n\n");
			term_puts(MSGTYPE_WHT, "Default memory size to test is ~95% of the total physical memory.\n\n");
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
				term_enable_colors(color_mode);
				print_app_logo();
				term_printf(MSGTYPE_RED, "The specified option is unknown: \"--%S\"\n\n", option);
				return EXIT_FAILURE;
			}
		}
		break;
	}

	term_enable_colors(color_mode);
	print_app_logo();

	if (read_envvar(L"MEMCHCK_PASSES", &num_passes) < 0L)
	{
		term_puts(MSGTYPE_RED, "Number of passes specified in environment variable MEMCHCK_PASSES is invalid!\n\n");
		return EXIT_FAILURE;
	}

	if (arg_offset < argc)
	{
		const wchar_t *const value = argv[arg_offset++];
		wchar_t *end_ptr = NULL;
		target_memory = wcstoull(value, &end_ptr, 10);
		if ((!target_memory) || (end_ptr && (*end_ptr != L'%') && (*end_ptr != L'\0')))
		{
			term_printf(MSGTYPE_RED, "The specified target memory size is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
		if (end_ptr && (*end_ptr == L'%'))
		{
			percent_mode = TRUE;
			if (target_memory > 100U)
			{
				term_puts(MSGTYPE_RED, "Error: Cannot allocated more than 100% of the total physical memory!\n\n");
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
			term_printf(MSGTYPE_RED, "The specified thread count is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
	}

	/* ----------------------------------------------------- */
	/* Get system properties                                 */
	/* ----------------------------------------------------- */

	clock_frequency = get_performance_frequency();
	clock_total[0U] = query_performance_counter();

	if (!(page_size = get_page_size()))
	{
		term_puts(MSGTYPE_RED, "System error: Failed to determine page size!\n\n");
		goto cleanup;
	}

	if ((page_size % RW_BUFSIZE) != 0)
	{
		term_printf(MSGTYPE_RED, "System error: Page size is *not* a multiple of %llu bytes!\n\n", RW_BUFSIZE);
		goto cleanup;
	}

	phys_memory = get_physical_memory_info();
	if ((phys_memory.total < 1U) || (phys_memory.avail < 1U))
	{
		term_puts(MSGTYPE_RED, "System error: Failed to determine physical memory size!\n\n");
		goto cleanup;
	}

	term_printf(MSGTYPE_WHT, "Total physical memory : %012llu (0x%010llX)\n", phys_memory.total, phys_memory.total);
	term_printf(MSGTYPE_WHT, "Avail physical memory : %012llu (0x%010llX)\n", phys_memory.avail, phys_memory.avail);

	if (phys_memory.total <= MIN_MEMORY)
	{
		term_puts(MSGTYPE_RED, "\nError: Sorry, not enough physical memory!\n\n");
		goto cleanup;
	}

	if (percent_mode)
	{
		target_memory = (SIZE_T) round(phys_memory.total * (bound(1U, target_memory, 100U) / 100.0));
	}
	else if (!target_memory)
	{
		target_memory = get_max((SIZE_T)round(phys_memory.total * 0.9), (SIZE_T)round(phys_memory.avail * 0.99));
	}
	else if (target_memory > phys_memory.total)
	{
		term_puts(MSGTYPE_RED, "\nError: Specified memory size exceeds total physical memory size!\n\n");
		goto cleanup;
	}

	target_memory = round_up(target_memory, page_size);
	term_printf(MSGTYPE_WHT, "Check physical memory : %012llu (0x%010llX)\n\n", target_memory, target_memory);

	if (!num_threads)
	{
		num_threads = bound(1U, get_cpu_count(), MAX_THREAD);
	}
	else
	{
		if (num_threads > MAX_THREAD)
		{
			term_puts(MSGTYPE_RED, "Error: Specified number of threads exceeds allowable maximum!\n\n");
			goto cleanup;
		}
	}

	term_printf(MSGTYPE_WHT, "Threads count : %llu\n\n", num_threads);

	if (set_process_priority(high_priority))
	{
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
	}
	else
	{
		term_puts(MSGTYPE_YLW, "WARNING: Failed to adjust process priority class!\n\n");
	}

	/* ----------------------------------------------------- */
	/* Allocated memory                                      */
	/* ----------------------------------------------------- */

	if (!change_working_set_size(target_memory + ((IsWindowsVistaOrGreater() ? 128U : 4096U) * page_size)))
	{
		term_puts(MSGTYPE_YLW, "WARNING: Failed to change working set size. Allocation is likely to fail !!!\n\n");
	}

	term_puts(MSGTYPE_WHT, "Allocating memory, please be patient, this will take a while...\n");
	term_puts(MSGTYPE_MAG, "0.0%");
	update_progress(0, continuous_mode ? 0U : num_passes, 0.0);

	SecureZeroMemory(CHUNKS, sizeof(chunk_t) * MAX_CHUNKS);
	chunk_size = round_up(get_max(8U * 1024U * 1024U, get_min(256U * 1024U * 1024U, target_memory / num_threads)), page_size);

	while ((!stop) && (chunk_size >= page_size) && (allocated_memory < target_memory))
	{
		SIZE_T remaining = target_memory - allocated_memory;
		ULONG32 retry_counter = 0U;
		while ((!stop) && (remaining >= chunk_size) && (num_chunks < MAX_CHUNKS))
		{
			LPVOID addr = allocate_physical_memory(chunk_size);
			if (addr)
			{
				chunk_t *const current_chunk = &CHUNKS[num_chunks++];
				current_chunk->size = chunk_size;
				current_chunk->addr = addr;
				allocated_memory += chunk_size;
				remaining = (allocated_memory < target_memory) ? target_memory - allocated_memory : 0U;
				retry_counter = 0U;
				const double progress = 100.0 * ((double)allocated_memory / target_memory);
				term_printf(MSGTYPE_MAG, "\r%.1f%%", progress);
				update_progress(0, continuous_mode ? 0U : num_passes, progress);
				if (debug_mode)
				{
					debug_chunk(num_chunks - 1U, chunk_size, addr);
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
		term_puts(MSGTYPE_YLW, "\rInterrupted!\n\n");
		goto cleanup;
	}

	term_printf(MSGTYPE_GRN, "\r%.1f%% [OK]\n\n", 100.0 * ((double)allocated_memory / target_memory));
	update_progress(0, continuous_mode ? 0U : num_passes, 100.0);

	term_printf(MSGTYPE_WHT, "Allocated memory : %012llu (0x%010llX)\n\n", allocated_memory, allocated_memory);

	if (allocated_memory < target_memory)
	{
		term_puts(MSGTYPE_RED, "Error: Failed to allocate the requested amount of physical memory!\n\n");
		term_puts(MSGTYPE_YLW, "NOTE: Please free up more physical memory or try again with a smaller target memory size.\n\n");
		goto cleanup;
	}

	/* ----------------------------------------------------- */
	/* Test memory                                           */
	/* ----------------------------------------------------- */

	for (pass = 0U; continuous_mode || (pass < num_passes); ++pass)
	{
		if (!continuous_mode)
		{
			term_printf(MSGTYPE_CYN, "--- [ Pass %llu of %llu ] ---\n\n", pass + 1U, (SIZE_T)num_passes);
		}
		else
		{
			term_printf(MSGTYPE_CYN, "--- [ Testing pass %llu ] ---\n\n", pass + 1U);
		}

		clock_pass[0U] = query_performance_counter();

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Fill memory                               */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		term_puts(MSGTYPE_WHT, "Writing memory, please be patient, this will take a while...\n");
		term_puts(MSGTYPE_MAG, "0.0%");
		update_progress(pass + 1U, continuous_mode ? 0U : num_passes, 0.0);

		completed = 0LL;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE) _beginthreadex(NULL, 0, thread_fill, (PVOID)((UINT_PTR)thread_idx), 0U, NULL);
			if (!thread[thread_idx])
			{
				term_puts(MSGTYPE_YLW, "\rFailed!\n\n");
				term_puts(MSGTYPE_RED, "System error: Thread creation has failed!\n\n");
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
				term_printf(MSGTYPE_MAG, "\r%.1f%%", progress);
				update_progress(pass + 1U, continuous_mode ? 0U : num_passes, 0.5 * progress);
			}
			else
			{
				term_puts(MSGTYPE_YLW, "\rFailed!\n\n");
				term_puts(MSGTYPE_RED, "System error: Failed to wait for thread!\n\n");
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
			term_puts(MSGTYPE_YLW, "\rInterrupted!\n\n");
			goto cleanup;
		}

		term_printf(MSGTYPE_GRN, "\r%.1f%% [OK]\n\n", 100.0);

		if ((SIZE_T)completed != allocated_memory)
		{
			term_puts(MSGTYPE_YLW, "WARNING: Completed memory counter does not match total allocated memory!\n\n");
		}

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Check memory                              */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		term_puts(MSGTYPE_WHT, "Reading memory, please be patient, this will take a while...\n");
		term_puts(MSGTYPE_MAG, "0.0%");
		update_progress(pass + 1U, continuous_mode ? 0U : num_passes, 50.0);

		completed = 0LL;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE)_beginthreadex(NULL, 0, thread_check, (PVOID)((UINT_PTR)thread_idx), 0U, NULL);
			if (!thread[thread_idx])
			{
				term_puts(MSGTYPE_YLW, "\rFailed!\n\n");
				term_puts(MSGTYPE_RED, "System error: Thread creation has failed!\n\n");
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
				term_printf(MSGTYPE_MAG, "\r%.1f%%", progress);
				update_progress(pass + 1U, continuous_mode ? 0U : num_passes, 50.0 + (0.5 * progress));
			}
			else
			{
				term_puts(MSGTYPE_YLW, "\rFailed!\n\n");
				term_puts(MSGTYPE_RED, "System error: Failed to wait for thread!\n\n");
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
			term_puts(MSGTYPE_YLW, "\rFailed!\n\n");
			term_printf(MSGTYPE_RED, "Error: %lld hash check(s) have failed. Memory corrupted :-(\n\n", chk_error);
			goto cleanup;
		}

		if (stop)
		{
			term_puts(MSGTYPE_YLW, "\rInterrupted!\n\n");
			goto cleanup;
		}

		term_printf(MSGTYPE_GRN, "\r%.1f%% [OK]\n\n", 100.0);
		update_progress(pass + 1U, continuous_mode ? 0U : num_passes, 100.0);

		if ((SIZE_T)completed != allocated_memory)
		{
			term_puts(MSGTYPE_YLW, "WARNING: Completed memory counter does not match total allocated memory!\n\n");
		}

		clock_pass[1U] = query_performance_counter();
		term_printf(MSGTYPE_WHT, "Pass completed after %.2f seconds.\n\n", (clock_pass[1U] - clock_pass[0U]) / ((double)clock_frequency));
	}

	/* ----------------------------------------------------- */
	/* Clean-up                                              */
	/* ----------------------------------------------------- */

	term_puts(MSGTYPE_CYN, "--- [ Completed ] ---\n\n");
	term_puts(MSGTYPE_GRN, "No errors have been detected during the test :-)\n\n");
	
	exit_code = EXIT_SUCCESS;

cleanup:

	clock_total[1U] = query_performance_counter();

	term_puts(MSGTYPE_WHT, "Cleaning up... ");

	for (chunk_idx = 0U; chunk_idx < num_chunks; ++chunk_idx)
	{
		chunk_t *const current_chunk = &CHUNKS[chunk_idx];
		if (current_chunk->addr)
		{
			free_physical_memory(current_chunk->addr);
			current_chunk->addr = NULL;
		}
	}

	term_printf(MSGTYPE_WHT, "Goodbye!\n\nTest run completed after %.2f seconds.\n\n", (clock_total[1U] - clock_total[0U]) / ((double)clock_frequency));

	term_exit();

	if (!(batch_mode || stop))
	{
		system("pause"); /*prevent terminal from closing*/
	}

	return exit_code;
}

int wmain(const int argc, const wchar_t *const argv[])
{
	int ret = EXIT_FAILURE;
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#ifdef _MSC_VER
	__try
	{
		ret = memchecker_main(argc, argv);
	}
	__except (1)
	{
		exception_handler(GetExceptionCode());
	}
#else
	SetUnhandledExceptionFilter(unhandled_exception_filter);
	ret = memchecker_main(argc, argv);
#endif
	return ret;
}
