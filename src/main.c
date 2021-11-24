/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef _M_X64
#error This program should be compiled as x64 binary!
#endif

#define _CRT_RAND_S
#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <process.h>

#define MAX_CHUNKS 4096U
#define MAX_THREAD   32U
#define NUM_PASSES    5U

#define MIN_MEMORY (512U * 1024U * 1024U)

#include "crc64table.h"

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
	ULONG32 x, y, z, w, v, d;
}
rand_state_t;

typedef struct
{
	BYTE buffer[sizeof(ULONG32)];
	SIZE_T offset;
	rand_state_t random;
}
byte_state_t;

typedef struct
{
	SIZE_T size;
	BYTE *addr;
}
chunk_t;

/* ====================================================================== */
/* Globals                                                                */
/* ====================================================================== */

static chunk_t CHUNKS[MAX_CHUNKS];
static ULONG64 CRC[MAX_CHUNKS];

static SIZE_T num_chunks = 0U, num_threads = 0U;

static volatile SIZE_T completed = 0U;
static volatile SIZE_T crc_error = 0U;

static volatile BOOL stop = FALSE;

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

static SIZE_T get_min_working_set_size()
{
	SIZE_T min_size, max_size;
	if (GetProcessWorkingSetSize(GetCurrentProcess(), &min_size, &max_size))
	{
		return min_size;
	}
	return 0U;
}

static SIZE_T get_cpu_count()
{
	SYSTEM_INFO info;
	SecureZeroMemory(&info, sizeof(SYSTEM_INFO));
	GetSystemInfo(&info);
	return info.dwNumberOfProcessors;
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

static void set_console_progress(const SIZE_T pass, const SIZE_T total, const double progress)
{
	wchar_t buffer[64U];
	if (total > 0U)
	{
		_snwprintf_s(buffer, 64U, _TRUNCATE, L"[%llu/%llu] %.1f%% - Memory Checker", pass, total, progress);
	}
	else
	{
		_snwprintf_s(buffer, 64U, _TRUNCATE, L"[%llu] %.1f%% - Memory Checker", pass, progress);
	}
	SetConsoleTitleW(buffer);
}

static void random_init(rand_state_t *const state)
{
	SecureZeroMemory(state, sizeof(rand_state_t));
	rand_s(&state->x);
	rand_s(&state->y);
	rand_s(&state->z);
	rand_s(&state->w);
	rand_s(&state->v);
	rand_s(&state->d);
}

static inline ULONG32 random_next(rand_state_t *const state)
{
	const ULONG32 t = state->x ^ (state->x >> 2);
	state->x = state->y;
	state->y = state->z;
	state->z = state->w;
	state->w = state->v;
	state->v ^= (state->v << 4) ^ t ^ (t << 1);
	return (state->d += 0x000587C5) + state->v;
}

static inline BYTE next_byte(byte_state_t *const state)
{
	if (state->offset >= sizeof(ULONG32))
	{
		*((ULONG32*)&state->buffer) = random_next(&state->random);
		state->offset = 0U;
	}
	return state->buffer[state->offset++];
}

static inline void crc_update(ULONG64 *const crc, const ULONG32 value)
{
	const BYTE *p = (const BYTE*)&value;
	for (SIZE_T i = 0U; i < sizeof(ULONG32); ++i)
	{
		const SIZE_T t = (((*crc) >> 56) ^ (*p++)) & 0xFF;
		*crc = CRC64_TABLE[t] ^ ((*crc) << 8);
	}
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

/* ====================================================================== */
/* Thread                                                                 */
/* ====================================================================== */

static DWORD thread_fill(void *const arg)
{
	rand_state_t rand_state;
	SIZE_T chunk_idx;
	const SIZE_T id = (SIZE_T)arg;

	random_init(&rand_state);

	for (chunk_idx = id; (!stop) && (chunk_idx < num_chunks); chunk_idx += num_threads)
	{
		ULONG64* const crc = &CRC[chunk_idx];
		*crc = (ULONG64)~0;
		BYTE *const limit = CHUNKS[chunk_idx].addr + CHUNKS[chunk_idx].size;
		for (BYTE *addr = CHUNKS[chunk_idx].addr; addr < limit; addr += sizeof(ULONG32))
		{
			const ULONG32 value = random_next(&rand_state);
			crc_update(crc, value);
			memcpy(addr, &value, sizeof(ULONG32));
		}
		InterlockedAdd64(&completed, CHUNKS[chunk_idx].size);
	}

	return stop ? EXIT_FAILURE : EXIT_SUCCESS;
}

static DWORD thread_check(void *const arg)
{
	SIZE_T chunk_idx;
	const SIZE_T id = (SIZE_T)arg;

	for (chunk_idx = id; (!stop) && (chunk_idx < num_chunks); chunk_idx += num_threads)
	{
		ULONG64 crc = (ULONG64)~0;
		BYTE* const limit = CHUNKS[chunk_idx].addr + CHUNKS[chunk_idx].size;
		for (BYTE* addr = CHUNKS[chunk_idx].addr; addr < limit; addr += sizeof(ULONG32))
		{
			ULONG32 value;
			memcpy(&value, addr, sizeof(ULONG32));
			crc_update(&crc, value);
		}
		if (crc != CRC[chunk_idx])
		{
			InterlockedIncrement64(&crc_error);
		}
		InterlockedAdd64(&completed, CHUNKS[chunk_idx].size);
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
	SIZE_T chunk_size, working_set_size, pass, completed_last, chunk_idx, thread_idx;
	BOOL batch_mode = FALSE, continuous_mode = FALSE;
	meminfo_t phys_memory;
	HANDLE thread[MAX_THREAD];

	fputs("Memory Checker [" __DATE__ "], by LoRd_MuldeR <MuldeR2@GMX.de>\n", stderr);
	fputs("This work has been released under the CC0 1.0 Universal license!\n\n", stderr);

	SetConsoleTitleW(L"Memory Checker");

	while (arg_offset < argc)
	{
		if ((!_wcsicmp(argv[arg_offset], L"-h")) || (!_wcsicmp(argv[arg_offset], L"/?")) || (!_wcsicmp(argv[arg_offset], L"-?")) || (!_wcsicmp(argv[arg_offset], L"--help")))
		{
			fputs("Usage:\n", stderr);
			fputs("  MemoryChecker.exe [--batch] [--continuous] [<memory_size>] [<threads>]\n\n", stderr);
			fputs("Default memory size to test is ~95% of the total physical memory.\n\n", stderr);
			return EXIT_SUCCESS;
		}
		if ((argv[arg_offset][0U] == L'-') && (argv[arg_offset][1U] == L'-'))
		{
			const wchar_t *const option = argv[arg_offset++] + 2U;
			if (option[0U] != L'\0')
			{
				if (!_wcsicmp(option, L"batch"))
				{
					batch_mode = TRUE;
				}
				else if (!_wcsicmp(option, L"continuous"))
				{
					continuous_mode = TRUE;
				}
				else
				{
					fprintf(stderr, "The specified option is unknown: \"--%S\"\n\n", option);
					return EXIT_FAILURE;
				}
				continue;
			}
		}
		break; /*no more options*/
	}

	if (arg_offset < argc)
	{
		const wchar_t *const value = argv[arg_offset++];
		target_memory = wcstoull(value, NULL, 10);
		if (!target_memory)
		{
			fprintf(stderr, "The specified memory size is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
	}

	if (arg_offset < argc)
	{
		const wchar_t *const value = argv[arg_offset++];
		num_threads = wcstoull(value, NULL, 10);
		if (!num_threads)
		{
			fprintf(stderr, "The specified thread count is invalid: \"%S\"\n\n", value);
			return EXIT_FAILURE;
		}
	}

	if (!(page_size = get_page_size()))
	{
		fputs("System error: Failed to determine page size!\n\n", stderr);
		goto cleanup;
	}

	if (page_size % sizeof(ULONG64) != 0)
	{
		fputs("System error: Page size is *not* a multiple of 4 bytes!\n\n", stderr);
		goto cleanup;
	}

	phys_memory = get_physical_memory_size();
	if ((phys_memory.total < 1U) || (phys_memory.avail < 1U))
	{
		fputs("System error: Failed to determine physical memory size!\n\n", stderr);
		goto cleanup;
	}

	fprintf(stderr, "Total physical memory : %012llu (0x%010llX)\n", phys_memory.total, phys_memory.total);
	fprintf(stderr, "Avail physical memory : %012llu (0x%010llX)\n", phys_memory.avail, phys_memory.avail);

	if (phys_memory.total < MIN_MEMORY)
	{
		fputs("\nError: Sorry, not enough physical memory!\n\n", stderr);
		goto cleanup;
	}

	if (!target_memory)
	{
		target_memory = (UINT64)round(phys_memory.total * 0.95);
	}
	else
	{
		if (target_memory > phys_memory.total)
		{
			fputs("\nError: Specified memory size exceeds the total physical memory size!\n\n", stderr);
			goto cleanup;
		}
	}

	target_memory = round_up(get_min(phys_memory.total - MIN_MEMORY, target_memory), page_size);
	fprintf(stderr, "Check physical memory : %012llu (0x%010llX)\n\n", target_memory, target_memory);

	if (!num_threads)
	{
		num_threads = get_cpu_count();
	}

	num_threads = bound(1U, num_threads, MAX_THREAD);
	fprintf(stderr, "Threads count : %llu\n\n", num_threads);

	/* ----------------------------------------------------- */
	/* Allocated memory                                      */
	/* ----------------------------------------------------- */

	working_set_size = round_up(target_memory + get_max(204800U, get_min_working_set_size()), page_size);
	if (!SetProcessWorkingSetSize(GetCurrentProcess(), working_set_size, working_set_size))
	{
		fputs("WARNING: Failed to set working set size. Memory allocation is probably going to fail!\n\n", stderr);
	}

	fputs("Allocating memory, please be patient, this will take a while...\n", stderr);
	fputs("0.0%", stderr);
	fflush(stderr);
	set_console_progress(0, continuous_mode ? 0U : NUM_PASSES, 0.0);

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
				fprintf(stderr, "\r%.1f%%", progress);
				fflush(stderr);
				set_console_progress(0, continuous_mode ? 0U : NUM_PASSES, progress);
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
		chunk_size = (chunk_size > page_size) ? round_up(chunk_size / 2U, page_size) : (page_size / 2U);
	}

	if (stop)
	{
		fputs("\rInterrupted!\n\n", stderr);
		goto cleanup;
	}

	fprintf(stderr, "\r%.1f%% [OK]\n\n", 100.0 * ((double)allocated_memory / target_memory));
	fflush(stderr);
	set_console_progress(0, continuous_mode ? 0U : NUM_PASSES, 100.0);

	fprintf(stderr, "Allocated memory : %012llu (0x%010llX)\n\n", allocated_memory, allocated_memory);

	if (allocated_memory < target_memory)
	{
		fputs("Error: Failed to allocate the requested amount of physical memory!\n\n", stderr);
		goto cleanup;
	}

	/* ----------------------------------------------------- */
	/* Test memory                                           */
	/* ----------------------------------------------------- */

	for (pass = 0U; continuous_mode || (pass < NUM_PASSES); ++pass)
	{
		if (!continuous_mode)
		{
			fprintf(stderr, "--- [ Pass %llu of %llu ] ---\n\n", pass + 1U, (SIZE_T)NUM_PASSES);
			fflush(stderr);
		}
		else
		{
			fprintf(stderr, "--- [ Testing pass %llu ] ---\n\n", pass + 1U);
			fflush(stderr);
		}

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Fill memory                               */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		fputs("Writing memory, please be patient, this will take a while...\n", stderr);
		fputs("0.0%", stderr);
		fflush(stderr);
		set_console_progress(pass + 1U, continuous_mode ? 0U : NUM_PASSES, 0.0);

		completed = completed_last = 0U;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE)_beginthreadex(NULL, 0, thread_fill, (PVOID)thread_idx, 0U, NULL);
			if (thread[thread_idx] == 0U)
			{
				fputs("\rFailed!\n\n", stderr);
				fputs("System error: Thread creation has failed!\n\n", stderr);
				goto cleanup;
			}
		}

		while (!stop)
		{
			const DWORD result = WaitForMultipleObjects((DWORD)num_threads, thread, TRUE, 1250U);
			if ((result >= WAIT_OBJECT_0) && (result < WAIT_OBJECT_0 + num_threads))
			{
				break; /*completed*/
			}
			else if (result == WAIT_TIMEOUT)
			{
				const SIZE_T completed_current = completed;
				if (completed_current != completed_last)
				{
					const double progress = 100.0 * ((double)completed_current / allocated_memory);
					fprintf(stderr, "\r%.1f%%", progress);
					fflush(stderr);
					set_console_progress(pass + 1U, continuous_mode ? 0U : NUM_PASSES, 0.5 * progress);
					completed_last = completed_current;
				}
			}
			else
			{
				fputs("\rFailed!\n\n", stderr);
				fputs("System error: Failed to wait for thread!\n\n", stderr);
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
			fputs("\rInterrupted!\n\n", stderr);
			goto cleanup;
		}

		fprintf(stderr, "\r%.1f%% [OK]\n\n", 100.0 * ((double)completed / allocated_memory));
		fflush(stderr);

		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
		/* Check memory                              */
		/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

		fputs("Reading memory, please be patient, this will take a while...\n", stderr);
		fputs("0.0%", stderr);
		fflush(stderr);
		set_console_progress(pass + 1U, continuous_mode ? 0U : NUM_PASSES, 50.0);

		completed = completed_last = 0U;

		for (thread_idx = 0U; thread_idx < num_threads; ++thread_idx)
		{
			thread[thread_idx] = (HANDLE)_beginthreadex(NULL, 0, thread_check, (PVOID)thread_idx, 0U, NULL);
			if (thread[thread_idx] == 0U)
			{
				fputs("\rFailed!\n\n", stderr);
				fputs("System error: Thread creation has failed!\n\n", stderr);
				goto cleanup;
			}
		}

		while (!stop)
		{
			const DWORD result = WaitForMultipleObjects((DWORD)num_threads, thread, TRUE, 1250U);
			if ((result >= WAIT_OBJECT_0) && (result < WAIT_OBJECT_0 + num_threads))
			{
				break; /*completed*/
			}
			else if (result == WAIT_TIMEOUT)
			{
				const SIZE_T completed_current = completed;
				if (completed_current != completed_last)
				{
					const double progress = 100.0 * ((double)completed_current / allocated_memory);
					fprintf(stderr, "\r%.1f%%", progress);
					fflush(stderr);
					set_console_progress(pass + 1U, continuous_mode ? 0U : NUM_PASSES, 50.0 + (0.5 * progress));
					completed_last = completed_current;
				}
			}
			else
			{
				fputs("\rFailed!\n\n", stderr);
				fputs("System error: Failed to wait for thread!\n\n", stderr);
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

		if (crc_error != 0U)
		{
			fputs("\rFailed!\n\n", stderr);
			fprintf(stderr, "Error: %llu CRC check(s) have failed. Memory corruption :-(\n\n", crc_error);
			goto cleanup;
		}

		if (stop)
		{
			fputs("\rInterrupted!\n\n", stderr);
			goto cleanup;
		}

		fprintf(stderr, "\r%.1f%% [OK]\n\n", 100.0 * ((double)completed / allocated_memory));
		fflush(stderr);
		set_console_progress(pass + 1U, continuous_mode ? 0U : NUM_PASSES, 100.0);
	}

	/* ----------------------------------------------------- */
	/* Clean-up                                              */
	/* ----------------------------------------------------- */

	fputs("--- [ Completed ] ---\n\n", stderr);
	fputs("No errors have been detected during the test :-)\n\n", stderr);
	
	exit_code = EXIT_SUCCESS;
	
cleanup:

	fputs("Cleaning up... ", stderr);

	for (chunk_idx = 0U; chunk_idx < num_chunks; ++chunk_idx)
	{
		chunk_t *const current_chunk = &CHUNKS[chunk_idx];
		if (current_chunk->addr)
		{
			VirtualFree(current_chunk->addr, 0U, MEM_RELEASE);
		}
		current_chunk->addr = NULL;
	}

	fputs("Goodbye!\n\n", stderr);

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
		fprintf(stderr, "\n\nEXCEPTION: Something went seriously wrong! (Exception code: %u)\n\n", ex_code);
		fflush(stderr);
	}
}
