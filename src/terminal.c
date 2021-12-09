/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1
#define MAX_CHARS 384U
#define BUFFER_SIZE (4U * MAX_CHARS)

#include <Windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <process.h>
#include <io.h>
#include "terminal.h"

static volatile LONG reference_counter = 0L;
static CRITICAL_SECTION mutex;
static BOOL color_mode = TRUE;
static HANDLE handle = INVALID_HANDLE_VALUE;
static DWORD file_type = FILE_TYPE_UNKNOWN;
static WORD default_attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static UINT default_cp = UINT_MAX;
static char buffer_utf8[BUFFER_SIZE];
static wchar_t buffer_utf16[MAX_CHARS];

static const WORD BACKGROUND_MASK = BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED | BACKGROUND_INTENSITY;

/* ====================================================================== */
/* Helper macros                                                          */
/* ====================================================================== */

#define VSNPRINTF(BUFFER, COUNT, FORMAT, VA_LIST) do \
{ \
	_vsnprintf((BUFFER), (COUNT), (FORMAT), (VA_LIST)); \
	BUFFER[(COUNT) - 1U] = '\0'; \
} \
while(0)

#define VSNWPRINTF(BUFFER, COUNT, FORMAT, VA_LIST) do \
{ \
	_vsnwprintf((BUFFER), (COUNT), (FORMAT), (VA_LIST)); \
	BUFFER[(COUNT) - 1U] = '\0'; \
} \
while(0)

/* ====================================================================== */
/* Static functions                                                       */
/* ====================================================================== */

static inline WORD get_text_attributes(const HANDLE h)
{
	CONSOLE_SCREEN_BUFFER_INFO info;
	memset(&info, 0, sizeof(CONSOLE_SCREEN_BUFFER_INFO));
	if (GetConsoleScreenBufferInfo(h, &info))
	{
		return info.wAttributes;
	}
	return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
}

static inline WORD get_text_color(const msgtype_t type)
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

static inline void write_to_term(const HANDLE h, const char *const text)
{
	DWORD bytes_written;
	WriteConsoleA(h, text, (DWORD)strlen(text), &bytes_written, NULL);
}

static inline void write_to_file(const HANDLE h, const char *const text)
{
	DWORD bytes_written;
	WriteFile(h, text, (DWORD)strlen(text), &bytes_written, NULL);
}

static inline void send_utf8(const msgtype_t type, const char *const text)
{
	if (file_type == FILE_TYPE_CHAR)
	{
		if (color_mode)
		{
			SetConsoleTextAttribute(handle, (default_attributes & BACKGROUND_MASK) | get_text_color(type));
			write_to_term(handle, text);
			SetConsoleTextAttribute(handle, default_attributes);
		}
		else
		{
			write_to_term(handle, text);
		}
	}
	else
	{
		write_to_file(handle, text);
	}
}

static inline void send_utf16(const msgtype_t type, const wchar_t *const text)
{
	if (WideCharToMultiByte(CP_UTF8, 0U, text, -1, buffer_utf8, BUFFER_SIZE, NULL, NULL) > 0U)
	{
		send_utf8(type, buffer_utf8);
	}
}

/* ====================================================================== */
/* Public functions                                                       */
/* ====================================================================== */

void term_init(void)
{
	if (InterlockedIncrement(&reference_counter) == 1L)
	{
		InitializeCriticalSection(&mutex);
		if ((file_type = GetFileType(handle = GetStdHandle(STD_OUTPUT_HANDLE))) == FILE_TYPE_CHAR)
		{
			default_cp = GetConsoleOutputCP();
			default_attributes = get_text_attributes(handle);
			SetConsoleOutputCP(CP_UTF8);
		}
	}
}

void term_puts(const msgtype_t type, const char *const text)
{
	EnterCriticalSection(&mutex);
	send_utf8(type, text);
	LeaveCriticalSection(&mutex);
}

void term_putws(const msgtype_t type, const wchar_t *const text)
{
	EnterCriticalSection(&mutex);
	send_utf16(type, text);
	LeaveCriticalSection(&mutex);
}

void term_printf(const msgtype_t type, const char *const format, ...)
{
	EnterCriticalSection(&mutex);
	va_list ap;
	va_start(ap, format);
	VSNPRINTF(buffer_utf8, BUFFER_SIZE, format, ap);
	va_end(ap);
	send_utf8(type, buffer_utf8);
	LeaveCriticalSection(&mutex);
}

void term_wprintf(const msgtype_t type, const wchar_t *const format, ...)
{
	EnterCriticalSection(&mutex);
	va_list ap;
	va_start(ap, format);
	VSNWPRINTF(buffer_utf16, MAX_CHARS, format, ap);
	va_end(ap);
	send_utf16(type, buffer_utf16);
	LeaveCriticalSection(&mutex);
}

void term_exit(void)
{
	if (InterlockedDecrement(&reference_counter) == 0L)
	{
		if ((handle != INVALID_HANDLE_VALUE) && (file_type == FILE_TYPE_CHAR))
		{
			SetConsoleTextAttribute(handle, default_attributes);
			if (default_cp != UINT_MAX)
			{
				SetConsoleOutputCP(default_cp);
			}
		}
		handle = INVALID_HANDLE_VALUE;
		file_type = FILE_TYPE_UNKNOWN;
		DeleteCriticalSection(&mutex);
	}
}
