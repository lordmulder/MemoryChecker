/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#define WIN32_LEAN_AND_MEAN 1

#include <Windows.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <process.h>
#include "terminal.h"

#define MAX_WCHARS 384U
#define MAX_U8CHAR (4U * MAX_WCHARS)

static volatile LONG reference_counter = 0L;
static CRITICAL_SECTION mutex;
static BOOL color_mode = FALSE, is_tty = FALSE;
static HANDLE handle = INVALID_HANDLE_VALUE;
static UINT default_cp = UINT_MAX;
static WORD default_attributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static char buffer_utf8[MAX_U8CHAR];
static wchar_t buffer_utf16[MAX_WCHARS];

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

#define BOOLIFY(X) (!(!(X)))

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
	case MSGTYPE_CYN:
		return FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
	case MSGTYPE_MAG:
		return FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
	case MSGTYPE_YLW:
		return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
	case MSGTYPE_RED:
		return FOREGROUND_RED | FOREGROUND_INTENSITY;
	case MSGTYPE_GRN:
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

static inline void print_utf8(const msgtype_t type, const char *const text)
{
	if (is_tty)
	{
		const BOOL has_color = color_mode;
		if (has_color) { SetConsoleTextAttribute(handle, (default_attributes & BACKGROUND_MASK) | get_text_color(type)); }
		write_to_term(handle, text);
		if (has_color) { SetConsoleTextAttribute(handle, default_attributes); }
	}
	else
	{
		write_to_file(handle, text);
	}
}

static inline void print_utf16(const msgtype_t type, const wchar_t *const text)
{
	const DWORD result = WideCharToMultiByte(CP_UTF8, 0U, text, -1, buffer_utf8, MAX_U8CHAR, NULL, NULL);
	if ((result > 0U) && (result <= MAX_U8CHAR))
	{
		print_utf8(type, buffer_utf8);
	}
}

/* ====================================================================== */
/* Public functions                                                       */
/* ====================================================================== */

void term_init(void)
{
	if (InterlockedIncrement(&reference_counter) == 1L)
	{
		if (!InitializeCriticalSectionAndSpinCount(&mutex, 0x00000400))
		{
			abort(); /*system error*/
		}
		if ((is_tty = (GetFileType(handle = GetStdHandle(STD_OUTPUT_HANDLE)) == FILE_TYPE_CHAR)))
		{
			default_cp = GetConsoleOutputCP();
			default_attributes = get_text_attributes(handle);
			SetConsoleOutputCP(CP_UTF8);
		}
	}
}

void term_enable_colors(const BOOL enable)
{
	EnterCriticalSection(&mutex);
	color_mode = BOOLIFY(enable);
	LeaveCriticalSection(&mutex);
}

void term_title_wset(const wchar_t *const text)
{
	SetConsoleTitleW(text);
}

void term_title_wsetf(const wchar_t *const format, ...)
{
	va_list ap;
	EnterCriticalSection(&mutex);
	va_start(ap, format);
	VSNWPRINTF(buffer_utf16, MAX_WCHARS, format, ap);
	va_end(ap);
	term_title_wset(buffer_utf16);
	LeaveCriticalSection(&mutex);
}

void term_puts(const msgtype_t type, const char *const text)
{
	EnterCriticalSection(&mutex);
	print_utf8(type, text);
	LeaveCriticalSection(&mutex);
}

void term_putws(const msgtype_t type, const wchar_t *const text)
{
	EnterCriticalSection(&mutex);
	print_utf16(type, text);
	LeaveCriticalSection(&mutex);
}

void term_printf(const msgtype_t type, const char *const format, ...)
{
	va_list ap;
	EnterCriticalSection(&mutex);
	va_start(ap, format);
	VSNPRINTF(buffer_utf8, MAX_U8CHAR, format, ap);
	va_end(ap);
	print_utf8(type, buffer_utf8);
	LeaveCriticalSection(&mutex);
}

void term_wprintf(const msgtype_t type, const wchar_t *const format, ...)
{
	va_list ap;
	EnterCriticalSection(&mutex);
	va_start(ap, format);
	VSNWPRINTF(buffer_utf16, MAX_WCHARS, format, ap);
	va_end(ap);
	print_utf16(type, buffer_utf16);
	LeaveCriticalSection(&mutex);
}

void dbg_puts(const char* const text)
{
	OutputDebugStringA(text);
}

void dbg_printf(const char* const format, ...)
{
	va_list ap;
	EnterCriticalSection(&mutex);
	va_start(ap, format);
	VSNPRINTF(buffer_utf8, MAX_U8CHAR, format, ap);
	va_end(ap);
	dbg_puts(buffer_utf8);
	LeaveCriticalSection(&mutex);
}

void term_exit(void)
{
	const LONG counter = InterlockedDecrement(&reference_counter);
	if (counter == 0L)
	{
		if (is_tty)
		{
			SetConsoleTextAttribute(handle, default_attributes);
			if (default_cp != UINT_MAX)
			{
				SetConsoleOutputCP(default_cp);
			}
		}
		handle = INVALID_HANDLE_VALUE;
		is_tty = FALSE;
		DeleteCriticalSection(&mutex);
	}
	else if (counter < 0L)
	{
		abort(); /*This is not supposed to happen!*/
	}
}
