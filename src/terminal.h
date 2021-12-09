/******************************************************************************/
/* Memory Checker, by LoRd_MuldeR <MuldeR2@GMX.de>                            */
/* This work has been released under the CC0 1.0 Universal license!           */
/******************************************************************************/

#ifndef INC_TERMINAL_H
#define INC_TERMINAL_H

#ifndef _WINDOWS_
#error Must include <Windows.h> before including this header!
#endif

typedef enum
{
	MSGTYPE_WHT = 0x01,   /*white*/
	MSGTYPE_CYN = 0x02,   /*cyan*/
	MSGTYPE_MAG = 0x04,   /*magenta*/
	MSGTYPE_YLW = 0x08,   /*yekkiw*/
	MSGTYPE_RED = 0x10,   /*red*/
	MSGTYPE_GRN = 0x20    /*green*/
}
msgtype_t;

void term_init(void);
void term_exit(void);

void term_title_wset(const wchar_t *const text);
void term_title_wsetf(const wchar_t *const format, ...);

void term_enable_colors(const BOOL enable);

void term_puts(const msgtype_t type, const char *const text);
void term_printf(const msgtype_t type, const char *const format, ...);

void term_putws(const msgtype_t type, const wchar_t *const text);
void term_wprintf(const msgtype_t type, const wchar_t *const format, ...);

void dbg_puts(const char* const text);
void dbg_printf(const char* const format, ...);

#endif
