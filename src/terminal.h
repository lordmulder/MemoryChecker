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
	MSGTYPE_NFO = 0,
	MSGTYPE_HDR = 1,
	MSGTYPE_PRG = 2,
	MSGTYPE_WRN = 4,
	MSGTYPE_ERR = 8,
	MSGTYPE_FIN = 16
}
msgtype_t;

void term_init(void);
void term_exit(void);

void term_puts(const msgtype_t type, const char *const text);
void term_printf(const msgtype_t type, const char *const format, ...);

void term_putws(const msgtype_t type, const wchar_t *const text);
void term_wprintf(const msgtype_t type, const wchar_t *const format, ...);

#endif
