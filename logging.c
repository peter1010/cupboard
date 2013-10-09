#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include "logging.h"

static int log_level = LOG_WARN;
static bool log_append_allowed = false;

/**
 * Logging function
 *
 * @param[in] filename Name of file that log was called from
 * @param[in] line Line number where log called from
 * @param[in] level The level
 * @param[in] fmt The format string in the style of printf
 * @param[in] args Variable args
 */
void log_msg(const char * filename, int line, unsigned level, const char * fmt, ...)
{
    if(level <= log_level)
    {
        va_list ap;
        va_start(ap, fmt);

        fprintf(stderr, "\n[%s:%i] ", filename, line);
        vfprintf(stderr, fmt, ap);

        va_end(ap);
        log_append_allowed = true;
    }
    else
    {
        log_append_allowed = false;
    }
}

void log_msg_append(const char * fmt, ...)
{
    if(log_append_allowed)
    {
        va_list ap;
        va_start(ap, fmt);

        vfprintf(stderr, fmt, ap);

        va_end(ap);
    }
}

