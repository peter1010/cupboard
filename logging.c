#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include "logging.h"

static unsigned log_level = LOG_WARN_LVL;
static bool log_append_allowed = false;
static FILE * log_out = NULL;


void log_init()
{
    if(!log_out)
    {
        log_out = stderr;
    }
}

void set_logging_level(unsigned level)
{
    log_level = level;
}

/**
 * Logging function
 *
 * @param[in] filename Name of file that log was called from
 * @param[in] line Line number where log called from
 * @param[in] level The level
 * @param[in] fmt The format string in the style of printf
 * @param[in] args Variable args
 */
void log_msg(const char * category, int line, unsigned level, const char * fmt, ...)
{
    if(level <= log_level)
    {
        log_init();

        va_list ap;
        va_start(ap, fmt);

        fprintf(log_out, "[%s:%i] ", category, line);
        vfprintf(log_out, fmt, ap);
        fputs("\n", log_out);

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

        fprintf(log_out, "\t");
        vfprintf(log_out, fmt, ap);
        fputs("\n", log_out);

        va_end(ap);
    }
}
