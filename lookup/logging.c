#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logging.h"

#ifdef LOG_TIMESTAMP
#    include <time.h>
#endif



static unsigned log_level = LOG_WARN_LVL;
FILE * log_out = NULL;

struct Logger_s
{
#ifdef LOG_TIMESTAMP
    struct timespec ts;
#endif
};

typedef struct Logger_s Logger_t;

Logger_t log_info;


/**
 * Initialiser the logger by opening the output stream
 */
void log_init()
{
    if(!log_out)
    {
        log_out = stderr;
    }
}


/**
 * Set logging level
 *
 * @param[in] level, the level to set
 */
void set_logging_level(unsigned level)
{
    log_level = level;
}


/**
 * Open the logger, called before each log call, it also tests if we want to
 * log. If logging, then the initial message prefix is sent.
 *
 * @param[in] level
 *
 * @return True if log, false if not
 */
void * open_logger(unsigned level)
{
    if(level <= log_level)
    {
#ifdef LOG_TIMESTAMP
        clock_gettime(CLOCK_MONOTONIC, &log_info.ts);
#endif
        log_init();
        return (void *) &log_info;
    }
    else
    {
        return 0;
    }
}


/**
 * Log a message
 *
 * @param[in] hnd The handle to the logger
 * @param[in] fmt The format string in the style of printf
 * @param[in] args Variable args
 */
void log_msg(void * hnd, const char * fmt, ...)
{
    Logger_t * info = (Logger_t *)hnd;
    va_list ap;
    va_start(ap, fmt);

#ifdef LOG_TIMESTAMP
    fprintf(log_out, "%u.%03li ",
        (unsigned)info->ts.tv_sec,
        info->ts.tv_nsec/1000000
    );
#endif
    vfprintf(log_out, fmt, ap);
    fputs("\n", log_out);

    va_end(ap);
}


/**
 * Log a message with errno included
 *
 * @param[in] hnd The handle to the logger
 * @param[in] fmt The format string in the style of printf
 * @param[in] args Variable args
 */
void log_errno(void * hnd, const char * fmt, ...)
{
    Logger_t * info = (Logger_t *)hnd;
    va_list ap;
    va_start(ap, fmt);

#ifdef LOG_TIMESTAMP
    fprintf(log_out, "%u.%03li ",
        (unsigned)info->ts.tv_sec,
        info->ts.tv_nsec/1000000
    );
#endif
    vfprintf(log_out, fmt, ap);
    fputs(":", log_out);
    fputs(strerror(errno), log_out);
    fputs("\n", log_out);

    va_end(ap);
}

