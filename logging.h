#ifndef _LOGGING_H_
#define _LOGGING_H_

/**
 * Some Logging code
 */

enum Log_Level_enum
{
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
};

extern void set_logging_level(int level);

static const char src_filename[] = __BASE_FILE__;

#define FINI_LOGGING log_fini()

#define ERROR_MSG(...) log_msg(src_filename, __LINE__, LOG_ERROR, __VA_ARGS__)
#define WARN_MSG(...)  log_msg(src_filename, __LINE__, LOG_WARN,  __VA_ARGS__)
#define INFO_MSG(...)  log_msg(src_filename, __LINE__, LOG_INFO,  __VA_ARGS__)
#define DEBUG_MSG(...) log_msg(src_filename, __LINE__, LOG_DEBUG, __VA_ARGS__)

#define DEBUG_MSG_APPEND(...) log_msg_append(__VA_ARGS__)

extern void log_msg(const char * filename, int line, unsigned level, const char * fmt, ...)
    __attribute__((format (printf, 4, 5)));

extern void log_msg_append(const char * fmt, ...) __attribute__((format (printf, 1, 2)));

extern void log_fini();

#endif
