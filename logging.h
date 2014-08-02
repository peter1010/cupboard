#ifndef _LOGGING_H_
#define _LOGGING_H_

/**
 * Some Logging code
 */

/**
 * Logging levels
 */
enum Log_Level_enum
{
    LOG_ERROR_LVL,
    LOG_WARN_LVL,
    LOG_INFO_LVL,
    LOG_DEBUG_LVL
};

extern void set_logging_level(unsigned level);

#ifdef __BASE_FILE__
static const char log_category[] = __BASE_FILE__;
#else
/* Place this macro at top of all files that using logging */
#define SET_LOG_CATEGORY static const char log_category[] = __FILE__
#endif

/* Use these macros to log messages for different levels */
#define LOG_ERROR(...) log_msg(log_category, __LINE__, LOG_ERROR_LVL, __VA_ARGS__)
#define LOG_WARN(...)  log_msg(log_category, __LINE__, LOG_WARN_LVL,  __VA_ARGS__)
#define LOG_INFO(...)  log_msg(log_category, __LINE__, LOG_INFO_LVL,  __VA_ARGS__)
#define LOG_DEBUG(...) log_msg(log_category, __LINE__, LOG_DEBUG_LVL, __VA_ARGS__)

/* Append additional info to previous log message */
#define LOG_APPEND(...) log_msg_append(__VA_ARGS__)

extern void log_msg(
    const char * category,
    int line,
    unsigned level,
    const char * fmt,
    ...) __attribute__((format (printf, 4, 5)));

extern void log_msg_append(
    const char * fmt,
    ...) __attribute__((format (printf, 1, 2)));

#endif
