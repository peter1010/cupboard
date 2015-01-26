#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdbool.h>

/* If compiled using C++, use C linkage */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Some Logging code
 */

#define LOG_TIMESTAMP

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

#define _LOG_MSG(level, ...) \
    do { void * hnd = open_logger(level); \
         if(hnd) \
            log_msg(hnd, __VA_ARGS__); \
    } while(0)

#define _LOG_ERRNO(level, ...)\
    do { void * hnd = open_logger(level); \
         if(hnd) \
            log_errno(hnd, __VA_ARGS__); \
    } while(0)


/* Use these macros to log messages for different levels */
#define LOG_ERROR(...) _LOG_MSG(LOG_ERROR_LVL, __VA_ARGS__)
#define LOG_WARN(...)  _LOG_MSG(LOG_WARN_LVL,  __VA_ARGS__)
#define LOG_INFO(...)  _LOG_MSG(LOG_INFO_LVL,  __VA_ARGS__)
#define LOG_DEBUG(...) _LOG_MSG(LOG_DEBUG_LVL, __VA_ARGS__)

#define LOG_ERRNO_AS_ERROR(...) _LOG_ERRNO(LOG_ERROR_LVL, __VA_ARGS__)

extern void * open_logger(unsigned level);

extern void log_msg(
    void * hnd,
    const char * fmt,
    ...) __attribute__((format (printf, 2, 3)));


extern void log_errno(
    void * hnd,
    const char * fmt,
    ...) __attribute__((format (printf, 2, 3)));

/* If compiled using C++, use C linkage */
#ifdef __cplusplus
}
#endif

#endif
