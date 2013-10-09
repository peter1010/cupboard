#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "logging.h"
#include "symbols.h"

INIT_LOGGING;

void end()
{
    FINI_LOGGING;
}

int main(int argc, const char * argv[])
{
    atexit(end);

    if(argc < 3)
    {
        ERROR_MSG("Incorrect number of arguments");
        return 1;
    }
    pid_t tgt_pid;

    char * endp;
    tgt_pid = strtol(argv[1], &endp, 10);
    if(*endp != '\0')
    {
        ERROR_MSG("Invalid PID '%s' for first argument", argv[1]);
        return 1;
    }

    void * ptr = find_addr_of_symbol(tgt_pid, NULL, argv[2]);
    printf("%s = %p\n", argv[2], ptr);
}
