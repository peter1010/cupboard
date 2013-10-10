#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logging.h"
#include "symbols.h"

INIT_LOGGING;

void end()
{
    FINI_LOGGING;
}

static void print_usage()
{
    fprintf(stderr, "Usage: [-v level] -p pid address\n");
}

int main(int argc, char * const argv[])
{
    atexit(end);

    pid_t tgt_pid = -1;
    int opt;
    while((opt = getopt(argc, argv, "v:p:")) != -1)
    {
        switch(opt)
        {
            case 'v':
                set_logging_level(atoi(optarg));
                break;

            case 'p':
                tgt_pid = atoi(optarg);
                break;

            default:
                print_usage();
                return EXIT_FAILURE;
                break;
        }
    }


    if((optind >= argc) || (tgt_pid < 0))
    {
        print_usage();
        return EXIT_FAILURE;
    }
    void * addr = (void *) atoi(argv[optind]);

    char * sym_name = find_closest_symbol(tgt_pid, addr);
    printf("In process %i; %p is close to %s\n", tgt_pid, addr, sym_name);
    return EXIT_SUCCESS;
}
