#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "logging.h"
#include "symbols.h"

static void print_usage()
{
    fprintf(stderr, "Usage: [-v level] -p pid symbol_name\n");
}

int main(int argc, char * const argv[])
{
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

    Sym2Addr sym(argv[optind]);

    find_addr_of_symbol(tgt_pid, NULL, &sym);

    sym.print(tgt_pid);
    return EXIT_SUCCESS;
}
