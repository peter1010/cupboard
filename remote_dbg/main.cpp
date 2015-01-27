/**
 * Print the program usage statement
 */
static void print_usage()
{
    fprintf(stderr, "Usage: [-v level] -p pid\n");
}

int main(int argc, char * argv[])
{
    static const struct option long_options[] =
    {
        {"help",     no_argument,       0, 'h'},
        {"verbose",  required_argument, 0, 'v'},
        {"pid",      required_argument, 0, 'p'},
        {NULL,       0,                 0, 0},
    };
    while(true)
    {
        int option_index;
        const int opt = getopt_long_only(
            argc,
            (char * const *)argv,
            "h",
            long_options,
            &option_index
        );
        if(opt == -1)
        {
            break;
        }
        switch(opt)
        {
            case 'h':
                help();
                break;

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

    return EXIT_SUCCESS;
}
