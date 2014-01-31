
DefaultEnvironment(CFLAGS="-Wall -O3 -Wextra")

Program("symbol2addr", ["symbols.c", "logging.c", "symbol2addr.c"])
Program("addr2symbol", ["symbols.c", "logging.c", "addr2symbol.c"])
Program("inject_puts", ["symbols.c", "logging.c", "inject_puts.c"])

Decider("MD5-timestamp")

