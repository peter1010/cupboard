#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>

#include "logging.h"
#include "symbols.h"

void write_proc_mem(pid_t pid, MemPtr_t addr, const unsigned char * buf, size_t buf_len)
{
    const size_t word_width = sizeof(unsigned long);
    for(;buf_len >= word_width; buf_len -= word_width)
    {
        ptrace(PTRACE_POKETEXT, pid, addr, *((unsigned long *)buf));
        addr += word_width;
        buf += word_width;
    }
    if(buf_len > 0)
    {
        unsigned long mask = 0;
        unsigned long value = 0;
        unsigned i;
        for(i = 0; i < word_width; i++, buf++)
        {
            if(buf_len > 0)
            {
                value |= (((unsigned long)*buf) << (8*i));
                buf_len--;
            }
            else
            {
                mask |= (0xffUL << (8*i));
            }
        }
        value = value | (mask & ((unsigned long)ptrace(PTRACE_PEEKTEXT, pid, addr, 0)));
        ptrace(PTRACE_POKETEXT, pid, addr, value);
    }
}


/* Must save EAX, ECX and EDX onto the stack before the call */
/* 1/ Move the stack pointer to make room for shell code and library name */
/* 2/ push saved esp, eax, ecx, edx and esp onto the stack */
/* 3/ push dlopen args onto stack */
/* 4/ push address to the pop, pop sequence */
/* 5/ push address of dlopen */
/* 4/ Push mprotect params onto stack */
/* 3/ Push return address from mprotect (i.e. pointer to move esp, ret) */

unsigned char shell_code1[] =
{
    /* mprotect has three arguments */
    0x83, 0xC4, 0x0C,  /* add $0xC, esp;  move stack pointer to reveal puts parameter */
    0xC3,              /* ret;            call puts */
};

unsigned char shell_code2[] =
{
    /* puts has one argument */
    0x83, 0xC4, 0x04,  /* add $0x4, esp;  move stack pointer to reveal save parameters */
    0x58,              /* pop %eax */
    0x59,              /* pop %ecx */
    0x5a,              /* pop %edx */
    0x9d,              /* popf */
    0xc3,              /* ret */
};

void print_as_x86_regs(struct user_regs_struct * regs)
{
    INFO_MSG("eax = %08lx, ebx = %08lx, ecx = %08lx, edx = %08x", regs->eax, regs->ebx, regs->ecx, regs->edx);
    INFO_MSG("edi = %08lx, esi = %08lx", regs->edi, regs->esi);
    INFO_MSG("eip = %08lx, ebp = %08lx, esp = %08lx", regs->eip, regs->ebp, regs->esp);
}

void get_regs(pid_t pid, void * regs, size_t reg_size)
{
    if(ptrace(PTRACE_GETREGS, pid, 0, regs) != 0)
    {
        ERROR_MSG("PTRACE_GETREGS failed");
    }
    print_as_x86_regs(regs);
}

void set_regs(pid_t pid, void * regs, size_t reg_size)
{
    if(ptrace(PTRACE_SETREGS, pid, 0, regs) != 0)
    {
        ERROR_MSG("PTRACE_SETREGS failed");
    }

//    INFO_MSG("eax = %08lx, ebx = %08lx, ecx = %08lx, edx = %08x", regs.eax, regs.ebx, regs.ecx, regs.edx);
//    INFO_MSG("edi = %08lx, esi = %08lx", regs.edi, regs.esi);
//    INFO_MSG("eip = %08lx, ebp = %08lx, esp = %08lx", regs.eip, regs.ebp, regs.esp);
}

void trace_stack_trend(pid_t pid)
{
    unsigned long step = 0;
    unsigned long stack_pointer = 0;

    INFO_MSG("Single stepping through the code");
    for(;step < 10000; step++)
    {
        int status;
        struct user_regs_struct regs;
        if(ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        {
            ERROR_MSG("PTRACE_GETREGS failed");
            return;
        }
        if(stack_pointer != (unsigned long) regs.esp)
        {
            struct Addr2Sym_s lookup;
            lookup.value = regs.eip;
            set_logging_level(0);
            find_closest_symbol(pid, &lookup);
            set_logging_level(5);

            unsigned long esp_contents =ptrace(PTRACE_PEEKTEXT, pid, regs.esp, 0);
            unsigned long eip_contents =ptrace(PTRACE_PEEKTEXT, pid, regs.eip, 0);

            INFO_MSG("[%u] EIP=%08x (*%08x) ESP=%08x (*%08x) {%s}", step, 
                                                     (unsigned long) regs.eip, eip_contents,
                                                     (unsigned long) regs.esp, esp_contents, lookup.name);
            stack_pointer = regs.esp;

        }
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        pid_t sig_pid = waitpid(-1, &status, __WALL);
    }
    INFO_MSG("Finished single stepping through the code");
}
 
void push(pid_t pid, MemPtr_t * pStack_pointer, unsigned long value)
{
    unsigned long * sp = (unsigned long *) *pStack_pointer;
    sp--;
    ptrace(PTRACE_POKETEXT, pid, sp, value);
    DEBUG_MSG("Pushing %08lx at %p", value, sp);
    *pStack_pointer = (MemPtr_t) sp;
}


int main(int argc, const char * argv[])
{
    set_logging_level(0);

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
    const char * string = argv[2];

    Sym2Addr_t sym;
    sym.name = "mprotect";

    find_addr_of_symbol(tgt_pid, NULL, &sym);
    int i;
    for(i = 0; i < sym.cnt; i++)
    {
        printf("In process %i; %s = %p\n", tgt_pid, sym.name, sym.values[i]);
    }
    MemPtr_t addr_mprotect = sym.values[0];

    sym.name = "puts";
    find_addr_of_symbol(tgt_pid, NULL, &sym);

    for(i = 0; i < sym.cnt; i++)
    {
        printf("In process %i; %s = %p\n", tgt_pid, sym.name, sym.values[i]);
    }
    MemPtr_t addr_puts = sym.values[0];

    set_logging_level(5);
    // Attach 
    if(ptrace(PTRACE_ATTACH, tgt_pid, 0, 0) < 0) 
    {
	ERROR_MSG("cannot attach to %d, error!", tgt_pid);
        perror("");
	exit(1);
    }
    int status;
    pid_t sig_pid = waitpid(-1, &status, __WALL);
    DEBUG_MSG("waitpid, pid=%i status=%i %i %i", sig_pid, status, WIFSTOPPED(status), WSTOPSIG(status));
	
    struct user_regs_struct regs;
    get_regs(tgt_pid, &regs, sizeof(regs));

/* push saved EIP on the stack */
    MemPtr_t stack_pointer = (MemPtr_t)regs.esp;
    push(tgt_pid, &stack_pointer, regs.eip);
    regs.esp = stack_pointer;

    unsigned long size = sizeof(shell_code1) + sizeof(shell_code2) + strlen(string) + 1;

    MemPtr_t addr_shell_code1 = stack_pointer - size;
    MemPtr_t addr_shell_code2 = addr_shell_code1 + sizeof(shell_code1);
    MemPtr_t addr_string = addr_shell_code2 + sizeof(shell_code2);
    MemPtr_t addr_page = (MemPtr_t) ((unsigned long)addr_shell_code1 & ~0xFFF);

/* 1/ Move the stack pointer to make room for shell code and library name */
    stack_pointer =- (size + sizeof(MemPtr_t));

    write_proc_mem(tgt_pid, addr_shell_code1, shell_code1, sizeof(shell_code1));
    
    write_proc_mem(tgt_pid, addr_shell_code2, shell_code2, sizeof(shell_code2));
    
    write_proc_mem(tgt_pid, addr_string, (const unsigned char *)string, (size_t)(strlen(string)+1));

/* push saved eax, ecx, edx, eflags and esp onto the stack, note when esp is popped stack
 * then points to saved eip */
    push(tgt_pid, &stack_pointer, regs.esp);
    push(tgt_pid, &stack_pointer, regs.eflags);
    push(tgt_pid, &stack_pointer, regs.edx);
    push(tgt_pid, &stack_pointer, regs.ecx);
    push(tgt_pid, &stack_pointer, regs.eax);

    
/* push puts() args onto the stack */
    push(tgt_pid, &stack_pointer, (unsigned long) addr_string);

    push(tgt_pid, &stack_pointer, (unsigned long) addr_shell_code2);
    push(tgt_pid, &stack_pointer, (unsigned long) addr_puts);

/* Push mprotect params onto stack */
    push(tgt_pid, &stack_pointer, PROT_WRITE | PROT_READ | PROT_EXEC);
    push(tgt_pid, &stack_pointer, 0x1000);
    push(tgt_pid, &stack_pointer, (unsigned long) addr_page);
    push(tgt_pid, &stack_pointer, (unsigned long) addr_shell_code1);

    regs.esp = (unsigned int) stack_pointer;
    regs.eip = (unsigned int) addr_mprotect;

    set_regs(tgt_pid, &regs, sizeof(regs));

    trace_stack_trend(tgt_pid);

    ptrace(PTRACE_DETACH, tgt_pid, 0, 0);
    return EXIT_SUCCESS;
}
