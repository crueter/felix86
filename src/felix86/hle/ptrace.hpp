#include <csignal>
#include <sys/ptrace.h>
#include <sys/types.h>
#include "felix86/common/types.hpp"

#define FELIX86_PTRACE_SIGNAL 53

// sigqueue is used to send a 64-bit number to the parent (in the case of traceme) or tracee (in the case of attach and seize)
// to inform them that they are now tracing/being traced (that is, TRACEME, ATTACH and SEIZE only are sent through signals)
// Signals are used for this because it needs to happen asynchronously and at any time. For example, the parent or tracee may be blocked
// in kernel-space, but they need to be informed immediately regardless
// Other ptrace commands, such as PTRACE_PEEKDATA, only happen when the tracee is in a stop state, so we can use a different mechanism
// to transfer the information, message queues
#define FELIX86_PTRACE_GET_EVENT(x) (x & 0xFFFF)

// Copied from x86 ptrace.h file as there's differences with RISC-V
enum {
    felix86_PTRACE_TRACEME = 0,
    felix86_PTRACE_PEEKTEXT = 1,
    felix86_PTRACE_PEEKDATA = 2,
    felix86_PTRACE_PEEKUSER = 3,
    felix86_PTRACE_POKETEXT = 4,
    felix86_PTRACE_POKEDATA = 5,
    felix86_PTRACE_POKEUSER = 6,
    felix86_PTRACE_CONT = 7,
    felix86_PTRACE_KILL = 8,
    felix86_PTRACE_SINGLESTEP = 9,
    felix86_PTRACE_GETREGS = 12,
    felix86_PTRACE_SETREGS = 13,
    felix86_PTRACE_GETFPREGS = 14,
    felix86_PTRACE_SETFPREGS = 15,
    felix86_PTRACE_ATTACH = 16,
    felix86_PTRACE_DETACH = 17,
    felix86_PTRACE_GETFPXREGS = 18,
    felix86_PTRACE_SETFPXREGS = 19,
    felix86_PTRACE_SYSCALL = 24,
    felix86_PTRACE_GET_THREAD_AREA = 25,
    felix86_PTRACE_SET_THREAD_AREA = 26,
    felix86_PTRACE_ARCH_PRCTL = 30,
    felix86_PTRACE_SYSEMU = 31,
    felix86_PTRACE_SYSEMU_SINGLESTEP = 32,
    felix86_PTRACE_SINGLEBLOCK = 33,
    felix86_PTRACE_SETOPTIONS = 0x4200,
    felix86_PTRACE_GETEVENTMSG = 0x4201,
    felix86_PTRACE_GETSIGINFO = 0x4202,
    felix86_PTRACE_SETSIGINFO = 0x4203,
    felix86_PTRACE_GETREGSET = 0x4204,
    felix86_PTRACE_SETREGSET = 0x4205,
    felix86_PTRACE_SEIZE = 0x4206,
    felix86_PTRACE_INTERRUPT = 0x4207,
    felix86_PTRACE_LISTEN = 0x4208,
    felix86_PTRACE_PEEKSIGINFO = 0x4209,
    felix86_PTRACE_GETSIGMASK = 0x420a,
    felix86_PTRACE_SETSIGMASK = 0x420b,
    felix86_PTRACE_SECCOMP_GET_FILTER = 0x420c,
    felix86_PTRACE_SECCOMP_GET_METADATA = 0x420d,
    felix86_PTRACE_GET_SYSCALL_INFO = 0x420e,
    felix86_PTRACE_GET_RSEQ_CONFIGURATION = 0x420f,
    felix86_PTRACE_SET_SYSCALL_USER_DISPATCH_CONFIG = 0x4210,
    felix86_PTRACE_GET_SYSCALL_USER_DISPATCH_CONFIG = 0x4211
};

struct Ptrace {
    static u64 request(enum __ptrace_request op, pid_t pid, void* addr, void* data);

    static void handle_event(siginfo_t* info);

    static void traceme();
};