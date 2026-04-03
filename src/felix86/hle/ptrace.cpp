#include "felix86/common/log.hpp"
#include "felix86/hle/ptrace.hpp"

std::string make_mq_name(int tracee_pid) {
    return "felix86-ptrace-" + std::to_string(tracee_pid);
}

void Ptrace::handle_event(siginfo_t* info) {
    // For TRACEME, it's the PID of the tracee
    // For ATTACH and SEIZE, it's the PID of the tracer
    const int pid = info->si_pid;
    const u64 value = (u64)info->si_value.sival_ptr;
    const int event = FELIX86_PTRACE_GET_EVENT(value);
    switch (event) {
    case felix86_PTRACE_TRACEME: {
        const std::string mq_name = make_mq_name(pid);
        break;
    }
    case felix86_PTRACE_ATTACH:
    case felix86_PTRACE_SEIZE: {
        // We'll just make the mq here and the child can join whenever
        const std::string mq_name = make_mq_name(pid);
        break;
    }
    default: {
        UNREACHABLE();
    }
    }
}