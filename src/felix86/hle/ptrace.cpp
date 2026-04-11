#include "felix86/common/log.hpp"
#include "felix86/common/state.hpp"
#include "felix86/hle/fd.hpp"
#include "felix86/hle/ptrace.hpp"

pid_t g_tracer_pid = -1;
bool g_is_tracer = false;

void make_mq_name(char* buffer, pid_t from, pid_t to) {
    // Use snprintf so it's async-signal-safe
    // snprintf won't use malloc here
    ASSERT(snprintf(buffer, 256, "/felix86-ptrace-%d-%d", from, to) > 0);
}

std::pair<mqd_t, mqd_t> Ptrace::create_ptrace_mqs(pid_t tracer_pid, pid_t tracee_pid) {
    char buffer1[256];
    char buffer2[256];
    make_mq_name(buffer1, tracer_pid, tracee_pid);
    make_mq_name(buffer2, tracee_pid, tracer_pid);
    struct mq_attr attr = {};
    attr.mq_maxmsg = 1;
    attr.mq_msgsize = 4096;
    mqd_t mq1 = mq_open(buffer1, O_CREAT, 0666, &attr);
    mqd_t mq2 = mq_open(buffer2, O_CREAT, 0666, &attr);
    ASSERT(mq1 >= 0);
    ASSERT(mq2 >= 0);
    return std::make_pair(mq1, mq2);
}

std::pair<mqd_t, mqd_t> get_ptrace_mqs(pid_t tracer_pid, pid_t tracee_pid) {
    char buffer1[256];
    char buffer2[256];
    make_mq_name(buffer1, tracer_pid, tracee_pid);
    make_mq_name(buffer2, tracee_pid, tracer_pid);
    mqd_t mq1 = mq_open(buffer1, 0);
    mqd_t mq2 = mq_open(buffer2, 0);
    ASSERT(mq1 >= 0);
    ASSERT(mq2 >= 0);
    return std::make_pair(mq1, mq2);
}

void close_ptrace_mqs(std::pair<mqd_t, mqd_t> mqs) {
    ASSERT(mq_close(mqs.first) == 0);
    ASSERT(mq_close(mqs.second) == 0);
}

void Ptrace::unlink_ptrace_mqs() {
    if (g_tracer_pid != -1) {
        pid_t tracer_pid = g_tracer_pid;
        pid_t tracee_pid = gettid();
        char buffer1[256];
        char buffer2[256];
        make_mq_name(buffer1, tracer_pid, tracee_pid);
        make_mq_name(buffer2, tracee_pid, tracer_pid);
        ASSERT(mq_unlink(buffer1) == 0);
        ASSERT(mq_unlink(buffer2) == 0);
    }
}

bool Ptrace::handle_event(siginfo_t* info) {
    // ATTACH and SEIZE can happen at any time, even if the tracee is waiting on a syscall
    // For this reason we deliver them via signal. To verify the signal was because of a ptrace command,
    // we check that the ptrace message queue was already created
    // For TRACEME, the tracee will create the message queue when it runs the ptrace syscall
    const pid_t pid = info->si_pid;
    const int event = (u64)info->si_value.sival_int;
    switch (event) {
    case felix86_PTRACE_TRACEME: {
        // This event is sent by the tracee to the tracer to notify it that it is now a tracer
        // This needs to be done because a tracer acts differently on wait4 syscalls, it will check
        // if the pid it is waiting on has a ptrace message queue and act accordingly
        g_is_tracer = true;
        return true;
    }
    case felix86_PTRACE_ATTACH:
    case felix86_PTRACE_SEIZE: {
        // The tracer should've made us the message queues, ensure that they exist
        std::pair<mqd_t, mqd_t> mqs = get_ptrace_mqs(pid, gettid());
        if (mqs.first >= 0 && mqs.second >= 0) {
            g_tracer_pid = pid;
            close_ptrace_mqs(mqs);
            return true;
        } else {
            return false;
        }
    }
    default: {
        return false;
    }
    }
}

void Ptrace::enter_stop(ThreadState* state) {
    // This function is called from inside a syscall (for syscall-enter-stop),
    // inside a signal (for signal-delivery-stop), or other similar stops, herein referred to as "stops"
    // The signal-delivery-stop happens during a safepoint. At that time, we are inside a host
    // signal handler, but it is still safe to make calls to stuff like malloc, because that signal
    // happened during a safepoint. At safepoints, we are inside JIT code, so there's no locked locks or anything
    // that would make it unsafe.
    if (g_tracer_pid == -1) {
        // Is not being traced, just return
        return;
    }

    auto mqs = get_ptrace_mqs(g_tracer_pid, gettid());
    mqd_t write_mq = mqs.second;
    mqd_t read_mq = mqs.first;

    // When a process enters a stop, it won't continue until it is allowed to by its tracer
    // So here we need to notify the tracer we entered a stop and wait for orders
    // The tracer will know that we entered a stop when it does waitpid
    mq_attr write_attr, read_attr;
    int result = mq_getattr(write_mq, &write_attr);
    ASSERT(result == 0);
    ASSERT(write_attr.mq_curmsgs == 0);
    result = mq_getattr(read_mq, &read_attr);
    ASSERT(result == 0);
    ASSERT(read_attr.mq_curmsgs == 0);
}