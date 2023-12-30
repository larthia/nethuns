#pragma once

#include <pthread.h>
#include <sched.h>

#ifdef __APPLE__
#include <sys/types.h> // this header cannot be included in C++ apps
#include <sys/sysctl.h>
#include <mach/mach_init.h>
#include <mach/thread_act.h>
#endif

#include <stdexcept>

namespace this_thread {

#if defined (__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    static inline void
    affinity(int core)
    {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset); CPU_SET(core, &cpuset);

        pthread_t pth = pthread_self();
        if ( ::pthread_setaffinity_np(pth, sizeof(cpuset), &cpuset) != 0)
            throw std::runtime_error("this_thread::affinity: pthread_setaffinity_np error on core " + std::to_string(core));
    }

#elif defined(__APPLE__)

    [[maybe_unused]] static inline void
    affinity(int core)
    {
        thread_port_t mach_thread;
        thread_affinity_policy_data_t policy = { core };
        mach_thread = pthread_mach_thread_np(pthread_self());
        if (thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, 1) != 0)
            throw std::runtime_error("this_thread::affinity: thread_policy_set");

        policy.affinity_tag = -1;

        mach_msg_type_number_t policy_count = THREAD_AFFINITY_POLICY_COUNT;
        boolean_t get_default = false;

        if (thread_policy_get(mach_thread, THREAD_AFFINITY_POLICY, (thread_policy_t)&policy, &policy_count, &get_default) != 0)
            throw std::runtime_error("this_thread::affinity: thread_policy_get");

        if (static_cast<int>(policy.affinity_tag) != core)
            throw std::runtime_error("this_thread::affinity: couldn't set thread affinity");
    }

#else

    static inline void
    affinity(int core)
    {
        throw std::runtime_error("this_thread::affinity: not supported on this platform");
    }

#endif

}