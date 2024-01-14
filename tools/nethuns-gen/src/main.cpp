#include <atomic>
#include <iostream>

#include "hdr/options.hpp"

std::atomic_int sig_shutdown;

void sighandler(int)
{
    auto v = sig_shutdown.fetch_add(1, std::memory_order_relaxed);
    if (v < 2) {
        std::cerr << " received, graceful down..." << std::endl;
    } else  {
        std::cerr << "EXIT!" << std::endl;
        std::exit(1);
    }
}

int main(int argc, char** argv)
try
{
    auto opt = parse_opt(argc, argv);
    signal(SIGINT, sighandler);
    signal(SIGSTOP, sighandler);

    validate_options(opt);

    return run(opt);
}
catch (std::exception& e)
{
    std::cerr  << e.what() << std::endl;
    return 1;
}
catch (...)
{
    std::cerr  << "unknow error!" << std::endl;
    return 1;
}