#include <atomic>
#include <iostream>

#include "hdr/options.hpp"

std::atomic_bool sig_shutdown;

void sighandler(int)
{
    sig_shutdown.store(true, std::memory_order_relaxed);
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