#pragma once
#include <chrono>

template <int MAX_PERIOD = 16>
struct rate_limiter
{
    int period_ = 0;

    template <typename TimePoint>
    auto wait(TimePoint deadline, size_t pktnum) -> void
    {
        if ((pktnum & ((1 << period_) - 1)) == 0) {
            auto spinning = false;
            while (std::chrono::steady_clock::now() < deadline)
            {
                spinning = true;
            }

            if (spinning) {
                if (period_ > 0) {
                    --period_;
                }
            } else {
                if (period_ < MAX_PERIOD) {
                    ++period_;
                }
            }
        }
    }
};