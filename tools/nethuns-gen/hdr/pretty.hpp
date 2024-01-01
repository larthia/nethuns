#pragma once
#include <string>
#include <sstream>

namespace detail {
    template <typename T>
    std::string stringify(std::ostringstream &out, T &&arg)
    {
        out << std::move(arg);
        return out.str();
    }
    template <typename T, typename ...Ts>
    std::string stringify(std::ostringstream &out, T &&arg, Ts&&... args)
    {
        out << std::move(arg);
        return stringify(out, std::forward<Ts>(args)...);
    }
}

template <typename ...Ts>
inline std::string
stringify(Ts&& ... args)
{
    std::ostringstream out;
    return detail::stringify(out, std::forward<Ts>(args)...);
}

template <typename T>
inline std::string
pretty_number(T value)
{
    if (value < 1000000000) {
    if (value < 1000000) {
    if (value < 1000) {
         return stringify(value);
    }
    else return stringify(value/1000, "_K");
    }
    else return stringify(value/1000000, "_M");
    }
    else return stringify(value/1000000000, "_G");
}
