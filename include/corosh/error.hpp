#pragma once


#include <libssh/libssh.h>
#include <system_error>

namespace corosh
{

std::error_category & ssh_category();


}

inline std::error_code
make_error_code(ssh_error_types_e e) noexcept {
    return {
        static_cast<int>(e),
        corosh::ssh_category()
    };
}

template <>
struct std::is_error_code_enum<ssh_error_types_e> : true_type {};

