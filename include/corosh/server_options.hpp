#pragma once

#include <libssh/libssh.h>
#include <libssh/server.h>

namespace corosh::server_options
{

template<ssh_bind_options_e Option>
struct cstring_option
{
  constexpr static ssh_bind_options_e option() {return Option; }

  cstring_option(const char * value = "") : value_(value) {}
  cstring_option& operator=(const char * value)
  {
    value_ = value;
    return *this;
  }

  const void * data() const noexcept
  {
    return value_;
  }

  const char * value() const noexcept
  {
      return value_;
  }

 private:
  const char * value_;
};


template<ssh_bind_options_e Option, typename Int>
struct integral_option
{
  constexpr static ssh_bind_options_e option() {return Option; }

  integral_option(Int value) : value_(value) {}
  integral_option& operator=(Int value)
  {
    value_ = value;
    return *this;
  }
  const void * data() const noexcept
  {
    return &value_;
  }

  void * data() noexcept
  {
    return &value_;
  }

  Int value() const noexcept
  {
      return value_;
  }

 private:
  Int value_;
};

template<ssh_bind_options_e Option>
using unsigned_int_option = integral_option<Option, unsigned int>;


template<ssh_bind_options_e Option>
using int_option = integral_option<Option, int>;

template<ssh_bind_options_e Option>
using long_option = integral_option<Option, long>;


template<ssh_bind_options_e Option>
struct bool_option
{
  constexpr static ssh_bind_options_e option() {return Option; }

  bool_option(bool value) : value_(value ? 1 : 0) {}
  bool_option& operator=(bool value)
  {
    value_ = value ? 1 : 0;
    return *this;
  }
  const void * data() const noexcept
  {
    return &value_;
  }

  void * data() noexcept
  {
    return &value_;
  }

  bool value() const noexcept
  {
      return value_ != 0;
  }

 private:
  int value_;
};


template<ssh_bind_options_e Option>
struct key_option
{
  constexpr static ssh_bind_options_e option() {return Option; }

  key_option(ssh_key value) : value_(value) {}
  key_option& operator=(ssh_key value)
  {
    value_ = value;
    return *this;
  }

  const void * data() const noexcept
  {
    return value_;
  }

  ssh_key value() const noexcept
  {
      return value_;
  }

 private:
  ssh_key value_;
};


using bind_addr     = cstring_option<SSH_BIND_OPTIONS_BINDADDR>;
using bind_port     = unsigned_int_option<SSH_BIND_OPTIONS_BINDPORT>;
using bind_port_str = cstring_option<SSH_BIND_OPTIONS_BINDPORT_STR>;
using host_key      = cstring_option<SSH_BIND_OPTIONS_HOSTKEY>;

// Deprecated host-key-type setters kept for completeness. Prefer host_key /
// import_key / import_key_str. libssh treats these as no-ops on modern builds.
using dsa_key       = cstring_option<SSH_BIND_OPTIONS_DSAKEY>;
using rsa_key       = cstring_option<SSH_BIND_OPTIONS_RSAKEY>;
using ecdsa_key     = cstring_option<SSH_BIND_OPTIONS_ECDSAKEY>;

using banner        = cstring_option<SSH_BIND_OPTIONS_BANNER>;
using log_verbosity = int_option<SSH_BIND_OPTIONS_LOG_VERBOSITY>;
using log_verbosity_str
                    = cstring_option<SSH_BIND_OPTIONS_LOG_VERBOSITY_STR>;

using import_key     = key_option<SSH_BIND_OPTIONS_IMPORT_KEY>;
using import_key_str = cstring_option<SSH_BIND_OPTIONS_IMPORT_KEY_STR>;

using key_exchange  = cstring_option<SSH_BIND_OPTIONS_KEY_EXCHANGE>;
using ciphers_c_s   = cstring_option<SSH_BIND_OPTIONS_CIPHERS_C_S>;
using ciphers_s_c   = cstring_option<SSH_BIND_OPTIONS_CIPHERS_S_C>;
using hmac_c_s      = cstring_option<SSH_BIND_OPTIONS_HMAC_C_S>;
using hmac_s_c      = cstring_option<SSH_BIND_OPTIONS_HMAC_S_C>;

using config_dir    = cstring_option<SSH_BIND_OPTIONS_CONFIG_DIR>;
using pubkey_accepted_key_types
                    = cstring_option<SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES>;
using hostkey_algorithms
                    = cstring_option<SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS>;
using process_config = bool_option<SSH_BIND_OPTIONS_PROCESS_CONFIG>;
using moduli        = cstring_option<SSH_BIND_OPTIONS_MODULI>;
using rsa_min_size  = int_option<SSH_BIND_OPTIONS_RSA_MIN_SIZE>;

}
