#pragma once

#include <libssh/libssh.h>

namespace corosh::options
{

template<ssh_options_e Option>
struct cstring_option 
{
  constexpr static ssh_options_e option() {return Option; }

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


template<ssh_options_e Option, typename Int>
struct integral_option 
{
  constexpr static ssh_options_e option() {return Option; }

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

  void * data()  noexcept 
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

template<ssh_options_e Option>
using unsigned_int_option = integral_option<Option, unsigned int>;


template<ssh_options_e Option>
using int_option = integral_option<Option, int>;

template<ssh_options_e Option>
using long_option = integral_option<Option, long>;


template<ssh_options_e Option>
struct bool_option
{
  constexpr static ssh_options_e option() {return Option; }
  
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

  void * data()  noexcept 
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


using host          = cstring_option<SSH_OPTIONS_HOST>;
using port          = unsigned_int_option<SSH_OPTIONS_PORT>;
using port_str      = cstring_option<SSH_OPTIONS_PORT_STR>;
using fd            = int_option<SSH_OPTIONS_FD>;
using binaddr       = cstring_option<SSH_OPTIONS_BINDADDR>;
using user          = cstring_option<SSH_OPTIONS_USER>;
using ssh_dir       = cstring_option<SSH_OPTIONS_SSH_DIR>;
using known_hosts   = cstring_option<SSH_OPTIONS_KNOWNHOSTS>;
using global_known_hosts  
                    = cstring_option<SSH_OPTIONS_GLOBAL_KNOWNHOSTS>;
using add_identity  = cstring_option<SSH_OPTIONS_ADD_IDENTITY>;
using timeout       = long_option<SSH_OPTIONS_TIMEOUT>;
using timeout_usec  = long_option<SSH_OPTIONS_TIMEOUT_USEC>;
using log_verbosity = int_option<SSH_OPTIONS_LOG_VERBOSITY>;
using log_verbosity_str
                    = cstring_option<SSH_OPTIONS_LOG_VERBOSITY_STR>;

using ciphser_c_s   = cstring_option<SSH_OPTIONS_CIPHERS_C_S>;
using ciphser_s_c   = cstring_option<SSH_OPTIONS_CIPHERS_S_C>;
using key_exchange  = cstring_option<SSH_OPTIONS_KEY_EXCHANGE>;
using hmac_c_s      = cstring_option<SSH_OPTIONS_HMAC_C_S>;
using hmac_s_c      = cstring_option<SSH_OPTIONS_HMAC_S_C>;


using host_keys     = cstring_option<SSH_OPTIONS_HOSTKEYS>;
using public_key_accepted_types 
                    = cstring_option<SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES>;

using compression_c_s = cstring_option<SSH_OPTIONS_COMPRESSION_C_S>;
using compression_s_c = cstring_option<SSH_OPTIONS_COMPRESSION_S_C>;
using compression     = cstring_option<SSH_OPTIONS_COMPRESSION>;
using compression_level  = int_option<SSH_OPTIONS_COMPRESSION_LEVEL>;
using stricthostkeycheck = bool_option<SSH_OPTIONS_STRICTHOSTKEYCHECK>;

using proxycommand = cstring_option<SSH_OPTIONS_PROXYCOMMAND>;

using gssapi_server_identity = cstring_option<SSH_OPTIONS_GSSAPI_SERVER_IDENTITY>;
using gssapi_client_identity = cstring_option<SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY>;
using gssapi_delegate_credential = bool_option<SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS>;

using password_auth = bool_option<SSH_OPTIONS_PASSWORD_AUTH>;
using pubkey_auth   = bool_option<SSH_OPTIONS_PUBKEY_AUTH>;
using kbdint_auth   = bool_option<SSH_OPTIONS_KBDINT_AUTH>;
using gssapi_auth   = bool_option<SSH_OPTIONS_GSSAPI_AUTH>;

using nodelay        = bool_option<SSH_OPTIONS_NODELAY>;
using process_config = bool_option<SSH_OPTIONS_PROCESS_CONFIG>;
using rekey_data     = integral_option<SSH_OPTIONS_REKEY_DATA, uint64_t>;
using rekey_time     = integral_option<SSH_OPTIONS_REKEY_TIME, uint32_t>;

using rsa_min_size   = int_option<SSH_OPTIONS_RSA_MIN_SIZE>;
using identity_agent = cstring_option<SSH_OPTIONS_IDENTITY_AGENT>;

}
