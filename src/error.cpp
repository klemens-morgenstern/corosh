// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#include <corosh/error.hpp>



namespace corosh
{

struct ssh_category_t final : std::error_category
{
  ssh_category_t() = default;

  std::string message( int ev ) const override
  {
    switch (ev)
    {
      case SSH_NO_ERROR:       return "no error";
      case SSH_REQUEST_DENIED: return "request denied";
      case SSH_FATAL:          return "fatal";
      case SSH_EINTR:          return "interrupted";
      default:
        return "unknown error";
    }
  }

  const char * name() const noexcept override
  {
    return "libssh";
  }
};

std::error_category & ssh_category()
{
  static ssh_category_t cat;
  return cat;
}

struct sftp_category_t final : std::error_category
{
  sftp_category_t() = default;

  std::string message( int ev ) const override
  {
    switch (ev)
    {
      case SSH_FX_OK:                  return "no error";
      case SSH_FX_EOF:                 return "end of file";
      case SSH_FX_NO_SUCH_FILE:        return "no such file";
      case SSH_FX_PERMISSION_DENIED:   return "permission denied";
      case SSH_FX_FAILURE:             return "failure";
      case SSH_FX_BAD_MESSAGE:         return "bad message";
      case SSH_FX_NO_CONNECTION:       return "no connection";
      case SSH_FX_CONNECTION_LOST:     return "connection lost";
      case SSH_FX_OP_UNSUPPORTED:      return "operation unsupported";
      case SSH_FX_INVALID_HANDLE:      return "invalid handle";
      case SSH_FX_NO_SUCH_PATH:        return "no such path";
      case SSH_FX_FILE_ALREADY_EXISTS: return "file already exists";
      case SSH_FX_WRITE_PROTECT:       return "write protected";
      case SSH_FX_NO_MEDIA:            return "no media";
      default:
        return "unknown error";
    }
  }

  const char * name() const noexcept override
  {
    return "libssh.sftp";
  }

  std::error_condition default_error_condition(int ev) const noexcept override
  {
    switch (ev)
    {
      case SSH_FX_OK:                  return {};
      case SSH_FX_NO_SUCH_FILE:        return std::errc::no_such_file_or_directory;
      case SSH_FX_NO_SUCH_PATH:        return std::errc::no_such_file_or_directory;
      case SSH_FX_PERMISSION_DENIED:   return std::errc::permission_denied;
      case SSH_FX_BAD_MESSAGE:         return std::errc::bad_message;
      case SSH_FX_NO_CONNECTION:       return std::errc::not_connected;
      case SSH_FX_CONNECTION_LOST:     return std::errc::connection_aborted;
      case SSH_FX_OP_UNSUPPORTED:      return std::errc::operation_not_supported;
      case SSH_FX_INVALID_HANDLE:      return std::errc::bad_file_descriptor;
      case SSH_FX_FILE_ALREADY_EXISTS: return std::errc::file_exists;
      case SSH_FX_WRITE_PROTECT:       return std::errc::read_only_file_system;
      case SSH_FX_NO_MEDIA:            return std::errc::no_such_device;
      default:
        return {ev, *this};
    }
  }

  bool equivalent(int code, const std::error_condition & cond) const noexcept override
  {
    if (cond.category() == *this)
      return cond.value() == code;
    return default_error_condition(code) == cond;
  }
};

std::error_category & sftp_category()
{
  static sftp_category_t cat;
  return cat;
}

}
