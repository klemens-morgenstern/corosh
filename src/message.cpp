// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern


#include <corosh/channel.hpp>
#include <corosh/message.hpp>
#include <corosh/error.hpp>

#include <boost/capy/when_all.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <system_error>

namespace corosh
{

// ------------------------------------------------------------------ meta
ssh_requests_e message::type() const noexcept
{
  return static_cast<ssh_requests_e>(ssh_message_type(message_.get()));
}

int message::subtype() const noexcept
{
  return ssh_message_subtype(message_.get());
}

// ------------------------------------------------------------------ auth
const char * message::auth_user() const noexcept
{
  return ssh_message_auth_user(message_.get());
}

bool message::auth_kbdint_is_response() const noexcept
{
  return ssh_message_auth_kbdint_is_response(message_.get()) != 0;
}

// ------------------------------------------------------------------ service
const char * message::service() const noexcept
{
  return ssh_message_service_service(message_.get());
}

// ------------------------------------------------------------------ global request
const char * message::global_request_address() const noexcept
{
  return ssh_message_global_request_address(message_.get());
}

int message::global_request_port() const noexcept
{
  return ssh_message_global_request_port(message_.get());
}

// ------------------------------------------------------------------ channel open
const char * message::channel_request_open_originator() const noexcept
{
  return ssh_message_channel_request_open_originator(message_.get());
}

int message::channel_request_open_originator_port() const noexcept
{
  return ssh_message_channel_request_open_originator_port(message_.get());
}

const char * message::channel_request_open_destination() const noexcept
{
  return ssh_message_channel_request_open_destination(message_.get());
}

int message::channel_request_open_destination_port() const noexcept
{
  return ssh_message_channel_request_open_destination_port(message_.get());
}

// ------------------------------------------------------------------ channel request
channel message::channel_request_channel() const noexcept
{
  return {ssh_message_channel_request_channel(message_.get()), socket_};
}

const char * message::channel_request_env_name() const noexcept
{
  return ssh_message_channel_request_env_name(message_.get());
}

const char * message::channel_request_env_value() const noexcept
{
  return ssh_message_channel_request_env_value(message_.get());
}

const char * message::channel_request_command() const noexcept
{
  return ssh_message_channel_request_command(message_.get());
}

const char * message::channel_request_subsystem() const noexcept
{
  return ssh_message_channel_request_subsystem(message_.get());
}


// ------------------------------------------------------------------ do_op_
//
// SSH_AGAIN-poll-retry loop. Mirrors session::do_op_ in src/session.cpp.
template<typename Function>
boost::capy::io_task<> message::do_op_(Function f)
{
  for (;;)
  {
    auto rc = f();
    if (rc == SSH_OK)
      co_return {};
    if (rc == SSH_ERROR)
      co_return std::error_code(ssh_get_error_code(session_), ssh_category());

    std::error_code ec;
    auto r = ssh_get_poll_flags(session_);
    if (r == SSH_READ_PENDING)
      ec = get<0>(co_await socket_->wait(boost::corosio::wait_type::read));
    else if (r == SSH_WRITE_PENDING)
      ec = get<0>(co_await socket_->wait(boost::corosio::wait_type::write));
    else if (r == (SSH_READ_PENDING | SSH_WRITE_PENDING))
    {
      auto v = co_await boost::capy::when_all(
        socket_->wait(boost::corosio::wait_type::read),
        socket_->wait(boost::corosio::wait_type::write)
      );
      ec = get<0>(v);
    }
    else
      ec = std::make_error_code(std::errc::not_connected);

    if (ec)
      co_return ec;
  }
}


// ------------------------------------------------------------------ replies
boost::capy::io_task<> message::reply_default()
{
  return do_op_([this]{ return ssh_message_reply_default(message_.get()); });
}

boost::capy::io_task<> message::auth_reply_success(bool partial)
{
  return do_op_([this, partial]{
    return ssh_message_auth_reply_success(message_.get(), partial ? 1 : 0);
  });
}

boost::capy::io_task<> message::auth_reply_pk_ok(ssh_string algo, ssh_string pubkey)
{
  return do_op_([this, algo, pubkey]{
    return ssh_message_auth_reply_pk_ok(message_.get(), algo, pubkey);
  });
}

boost::capy::io_task<> message::auth_reply_pk_ok_simple()
{
  return do_op_([this]{ return ssh_message_auth_reply_pk_ok_simple(message_.get()); });
}

int message::auth_set_methods(int methods)
{
  return ssh_message_auth_set_methods(message_.get(), methods);
}

boost::capy::io_task<> message::auth_interactive_request(
    const char * name, const char * instruction,
    unsigned int num_prompts, const char ** prompts, char * echo)
{
  return do_op_([this, name, instruction, num_prompts, prompts, echo]{
    return ssh_message_auth_interactive_request(
        message_.get(), name, instruction, num_prompts, prompts, echo);
  });
}

boost::capy::io_task<> message::service_reply_success()
{
  return do_op_([this]{ return ssh_message_service_reply_success(message_.get()); });
}

boost::capy::io_task<> message::global_request_reply_success(std::uint16_t bound_port)
{
  return do_op_([this, bound_port]{
    return ssh_message_global_request_reply_success(message_.get(), bound_port);
  });
}

boost::capy::io_task<> message::channel_request_open_reply_accept_channel(ssh_channel chan)
{
  return do_op_([this, chan]{
    return ssh_message_channel_request_open_reply_accept_channel(message_.get(), chan);
  });
}

boost::capy::io_task<> message::channel_request_reply_success()
{
  return do_op_([this]{
    return ssh_message_channel_request_reply_success(message_.get());
  });
}

}
