// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#pragma once

#include <memory>
#include <cstdint>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/capy/io_task.hpp>

namespace corosh
{

struct session;
struct channel;

struct message
{
  message() = default;

  operator bool() const { return !!message_; }

  using native_handle_type = ssh_message;
  native_handle_type native_handle()     const noexcept { return message_.get(); }
  ssh_message release()       noexcept { return message_.release(); }
  void        reset(ssh_message m = nullptr) noexcept { message_.reset(m); }

  // ----------------------------------------------------------------- meta
  ssh_requests_e type() const noexcept;
  int            subtype() const noexcept;

  // ----------------------------------------------------------------- auth
  const char * auth_user() const noexcept;
  bool         auth_kbdint_is_response() const noexcept;

  // ----------------------------------------------------------------- service
  const char * service() const noexcept;

  // ----------------------------------------------------------------- global request
  const char * global_request_address() const noexcept;
  int          global_request_port()    const noexcept;

  // ----------------------------------------------------------------- channel open
  const char * channel_request_open_originator()      const noexcept;
  int          channel_request_open_originator_port() const noexcept;
  const char * channel_request_open_destination()     const noexcept;
  int          channel_request_open_destination_port() const noexcept;

  // ----------------------------------------------------------------- channel request
  channel      channel_request_channel() const noexcept;
  const char * channel_request_env_name()  const noexcept;
  const char * channel_request_env_value() const noexcept;
  const char * channel_request_command()   const noexcept;
  const char * channel_request_subsystem() const noexcept;

  // ----------------------------------------------------------------- replies
  //
  // Reply helpers run the libssh call in a SSH_AGAIN-poll-retry loop,
  // mirroring `session::do_op_` in src/session.cpp.

  boost::capy::io_task<> reply_default();

  boost::capy::io_task<> auth_reply_success(bool partial = false);
  boost::capy::io_task<> auth_reply_pk_ok(ssh_string algo, ssh_string pubkey);
  boost::capy::io_task<> auth_reply_pk_ok_simple();

  // Synchronous — just updates the session's auth-methods bitmap.
  int auth_set_methods(int methods);

  boost::capy::io_task<> auth_interactive_request(
      const char * name, const char * instruction,
      unsigned int num_prompts, const char ** prompts, char * echo);

  boost::capy::io_task<> service_reply_success();

  boost::capy::io_task<> global_request_reply_success(std::uint16_t bound_port);

  // Accept the channel-open into a *pre-allocated* channel.
  boost::capy::io_task<> channel_request_open_reply_accept_channel(ssh_channel chan);

  boost::capy::io_task<> channel_request_reply_success();

 private:
  message(ssh_message                                 message,
          ssh_session                                 session,
          std::shared_ptr<boost::corosio::tcp_socket> socket_) :
    message_(message), session_(session), socket_(std::move(socket_))
  {}

  struct deleter_ { void operator()(ssh_message msg) { ssh_message_free(msg); } };
  std::unique_ptr<std::remove_pointer_t<ssh_message>, deleter_> message_;
  ssh_session                                                   session_ = nullptr;
  std::shared_ptr<boost::corosio::tcp_socket>                   socket_;

  // Defined in src/message.cpp; only used by the in-class reply
  // methods, so explicit template instantiation isn't required.
  template<typename Function>
  boost::capy::io_task<> do_op_(Function f);

  friend struct session;
};

}
