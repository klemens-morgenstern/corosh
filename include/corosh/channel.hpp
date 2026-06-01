// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#pragma once

#include <boost/capy/io_task.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/error.hpp>
#include <libssh/libssh.h>
#include <libssh/callbacks.h>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace corosh
{
struct session;
struct message;

struct exit_state
{
  std::uint32_t exit_code;
  std::string   exit_signal;
  bool          core_dumped;
};

struct channel
{
  channel(session & s);
  channel() noexcept = delete;
  channel(channel && ) noexcept = default;
  channel& operator=(channel && ) noexcept = default;


  bool is_open() const { return ssh_channel_is_open(channel_.get()) != 0; }
  bool eof()     const { return ssh_channel_is_eof(channel_.get()) != 0; }

  std::uint32_t window_size() const { return ssh_channel_window_size(channel_.get()); }

  boost::capy::io_task<> change_pty_size(int cols, int rows);
  boost::capy::io_task<exit_state> get_exit_state();

  boost::capy::io_task<> open_session();
  boost::capy::io_task<> open_auth_agent();
  boost::capy::io_task<> open_forward(const char * remotehost, int remoteport,
                                      const char * sourcehost, int localport);
  boost::capy::io_task<> open_forward_unix(const char * remotepath,
                                           const char * sourcehost, int localport);
  boost::capy::io_task<> open_x11(const char * orig_addr, int orig_port);
  boost::capy::io_task<> open_reverse_forward(const char * remotehost, int remoteport,
                                              const char * sourcehost, int localport);

  boost::capy::io_task<> request_env(const char * name, const char * value);
  boost::capy::io_task<> request_exec(const char * cmd);
  boost::capy::io_task<> request_pty();
  boost::capy::io_task<> request_pty_size(const char * term, int cols, int rows);
  boost::capy::io_task<> request_pty_size_modes(const char * term, int cols, int rows,
                                                const unsigned char * modes, std::size_t modes_len);
  boost::capy::io_task<> request_shell();
  boost::capy::io_task<> request_send_signal(const char * signum);
  boost::capy::io_task<> request_send_break(std::uint32_t length);
  boost::capy::io_task<> request_sftp();
  boost::capy::io_task<> request_subsystem(const char * subsystem);
  boost::capy::io_task<> request_x11(int single_connection, const char * protocol,
                                     const char * cookie, int screen_number);
  boost::capy::io_task<> request_auth_agent();
  boost::capy::io_task<> request_send_exit_status(int exit_status);
  boost::capy::io_task<> request_send_exit_signal(const char * signum, int core,
                                                  const char * errmsg, const char * lang);


  template<boost::capy::MutableBufferSequence MB>
    requires (!std::same_as<MB, boost::capy::mutable_buffer>)
  boost::capy::io_task<std::size_t> read_some(MB buffer, bool is_stderr = false)
  {
    if (boost::capy::buffer_size(buffer) == 0u)
      return []() -> boost::capy::io_task<std::size_t> {co_return {{}, 0u};}();

    boost::capy::mutable_buffer b = *std::begin(buffer);
    return read_some(b, is_stderr);
  }

  boost::capy::io_task<std::size_t> read_some(boost::capy::mutable_buffer buffer, bool is_stderr = false);


  template<boost::capy::MutableBufferSequence MB>
    requires (!std::same_as<MB, boost::capy::mutable_buffer>)
  boost::capy::io_task<std::size_t> read(MB buffer, bool is_stderr = false)
  {
    std::size_t n = 0u;
    for (auto bf : buffer)
    {
        auto [ec, m] = co_await read(bf, is_stderr);
        m += n;
        if (!ec && eof())
          ec = boost::capy::error::eof;
        if (ec)
          co_return {ec, n};
    }

    co_return {{}, n};
  }

  boost::capy::io_task<std::size_t> read(boost::capy::mutable_buffer buffer, bool is_stderr = false);


  template<boost::capy::ConstBufferSequence CB>
    requires (!std::same_as<CB, boost::capy::const_buffer>)
  boost::capy::io_task<std::size_t> write_some(CB buffer, bool is_stderr = false)
  {
    if (boost::capy::buffer_size(buffer) == 0u)
      return []() -> boost::capy::io_task<std::size_t> {co_return {{}, 0u};}();

    boost::capy::const_buffer b = *std::begin(buffer);
    return write_some(b, is_stderr);
  }
  boost::capy::io_task<std::size_t> write_some(boost::capy::const_buffer buffer, bool is_stderr);

 template<boost::capy::ConstBufferSequence CB>
    requires (!std::same_as<CB, boost::capy::const_buffer>)
  boost::capy::io_task<std::size_t> write(CB buffer, bool is_stderr = false)
  {
    std::size_t n = 0u;
    for (auto bf : buffer)
    {
        auto [ec, m] = co_await write(bf, is_stderr);
        m += n;
        if (!ec && eof())
          ec = boost::capy::error::eof;
        if (ec)
          co_return {ec, n};
    }

    co_return {{}, n};
  }

  boost::capy::io_task<std::size_t> write(boost::capy::const_buffer buffer, bool is_stderr = false);


 template<boost::capy::ConstBufferSequence CB>
    requires (!std::same_as<CB, boost::capy::const_buffer>)
  boost::capy::io_task<std::size_t> write_eof(CB buffer, bool is_stderr = false)
  {
    std::size_t n = 0u;
    for (auto bf : buffer)
    {
        auto [ec, m] = co_await write(bf, is_stderr);
        m += n;
        if (!ec && eof())
          ec = boost::capy::error::eof;
        if (ec)
          co_return {ec, n};
    }

    auto [ec] = co_await write_eof();
    co_return {ec, n};
  }

  boost::capy::io_task<> write_eof();

  struct stderr_t
  {
    stderr_t(channel & chn) noexcept : chn_(chn) {}


    template<boost::capy::MutableBufferSequence MB>
    boost::capy::io_task<std::size_t> read_some(MB buffer)
    {
      return chn_.read_some(std::move(buffer), true);
    }

    template<boost::capy::MutableBufferSequence MB>
    boost::capy::io_task<std::size_t> read(MB buffer)
    {
      return chn_.read(std::move(buffer), true);
    }

    template<boost::capy::ConstBufferSequence CB>
    boost::capy::io_task<std::size_t> write_some(CB buffer)
    {
      return chn_.write_some(std::move(buffer), true);
    }

    template<boost::capy::ConstBufferSequence CB>
    boost::capy::io_task<std::size_t> write(CB buffer)
    {
      return chn_.write(std::move(buffer), true);
    }

    template<boost::capy::ConstBufferSequence CB>
    boost::capy::io_task<std::size_t> write_eof(CB buffer)
    {
      return chn_.write_eof(std::move(buffer), true);    
    }
    
    boost::capy::io_task<> write_eof()
    {
      return chn_.write_eof();
    }

   private: 
    channel & chn_;
  };

  stderr_t std_err() {return stderr_t{*this};}

  struct callbacks;
  void set_callbacks(callbacks & cb);

 private:
  channel(
    ssh_channel channel,
    std::shared_ptr<boost::corosio::tcp_socket> socket_) : 
    channel_(channel), socket_(std::move(socket_)) 
  {}
  struct deleter { void operator()(ssh_channel chan) {ssh_channel_free(chan);} };
  std::unique_ptr<std::remove_pointer_t<ssh_channel>, deleter> channel_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;

  template<typename Function>
  boost::capy::io_task<> do_open_(Function f);

  
  template<typename Function>
  boost::capy::io_task<std::size_t> do_some_io_(Function f);

  template<typename Function>
  boost::capy::io_task<std::size_t> do_io_(Function f);

  friend struct session;
  friend struct message;

};


struct channel::callbacks
{
  callbacks();
  callbacks(const callbacks & ) = delete;

  virtual void signal(const char *signal);
  virtual void exit_status(int exit_status);
  virtual void exit_signal(const char *signal, int core,
                           const char *errmsg, const char *lang);
  virtual void x11_req(int single_connection, const char *auth_protocol,
                       const char *auth_cookie, std::uint32_t screen_number);

  virtual void close();

  virtual bool pty_request(const char *term, int width, int height,
                           int pxwidth, int pwheight);
  virtual bool pty_window_change(int width, int height, int pxwidth, int pwheight);
  virtual bool shell_request();
  virtual bool exec_request(const char *command);
  virtual bool env_request(const char *env_name, const char *env_value);
  virtual bool subsystem_request(const char *subsystem);

  virtual ~callbacks();
 private:
  friend struct channel;
  ssh_channel_callbacks_struct impl_;
  ssh_channel chan_ = nullptr;
};




}

