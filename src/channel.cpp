// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#include <chrono>
#include <corosh/channel.hpp>
#include <corosh/session.hpp>

#include <boost/capy/when_all.hpp>
#include <boost/capy/concept/read_source.hpp>
#include <boost/capy/concept/write_sink.hpp>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <libssh/server.h>

namespace corosh
{

channel::channel(session & s)
  : channel_(ssh_channel_new(s.session_.get()))
  , socket_(s.socket_)
{
  if (channel_ == nullptr)
    throw std::system_error(
            std::error_code(ssh_get_error_code(s.session_.get()), ssh_category()),
            ssh_get_error(s.session_.get())
            );
  ssh_channel_set_blocking(channel_.get(), 0);
}

template<typename Function>
boost::capy::io_task<> channel::do_open_(Function f)
{
  auto s = ssh_channel_get_session(channel_.get());
  for (;;)
  {
    auto rc = f();
    if (rc == SSH_OK)
       co_return {};
    if (rc == SSH_ERROR)
      co_return std::error_code(ssh_get_error_code(channel_.get()), ssh_category());

    std::error_code ec;

    auto r = ssh_get_poll_flags(s);
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

boost::capy::io_task<> channel::open_session()
{
  return do_open_(
    [this]
    {
      return ssh_channel_open_session(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::open_auth_agent()
{
  return do_open_(
    [this]
    {
      return ssh_channel_open_auth_agent(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::open_forward(const char * remotehost, int remoteport,
                                             const char * sourcehost, int localport)
{
  return do_open_(
    [this, remotehost, remoteport, sourcehost, localport]
    {
      return ssh_channel_open_forward(channel_.get(), remotehost, remoteport, sourcehost, localport);
    }
    );
}

boost::capy::io_task<> channel::open_forward_unix(const char * remotepath,
                                                  const char * sourcehost, int localport)
{
  return do_open_(
    [this, remotepath, sourcehost, localport]
    {
      return ssh_channel_open_forward_unix(channel_.get(), remotepath, sourcehost, localport);
    }
    );
}

boost::capy::io_task<> channel::open_x11(const char * orig_addr, int orig_port)
{
  return do_open_(
    [this, orig_addr, orig_port]
    {
      return ssh_channel_open_x11(channel_.get(), orig_addr, orig_port);
    }
    );
}

boost::capy::io_task<> channel::open_reverse_forward(const char * remotehost, int remoteport,
                                                     const char * sourcehost, int localport)
{
  return do_open_(
    [this, remotehost, remoteport, sourcehost, localport]
    {
      return ssh_channel_open_reverse_forward(channel_.get(), remotehost, remoteport, sourcehost, localport);
    }
    );
}

boost::capy::io_task<> channel::request_env(const char * name, const char * value)
{
  return do_open_(
    [this, name, value]
    {
      return ssh_channel_request_env(channel_.get(), name, value);
    }
    );
}

boost::capy::io_task<> channel::request_exec(const char * cmd)
{
  return do_open_(
    [this, cmd]
    {
      return ssh_channel_request_exec(channel_.get(), cmd);
    }
    );
}

boost::capy::io_task<> channel::request_pty()
{
  return do_open_(
    [this]
    {
      return ssh_channel_request_pty(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::request_pty_size(const char * term, int cols, int rows)
{
  return do_open_(
    [this, term, cols, rows]
    {
      return ssh_channel_request_pty_size(channel_.get(), term, cols, rows);
    }
    );
}

boost::capy::io_task<> channel::request_pty_size_modes(const char * term, int cols, int rows,
                                                       const unsigned char * modes, std::size_t modes_len)
{
  return do_open_(
    [this, term, cols, rows, modes, modes_len]
    {
      return ssh_channel_request_pty_size_modes(channel_.get(), term, cols, rows, modes, modes_len);
    }
    );
}

boost::capy::io_task<> channel::request_shell()
{
  return do_open_(
    [this]
    {
      return ssh_channel_request_shell(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::request_send_signal(const char * signum)
{
  return do_open_(
    [this, signum]
    {
      return ssh_channel_request_send_signal(channel_.get(), signum);
    }
    );
}

boost::capy::io_task<> channel::request_send_break(std::uint32_t length)
{
  return do_open_(
    [this, length]
    {
      return ssh_channel_request_send_break(channel_.get(), length);
    }
    );
}

boost::capy::io_task<> channel::request_sftp()
{
  return do_open_(
    [this]
    {
      return ssh_channel_request_sftp(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::request_subsystem(const char * subsystem)
{
  return do_open_(
    [this, subsystem]
    {
      return ssh_channel_request_subsystem(channel_.get(), subsystem);
    }
    );
}

boost::capy::io_task<> channel::request_x11(int single_connection, const char * protocol,
                                            const char * cookie, int screen_number)
{
  return do_open_(
    [this, single_connection, protocol, cookie, screen_number]
    {
      return ssh_channel_request_x11(channel_.get(), single_connection, protocol, cookie, screen_number);
    }
    );
}

boost::capy::io_task<> channel::request_auth_agent()
{
  return do_open_(
    [this]
    {
      return ssh_channel_request_auth_agent(channel_.get());
    }
    );
}

boost::capy::io_task<> channel::request_send_exit_status(int exit_status)
{
  return do_open_(
    [this, exit_status]
    {
      return ssh_channel_request_send_exit_status(channel_.get(), exit_status);
    }
    );
}

boost::capy::io_task<> channel::request_send_exit_signal(const char * signum, int core,
                                                         const char * errmsg, const char * lang)
{
  return do_open_(
    [this, signum, core, errmsg, lang]
    {
      return ssh_channel_request_send_exit_signal(channel_.get(), signum, core, errmsg, lang);
    }
    );
}

boost::capy::io_task<> channel::change_pty_size(int cols, int rows)
{
  return do_open_(
    [this, cols, rows]
    {
      return ssh_channel_change_pty_size(channel_.get(), cols, rows);
    }
    );
}

boost::capy::io_task<exit_state> channel::get_exit_state()
{
  auto s = ssh_channel_get_session(channel_.get());
  std::uint32_t exit_code = 0;
  char * exit_signal = nullptr;
  int core_dumped = 0;
  for (;;)
  {
    auto rc = ssh_channel_get_exit_state(channel_.get(), &exit_code, &exit_signal, &core_dumped);
    if (rc == SSH_OK)
    {
      exit_state es{
        exit_code,
        exit_signal ? std::string(exit_signal) : std::string{},
        core_dumped != 0
      };
      if (exit_signal)
        ssh_string_free_char(exit_signal);
      co_return {{}, std::move(es)};
    }
    if (rc == SSH_ERROR)
      co_return {std::error_code(ssh_get_error_code(channel_.get()), ssh_category()), {}};

    std::error_code ec;
    auto r = ssh_get_poll_flags(s);
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

    if (ec)
      co_return {ec, {}};
  }
}

boost::capy::io_task<> channel::write_eof()
{
  return do_open_(
    [this]
    {
      return ssh_channel_send_eof(channel_.get());
    }
    );
}


template<typename Function>
boost::capy::io_task<std::size_t> channel::do_some_io_(Function f)
{
  auto s = ssh_channel_get_session(channel_.get());
  for (;;)
  {
    auto rc = f();
    if (rc == 0)
       co_return {boost::capy::error::eof, 0u};
    if (rc > 0)
       co_return {{}, static_cast<std::size_t>(rc)};
       
    if (rc == SSH_ERROR)
      co_return {std::error_code(ssh_get_error_code(channel_.get()), ssh_category()), 0u};

    std::error_code ec;

    auto r = ssh_get_poll_flags(s);
    if (r == SSH_READ_PENDING)
    {
      boost::corosio::timer t{socket_->context()};
      t.expires_after(std::chrono::milliseconds(10));
      ec = (co_await t.wait()).ec;
      
      //ec = get<0>(co_await socket_->wait(boost::corosio::wait_type::read));
    }
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
    
    if (ec)
      co_return {ec, 0ull};
  }  
}



template<typename Function>
boost::capy::io_task<std::size_t> channel::do_io_(Function f)
{
  auto s = ssh_channel_get_session(channel_.get());
  for (;;)
  {
    auto rc = f();
    if (rc == 0)
       co_return {boost::capy::error::eof, 0u};
       
    if (rc == SSH_ERROR)
      co_return {std::error_code(ssh_get_error_code(channel_.get()), ssh_category()), 0u};

    std::error_code ec;

    auto r = ssh_get_poll_flags(s);
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
      
    if (ec)
      co_return {ec, 0ull};
  }  
}


boost::capy::io_task<std::size_t> channel::read_some(
    boost::capy::mutable_buffer buffer, bool is_stderr)
{
  return do_some_io_(
    [this, buffer, is_stderr]
    {
      return ssh_channel_read_timeout(channel_.get(), buffer.data(), buffer.size(), is_stderr ? 1 : 0, 0);
    }
  );
}


boost::capy::io_task<std::size_t> channel::read(
    boost::capy::mutable_buffer buffer, bool is_stderr)
{
  return do_io_(
      [this, buffer, is_stderr, m = 0]() mutable
      {
        auto n = ssh_channel_read_timeout(channel_.get(), buffer.data(), buffer.size(), is_stderr ? 1 : 0, 0);

        if (n < 0)
          return n;

        buffer += n;
        m += n;
        
        if (n == 0)
          return m;
          
        return SSH_AGAIN;        
      }
  );
}
  
boost::capy::io_task<std::size_t> channel::write_some(
    boost::capy::const_buffer buffer, bool is_stderr)
{
  if (is_stderr)
    return do_some_io_(
      [this, buffer]{
          return ssh_channel_write_stderr(channel_.get(), buffer.data(), buffer.size());
      }
    );
  else
    return do_some_io_(
      [this, buffer]
      {
          return ssh_channel_write(channel_.get(), buffer.data(), buffer.size());
      }
    );
}


boost::capy::io_task<std::size_t> channel::write(
    boost::capy::const_buffer buffer, bool is_stderr)
{
  if (is_stderr)
    return do_io_(
      [this, buffer, m = 0]() mutable
      {
        auto n =  ssh_channel_write_stderr(channel_.get(), buffer.data(), buffer.size());

        if (n < 0)
          return n;

        buffer += n;
        m += n;
        
        if (n == 0)
          return m;
          
        return SSH_AGAIN;        
      }
    );
  else
    return do_io_(
      [this, buffer, m = 0]() mutable
      {
        auto n = ssh_channel_write(channel_.get(), buffer.data(), buffer.size());
          
        if (n < 0)
          return n;

        buffer += n;
        m += n;
        
        if (n == 0)
          return m;
          
        return SSH_AGAIN;        

      }
    );
}



static_assert(boost::capy::ReadSource<channel>);
static_assert(boost::capy::WriteSink <channel>);
static_assert(boost::capy::ReadSource<channel::stderr_t>);
static_assert(boost::capy::WriteSink <channel::stderr_t>);

channel::callbacks::callbacks()
{
  ssh_callbacks_init(&impl_);

  impl_.userdata = this;
  impl_.channel_signal_function =
    +[](ssh_session, ssh_channel, const char * sig, void * this_)
    {
      static_cast<callbacks*>(this_)->signal(sig);
    };

  impl_.channel_exit_status_function =
    +[](ssh_session, ssh_channel, int exit_status, void * this_)
    {
      static_cast<callbacks*>(this_)->exit_status(exit_status);
    };

  impl_.channel_exit_signal_function =
    +[](ssh_session, ssh_channel, const char * sig, int core,
        const char * errmsg, const char * lang, void * this_)
    {
      static_cast<callbacks*>(this_)->exit_signal(sig, core, errmsg, lang);
    };
  impl_.channel_x11_req_function =
    +[](ssh_session, ssh_channel, int single_connection,
        const char * auth_protocol, const char * auth_cookie,
        std::uint32_t screen_number, void * this_)
    {
      static_cast<callbacks*>(this_)->x11_req(single_connection,
                                              auth_protocol, auth_cookie,
                                              screen_number);
    };

  impl_.channel_close_function =
    +[](ssh_session, ssh_channel, void * this_)
    {
      static_cast<callbacks*>(this_)->close();
    };

  impl_.channel_pty_request_function =
    [](ssh_session, ssh_channel,
        const char * term, int width, int height,
        int pxwidth, int pwheight, void * this_)
    {
      return static_cast<callbacks*>(this_)->pty_request(term, width, height, pxwidth, pwheight) ? 0 : -1;
    };

  impl_.channel_pty_window_change_function =
    [](ssh_session, ssh_channel,
        int width, int height, int pxwidth, int pwheight,
        void * this_)
    {
      return static_cast<callbacks*>(this_)->pty_window_change(width, height, pxwidth, pwheight) ? 0 : -1;
    };

  impl_.channel_shell_request_function =
    [](ssh_session, ssh_channel, void * this_)
    {
      return static_cast<callbacks*>(this_)->shell_request() ? 0 : -1;
    };

  impl_.channel_exec_request_function =
    [](ssh_session, ssh_channel,
        const char * exec,
        void * this_)
    {
      return static_cast<callbacks*>(this_)->exec_request(exec) ? 0 : -1;
    };

  impl_.channel_env_request_function =
    [](ssh_session, ssh_channel,
        const char * env_name, const char * env_value,
        void * this_)
    {
      return static_cast<callbacks*>(this_)->env_request(env_name, env_value) ? 0 : -1;
    };

  impl_.channel_subsystem_request_function =
    [](ssh_session, ssh_channel,
        const char * subsystem, void * this_)
    {
      return static_cast<callbacks*>(this_)->subsystem_request(subsystem) ? 0 : -1;
    };
}

void channel::callbacks::signal(const char * /*signal*/) { }
void channel::callbacks::exit_status(int /*exit_status*/) { }
void channel::callbacks::exit_signal(const char * /*signal*/, int /*core*/,
                                     const char * /*errmsg*/, const char * /*lang*/) { }
void channel::callbacks::x11_req(int /*single_connection*/,
                                 const char * /*auth_protocol*/,
                                 const char * /*auth_cookie*/,
                                 std::uint32_t /*screen_number*/) { }

void channel::callbacks::close() { }

bool channel::callbacks::pty_request(const char * /*term*/, int /*width*/, int /*height*/,
                                     int /*pxwidth*/, int /*pwheight*/)
{
  return false;
}

bool channel::callbacks::pty_window_change(int /*width*/, int /*height*/,
                                           int /*pxwidth*/, int /*pwheight*/)
{
  return false;
}

bool channel::callbacks::shell_request() { return false; }

bool channel::callbacks::exec_request(const char * /*command*/) { return false; }

bool channel::callbacks::env_request(const char * /*env_name*/, const char * /*env_value*/)
{
  return false;
}

bool channel::callbacks::subsystem_request(const char * /*subsystem*/) { return false; }


void channel::set_callbacks(callbacks & cb)
{
  cb.chan_ = channel_.get();
  auto rc = ssh_set_channel_callbacks(cb.chan_, &cb.impl_);
  if (rc != SSH_OK)
      throw std::system_error(
            std::error_code(ssh_get_error_code(channel_.get()), ssh_category()),
            ssh_get_error(channel_.get())
            );
}

channel::callbacks::~callbacks()
{
  if (chan_ != nullptr)
    ssh_remove_channel_callbacks(chan_, &impl_);
}

}

