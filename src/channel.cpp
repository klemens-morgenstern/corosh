#include <corosh/channel.hpp>
#include <corosh/session.hpp>

#include <boost/capy/when_all.hpp>
#include <boost/capy/concept/read_source.hpp>
#include <boost/capy/concept/write_sink.hpp>
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
    else
      ec = std::make_error_code(std::errc::not_connected);

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
    else
      ec = std::make_error_code(std::errc::not_connected);
      
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
        return ssh_channel_read(channel_.get(), buffer.data(), buffer.size(), is_stderr ? 1 : 0);;
    }
  );
}


boost::capy::io_task<std::size_t> channel::read(
    boost::capy::mutable_buffer buffer, bool is_stderr)
{
  return do_io_(
      [this, buffer, is_stderr, m = 0]() mutable
      {
        auto n = ssh_channel_read(channel_.get(), buffer.data(), buffer.size(), is_stderr ? 1 : 0);

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

}

