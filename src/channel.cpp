#include <corosh/channel.hpp>
#include <corosh/session.hpp>

#include <boost/capy/when_all.hpp>
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

boost::capy::io_task<> channel::send_eof()
{
  return do_open_(
    [this]
    {
      return ssh_channel_send_eof(channel_.get());
    }
    );
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

boost::capy::io_task<std::size_t> channel::read(
    boost::capy::mutable_buffer buffer, bool is_stderr)
{
  return do_io_(
    [this, buffer, is_stderr]{
        return ssh_channel_read(channel_.get(), buffer.data(), buffer.size(), is_stderr ? 1 : 0);;
    }
  );
}
  
boost::capy::io_task<std::size_t> channel::write(
    boost::capy::const_buffer buffer)
{
  return do_io_(
    [this, buffer]{
        return ssh_channel_write(channel_.get(), buffer.data(), buffer.size());
    }
  );
}


boost::capy::io_task<std::size_t> channel::write_stderr(
    boost::capy::const_buffer buffer)
{
  return do_io_(
    [this, buffer]{
        return ssh_channel_write_stderr(channel_.get(), buffer.data(), buffer.size());
    }
  );
}

}

