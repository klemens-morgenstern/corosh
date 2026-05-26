#include <corosh/channel.hpp>
#include <corosh/session.hpp>

#include <boost/capy/when_all.hpp>
#include <libssh/libssh.h>

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
    auto rc = Function();
    if (rc == SSH_OK)
       co_return {};
    if (rc == SSH_ERROR)
      co_return std::error_code(ssh_get_error_code(channel_.get()), ssh_category());


    auto r = ssh_get_poll_flags(s);
    if (r == SSH_READ_PENDING)
      co_return get<0>(co_await socket_->wait(boost::corosio::wait_type::read));
    else if (r == SSH_WRITE_PENDING)
      co_return get<0>(co_await socket_->wait(boost::corosio::wait_type::write));
    else if (r == (SSH_READ_PENDING | SSH_WRITE_PENDING))
    {
      auto v = co_await boost::capy::when_all(
        socket_->wait(boost::corosio::wait_type::read),
        socket_->wait(boost::corosio::wait_type::write)
      );
     co_return get<0>(v);
    }
    else
      co_return std::make_error_code(std::errc::not_connected);
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


}

