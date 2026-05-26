#include <chrono>
#include <corosh/session.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/timer.hpp>
#include <libssh/libssh.h>

namespace corosh
{


void session::parse_config(const char * filename)
{
  auto rc = ssh_options_parse_config(session_.get(), filename);
  if (rc != SSH_OK)
    throw std::system_error(
            std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
            ssh_get_error(session_.get())
            );
} 


boost::capy::io_task<> session::connect(boost::corosio::endpoint ep)
{
  socket_->open();
  auto res = co_await socket_->connect(ep);
  auto  & [ec] = res;
  if (ec)
    co_return res;

  set_option(options::fd(socket_->native_handle()));
  ssh_set_blocking(session_.get(), 0);

  for (;;)
  {
    auto rc = ssh_connect(session_.get());
    if (rc == SSH_OK)
       co_return {};
    if (rc == SSH_ERROR)
      co_return std::error_code(ssh_get_error_code(session_.get()), ssh_category());

    auto r = ssh_get_poll_flags(session_.get());
    if (r == SSH_READ_PENDING)
      res = co_await socket_->wait(boost::corosio::wait_type::read);
    else if (r == SSH_WRITE_PENDING)
      res = co_await socket_->wait(boost::corosio::wait_type::write);
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


template<typename AuthFunction>
boost::capy::io_task<ssh_auth_e> session::do_auth_(AuthFunction f)
{
  for (;;)
  {
    auto rc = f();
    if (rc == SSH_AUTH_AGAIN)
    {
      auto r = ssh_get_poll_flags(session_.get());
      std::error_code ec;
      
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
        co_return {ec, SSH_AUTH_ERROR};
      continue;
    }
    if (rc == SSH_AUTH_ERROR)
      co_return {
        std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
        SSH_AUTH_ERROR
        };
    co_return {std::error_code{}, static_cast<ssh_auth_e>(rc)};
  }
}



boost::capy::io_task<ssh_auth_e> session::userauth_none()
{
  return do_auth_(
    [this]{
      return ssh_userauth_none(session_.get(), nullptr);
    }
  );
}

boost::capy::io_task<ssh_auth_e> session::userauth_password(const char * password)
{
  return do_auth_(
    [this, password]{
      return ssh_userauth_password(session_.get(), nullptr, password);
    }
  );
}


boost::capy::io_task<ssh_auth_e> session::userauth_gssapi()
{
  return do_auth_(
    [this]{
      return ssh_userauth_gssapi(session_.get());
    }
  );

}



#if LIBSSH_VERSION_MINOR >= 12

boost::capy::io_task<ssh_auth_e> session::userauth_gssapi_keyex()
{
  return do_auth_(
    [this]{
      return ssh_userauth_gssapi_keyex(session_.get());
    }
  );
}

#else

boost::capy::io_task<ssh_auth_e> session::userauth_gssapi_keyex()
{
  co_return {
      std::make_error_code(std::errc::operation_not_supported), 
      SSH_AUTH_ERROR
      };
}

#endif


boost::capy::io_task<ssh_auth_e> session::userauth_try_publickey(ssh_key pubkey)
{
  return do_auth_(
    [this, pubkey]{
      return ssh_userauth_try_publickey(session_.get(), nullptr, pubkey);
    }
  );
}

boost::capy::io_task<ssh_auth_e> session::userauth_publickey(ssh_key privkey)
{
  return do_auth_(
    [this, privkey]{
      return ssh_userauth_publickey(session_.get(), nullptr, privkey);
    }
  );
}

boost::capy::io_task<ssh_auth_e> session::userauth_agent()
{
  return do_auth_(
    [this]{
      return ssh_userauth_agent(session_.get(), nullptr);
    }
  );
}

boost::capy::io_task<ssh_auth_e> session::userauth_publickey_auto(const char * passphrase)
{
  return do_auth_(
    [this, passphrase]{
      return ssh_userauth_publickey_auto(session_.get(), nullptr, passphrase);
    }
  );
}

boost::capy::io_task<ssh_auth_e> session::userauth_kbdint(const char * submethods)
{
  return do_auth_(
    [this, submethods]{
      return ssh_userauth_kbdint(session_.get(), nullptr, submethods);
    }
  );
}

unsigned int session::userauth_list()
{
  return ssh_userauth_list(session_.get(), nullptr);
}

template<typename Function>
boost::capy::io_task<> session::do_op_(Function f)
{
  for (;;)
  {
    auto rc = f();
    if (rc == SSH_OK)
      co_return {};
    if (rc == SSH_ERROR)
      co_return std::error_code(ssh_get_error_code(session_.get()), ssh_category());

    std::error_code ec;
    auto r = ssh_get_poll_flags(session_.get());
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

boost::capy::io_task<int> session::listen_forward(const char * address, int port)
{
  int bound_port = 0;
  for (;;)
  {
    auto rc = ssh_channel_listen_forward(session_.get(), address, port, &bound_port);
    if (rc == SSH_OK)
      co_return {{}, bound_port};
    if (rc == SSH_ERROR)
      co_return {std::error_code(ssh_get_error_code(session_.get()), ssh_category()), 0};

    std::error_code ec;
    auto r = ssh_get_poll_flags(session_.get());
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
      co_return {ec, 0};
  }
}

boost::capy::io_task<> session::cancel_forward(const char * address, int port)
{
  return do_op_(
    [this, address, port]
    {
      return ssh_channel_cancel_forward(session_.get(), address, port);
    }
    );
}

std::string session::userauth_publickey_auto_get_current_identity()
{
  char * value = nullptr;
  auto rc = ssh_userauth_publickey_auto_get_current_identity(session_.get(), &value);
  if (rc != SSH_OK)
    throw std::system_error(
            std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
            ssh_get_error(session_.get())
            );
  std::string out = value ? std::string(value) : std::string();
  if (value)
    ssh_string_free_char(value);
  return out;
}

const char * session::userauth_kbdint_getinstruction() noexcept
{
  return ssh_userauth_kbdint_getinstruction(session_.get());
}

const char * session::userauth_kbdint_getname() noexcept
{
  return ssh_userauth_kbdint_getname(session_.get());
}

int session::userauth_kbdint_getnprompts() noexcept
{
  return ssh_userauth_kbdint_getnprompts(session_.get());
}

const char * session::userauth_kbdint_getprompt(unsigned int i, char * echo) noexcept
{
  return ssh_userauth_kbdint_getprompt(session_.get(), i, echo);
}

int session::userauth_kbdint_getnanswers() noexcept
{
  return ssh_userauth_kbdint_getnanswers(session_.get());
}

const char * session::userauth_kbdint_getanswer(unsigned int i) noexcept
{
  return ssh_userauth_kbdint_getanswer(session_.get(), i);
}

bool session::userauth_kbdint_setanswer(unsigned int i, const char * answer) noexcept
{
   return ssh_userauth_kbdint_setanswer(session_.get(), i, answer) >= 0;
}

}

