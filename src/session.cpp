#include <chrono>
#include <corosh/session.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/socket_option.hpp>
#include <boost/corosio/timer.hpp>
#include <libssh/libssh.h>
#include <libssh/server.h>

namespace corosh
{

session::~session() = default;

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




auto session::open_forward_port() -> open_forward_port_result
{
  char * ptr = nullptr;
  int d, o;
  

  auto c = ssh_channel_open_forward_port(session_.get(), 0, &d, &ptr, &o);

  std::string orig;
  if (ptr != nullptr)
  {
    orig = ptr;
    ssh_string_free_char(ptr);
  }

  open_forward_port_result res{
    .destination_port=static_cast<unsigned short>(d),
    .originator=std::move(orig),
    .originator_port=static_cast<unsigned short>(o)
  };
  if (c)
    res.chan = channel(c, socket_);

  return res;
}
    
  


boost::capy::io_task<> session::server_init_kex()
{
  return do_op_(
    [this]
    {
      return ssh_server_init_kex(session_.get());
    }
    );
}


session::server_callbacks::server_callbacks()
{
  ssh_callbacks_init(&impl_);

  impl_.userdata = this;

  impl_.auth_password_function =
    +[](ssh_session, const char * user, const char * pwd, void * this_) -> int
    {
      return static_cast<int>(
          static_cast<server_callbacks *>(this_)->auth_password(user, pwd));
    };

  impl_.auth_none_function =
    +[](ssh_session, const char * user, void * this_) -> int
    {
      return static_cast<int>(
          static_cast<server_callbacks *>(this_)->auth_none(user));
    };

  impl_.auth_pubkey_function =
    +[](ssh_session, const char * user, struct ssh_key_struct * pubkey,
        char signature_state, void * this_) -> int
    {
      return static_cast<int>(
          static_cast<server_callbacks *>(this_)->auth_pubkey(user, pubkey, signature_state));
    };

  impl_.auth_gssapi_mic_function =
    +[](ssh_session, const char * user, const char * principal, void * this_) -> int
    {
      return static_cast<int>(
          static_cast<server_callbacks *>(this_)->auth_gssapi_mic(user, principal));
    };

  impl_.service_request_function =
    +[](ssh_session, const char * service, void * this_) -> int
    {
      return static_cast<server_callbacks *>(this_)->service_request(service) ? 0 : -1;
    };

  impl_.channel_open_request_session_function =
    +[](ssh_session, void * this_) -> ssh_channel
    {
      return static_cast<server_callbacks *>(this_)->channel_open_request_session();
    };

}

ssh_auth_e session::server_callbacks::auth_password(const char * /*user*/, const char * /*password*/)
{ return SSH_AUTH_DENIED; }

ssh_auth_e session::server_callbacks::auth_none(const char * /*user*/)
{ return SSH_AUTH_DENIED; }

ssh_auth_e session::server_callbacks::auth_pubkey(const char * /*user*/, ssh_key /*pubkey*/,
                                                  char /*signature_state*/)
{ return SSH_AUTH_DENIED; }

ssh_auth_e session::server_callbacks::auth_gssapi_mic(const char * /*user*/, const char * /*principal*/)
{ return SSH_AUTH_DENIED; }

bool session::server_callbacks::service_request(const char * /*service*/) { return false; }

ssh_channel session::server_callbacks::channel_open_request_session() { return nullptr; }

ssh_string session::server_callbacks::gssapi_select_oid(const char * /*user*/, int /*n_oid*/,
                                                        ssh_string * /*oids*/)
{ return nullptr; }

int session::server_callbacks::gssapi_accept_sec_ctx(std::string_view /*input_token*/,
                                                     ssh_string * /*output_token*/)
{ return SSH_ERROR; }

int session::server_callbacks::gssapi_verify_mic(std::string_view /*mic*/,
                                                 boost::capy::const_buffer mic_buffer)
{ return SSH_ERROR; }


void session::install_server_callbacks(std::unique_ptr<server_callbacks> cb)
{
  auto rc = ssh_set_server_callbacks(session_.get(), &cb->impl_);
  if (rc != SSH_OK)
    throw std::system_error(
            std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
            ssh_get_error(session_.get())
            );

  server_callbacks_ = std::move(cb);
}

void session::server_callbacks::enable_gssapi()
{

  impl_.gssapi_select_oid_function =
    +[](ssh_session, const char * user, int n_oid, ssh_string * oids, void * this_) -> ssh_string
    {
      return static_cast<server_callbacks *>(this_)->gssapi_select_oid(user, n_oid, oids);
    };

  impl_.gssapi_accept_sec_ctx_function =
    +[](ssh_session, ssh_string input_token, ssh_string * output_token, void * this_) -> int
    {
      std::string_view sv = input_token
          ? std::string_view{ssh_string_get_char(input_token), ssh_string_len(input_token)}
          : std::string_view{};
      return static_cast<server_callbacks *>(this_)->gssapi_accept_sec_ctx(sv, output_token);
    };

  impl_.gssapi_verify_mic_function =
    +[](ssh_session, ssh_string mic, void * mic_buffer, size_t mic_buffer_size, void * this_) -> int
    {
      std::string_view sv = mic
          ? std::string_view{ssh_string_get_char(mic), ssh_string_len(mic)}
          : std::string_view{};
      return static_cast<server_callbacks *>(this_)->gssapi_verify_mic(sv, {mic_buffer, mic_buffer_size});
    };
}

void session::server_callbacks::disable_gssapi()
{
  impl_.gssapi_select_oid_function            = nullptr;
  impl_.gssapi_accept_sec_ctx_function        = nullptr;
  impl_.gssapi_verify_mic_function            = nullptr;
}


session::server_callbacks::~server_callbacks()
{
  impl_.auth_password_function                = nullptr;
  impl_.auth_none_function                    = nullptr;
  impl_.auth_gssapi_mic_function              = nullptr;
  impl_.auth_pubkey_function                  = nullptr;
  impl_.service_request_function              = nullptr;
  impl_.channel_open_request_session_function = nullptr;
  impl_.gssapi_select_oid_function            = nullptr;
  impl_.gssapi_accept_sec_ctx_function        = nullptr;
  impl_.gssapi_verify_mic_function            = nullptr;
};


session::client_callbacks::client_callbacks()
{
  ssh_callbacks_init(&impl_);

  impl_.userdata = this;

  impl_.auth_function =
    +[](const char * prompt, char * buf, size_t len,
        int echo, int verify, void * this_) -> int
    {
      return static_cast<client_callbacks *>(this_)->auth(prompt, {buf, len},
                                                          echo != 0, verify != 0) ? 0 : -1;
    };

  impl_.channel_open_request_x11_function =
    +[](ssh_session, const char * originator_address, int originator_port,
        void * this_) -> ssh_channel
    {
      return static_cast<client_callbacks *>(this_)
                 ->channel_open_request_x11(originator_address, originator_port);
    };

  impl_.channel_open_request_auth_agent_function =
    +[](ssh_session, void * this_) -> ssh_channel
    {
      return static_cast<client_callbacks *>(this_)->channel_open_request_auth_agent();
    };

  impl_.channel_open_request_forwarded_tcpip_function =
    +[](ssh_session, const char * destination_address, int destination_port,
        const char * originator_address, int originator_port,
        void * this_) -> ssh_channel
    {
      return static_cast<client_callbacks *>(this_)
                 ->channel_open_request_forwarded_tcpip(destination_address, destination_port,
                                                        originator_address,   originator_port);
    };
}

bool session::client_callbacks::auth(const char * /*prompt*/, std::span<char> buf,
                                    bool /*echo*/, bool /*verify*/)
{
  return false; 
}



ssh_channel session::client_callbacks::channel_open_request_x11(const char * /*originator_address*/,
                                                                int /*originator_port*/)
{
  return nullptr; 
}

ssh_channel session::client_callbacks::channel_open_request_auth_agent()
{ 
  return nullptr; 
}

ssh_channel session::client_callbacks::channel_open_request_forwarded_tcpip(
    const char * /*destination_address*/, int /*destination_port*/,
    const char * /*originator_address*/,   int /*originator_port*/)
{ 
  return nullptr; 
}


void session::install_client_callbacks(std::unique_ptr<client_callbacks> cb)
{
  auto rc = ssh_set_callbacks(session_.get(), &cb->impl_);
  if (rc != SSH_OK)
    throw std::system_error(
            std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
            ssh_get_error(session_.get())
            );

  client_callbacks_ = std::move(cb);
}

session::client_callbacks::~client_callbacks()
{
  impl_.auth_function                                 = nullptr;
  impl_.log_function                                  = nullptr;
  impl_.connect_status_function                       = nullptr;
  impl_.global_request_function                       = nullptr;
  impl_.channel_open_request_x11_function             = nullptr;
  impl_.channel_open_request_auth_agent_function      = nullptr;
  impl_.channel_open_request_forwarded_tcpip_function = nullptr;
}


}

