#pragma once

#include <corosh/error.hpp>
#include <corosh/channel.hpp>
#include <corosh/options.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <boost/capy/io_task.hpp>
#include <boost/capy/error.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timer.hpp>
#include <libssh/libssh.h>
#include <chrono>
#include <string>
#include <type_traits>

namespace corosh
{


struct session
{
  explicit session(boost::capy::execution_context& ctx) 
      : session_(ssh_new())
      , socket_(std::make_shared<boost::corosio::tcp_socket>(ctx))
  {
    if (!session_)
      throw std::bad_alloc();
  }
  
  template<class Ex>
      requires(!std::same_as<std::remove_cvref_t<Ex>, session>) &&
      boost::capy::Executor<Ex>
  explicit session(Ex const& ex) : session(ex.context())
  {
  }

  session(session && rhs) 
    : session_(std::exchange(rhs.session_, nullptr))
    , socket_(std::move(rhs.socket_))
  {
  }

  template<typename Option>
    requires requires (const Option & opt)
    {
      {opt.option()} -> std::same_as<ssh_options_e>;
      {opt.data()} -> std::same_as<const void*>;
    }
  void set_option(const Option & opt)
  {
    auto rc = ssh_options_set(session_.get(), opt.option(), opt.data());
    if (rc != SSH_OK)
      throw std::system_error(
              std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
              ssh_get_error(session_.get())
              );
  }
  
  template<typename Option>
    requires requires (Option & opt)
    {
      {opt.option()} -> std::same_as<ssh_options_e>;
      {opt.data()} -> std::same_as<void*>;
    }
  void get_option(const Option & opt)
  {
    auto rc = ssh_options_get(session_.get(), opt.option(), opt.data());
    if (rc != SSH_OK)
      throw std::system_error(
              std::error_code(ssh_get_error_code(session_.get()), ssh_category()),
              ssh_get_error(session_.get())
              );
  }

  void parse_config(const char * filename = nullptr);

  boost::capy::io_task<> connect(boost::corosio::endpoint ep);
  boost::capy::execution_context&
    context() const noexcept
  {
    return socket_->context();
  }


  boost::capy::io_task<ssh_auth_e> userauth_none();
  boost::capy::io_task<ssh_auth_e> userauth_password(const char * password);
  boost::capy::io_task<ssh_auth_e> userauth_gssapi();
  boost::capy::io_task<ssh_auth_e> userauth_gssapi_keyex();
  boost::capy::io_task<ssh_auth_e> userauth_try_publickey(ssh_key pubkey);
  boost::capy::io_task<ssh_auth_e> userauth_publickey(ssh_key privkey);
  boost::capy::io_task<ssh_auth_e> userauth_agent();
  boost::capy::io_task<ssh_auth_e> userauth_publickey_auto(const char * passphrase);
  boost::capy::io_task<ssh_auth_e> userauth_kbdint(const char * submethods);

  unsigned int userauth_list();

  boost::capy::io_task<int> listen_forward(const char * address, int port);
  boost::capy::io_task<>    cancel_forward(const char * address, int port);

  std::string userauth_publickey_auto_get_current_identity();

  const char * userauth_kbdint_getinstruction() noexcept;
  const char * userauth_kbdint_getname() noexcept;
  int          userauth_kbdint_getnprompts() noexcept;
  const char * userauth_kbdint_getprompt(unsigned int i, char * echo) noexcept;
  int          userauth_kbdint_getnanswers() noexcept;
  const char * userauth_kbdint_getanswer(unsigned int i) noexcept;
  bool         userauth_kbdint_setanswer(unsigned int i, const char * answer) noexcept;


  using native_handle_type = ssh_session;
  native_handle_type native_handle() const noexcept {return session_.get(); }

 private:

  friend struct channel;
 
  struct deleter_ {void operator()(ssh_session s) {ssh_free(s);} };
  std::unique_ptr<std::remove_pointer_t<ssh_session>, deleter_> session_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;

  template<typename AuthFunction>
  boost::capy::io_task<ssh_auth_e> do_auth_(AuthFunction);

  template<typename Function>
  boost::capy::io_task<> do_op_(Function f);
};

}
