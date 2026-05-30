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
#include <libssh/callbacks.h>
#include <chrono>
#include <string>
#include <type_traits>

namespace corosh
{

struct acceptor;
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

  ~session();

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

  struct open_forward_port_result
  {
    std::optional<channel> chan;
    unsigned short destination_port;
    std::string    originator;
    unsigned short originator_port;
  };

  open_forward_port_result open_forward_port();
  
  using native_handle_type = ssh_session;
  native_handle_type native_handle() const noexcept {return session_.get(); }


  // server functions
  boost::capy::io_task<> server_init_kex();

  struct server_callbacks;
  void install_server_callbacks(std::unique_ptr<server_callbacks> cb);

  struct client_callbacks;
  void install_client_callbacks(std::unique_ptr<client_callbacks> cb);

  

 private:
  friend struct channel;
  friend struct acceptor;

  struct deleter_ {void operator()(ssh_session s) {ssh_free(s);} };
  std::unique_ptr<std::remove_pointer_t<ssh_session>, deleter_> session_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;

  std::unique_ptr<server_callbacks> server_callbacks_;
  std::unique_ptr<client_callbacks> client_callbacks_;

  template<typename AuthFunction>
  boost::capy::io_task<ssh_auth_e> do_auth_(AuthFunction);

  template<typename Function>
  boost::capy::io_task<> do_op_(Function f);
};


struct session::server_callbacks
{
  server_callbacks();
  server_callbacks(const server_callbacks &) = delete;

  virtual ssh_auth_e auth_password(const char * user, const char * password);
  virtual ssh_auth_e auth_none(const char * user);
  virtual ssh_auth_e auth_pubkey(const char * user, ssh_key pubkey,
                                 char signature_state);
  virtual ssh_auth_e auth_gssapi_mic(const char * user, const char * principal);

  virtual bool        service_request(const char * service);
  virtual ssh_channel channel_open_request_session();

  virtual ssh_string gssapi_select_oid(const char * user, int n_oid, ssh_string * oids);
  virtual int        gssapi_accept_sec_ctx(std::string_view input_token, ssh_string * output_token);
  virtual int        gssapi_verify_mic(std::string_view mic, boost::capy::const_buffer mic_buffer);

  void enable_gssapi();
  void disable_gssapi();

  virtual ~server_callbacks();
 private:
  friend struct session;
  ssh_server_callbacks_struct impl_;
};


struct session::client_callbacks
{
  client_callbacks();
  client_callbacks(const client_callbacks &) = delete;

  virtual bool auth(const char * prompt, std::span<char> buf,
                    bool echo, bool verify);

  virtual ssh_channel channel_open_request_x11(
                          const char * originator_address,
                          int originator_port);
                          
  virtual ssh_channel channel_open_request_auth_agent();
  virtual ssh_channel channel_open_request_forwarded_tcpip(
                          const char * destination_address, int destination_port,
                          const char * originator_address,   int originator_port);

  virtual ~client_callbacks();
 private:
  friend struct session;
  ssh_callbacks_struct impl_;
};

}
