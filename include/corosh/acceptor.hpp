// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#pragma once 

#include <corosh/error.hpp>

#include <boost/capy/io_task.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <libssh/server.h>

namespace corosh
{

struct session;
struct acceptor
{

  explicit acceptor(boost::capy::execution_context& ctx) 
      : bind_(ssh_bind_new())
      , acceptor_(ctx)
  {
    if (!bind_)
      throw std::bad_alloc();

    ssh_bind_set_blocking(bind_.get(), 0);
  }
  
  template<class Ex>
      requires(!std::same_as<std::remove_cvref_t<Ex>, acceptor>) &&
      boost::capy::Executor<Ex>
  explicit acceptor(Ex const& ex) : acceptor(ex.context())
  {
  }

  acceptor(acceptor && rhs) 
    : bind_(std::exchange(rhs.bind_, nullptr))
    , acceptor_(std::move(rhs.acceptor_))
  {
  }

  template<typename Option>
    requires requires (const Option & opt)
    {
      {opt.option()} -> std::same_as<ssh_bind_options_e>;
      {opt.data()} -> std::same_as<const void*>;
    }
  void set_option(const Option & opt)
  {
    auto rc = ssh_bind_options_set(bind_.get(), opt.option(), opt.data());
    
    if (rc != SSH_OK)
      throw std::system_error(
              std::error_code(ssh_get_error_code(bind_.get()), ssh_category()),
              ssh_get_error(bind_.get())
              );
  }
  
  template<typename Option>
    requires requires (Option & opt)
    {
      {opt.option()} -> std::same_as<ssh_bind_options_e>;
      {opt.data()} -> std::same_as<void*>;
    }
  void get_option(const Option & opt)
  {
    auto rc = ssh_bind_options_get(bind_.get(), opt.option(), opt.data());
    if (rc != SSH_OK)
      throw std::system_error(
              std::error_code(ssh_get_error_code(bind_.get()), ssh_category()),
              ssh_get_error(bind_.get())
              );
  }


  void open(boost::corosio::tcp proto = boost::corosio::tcp::v4()) 
  {
    acceptor_.open(proto); 
  }
  std::error_code bind(boost::corosio::tcp_socket::endpoint_type);
  std::error_code listen();

  boost::capy::io_task<> accept(session & s);

  
  boost::capy::execution_context&
    context() const noexcept
  {
    return acceptor_.context();
  }

  using native_handle_type = ssh_bind;
  native_handle_type native_handle() const noexcept {return bind_.get(); }


  void parse_config(const char * filename = nullptr);
 private:

   
  struct deleter_ {void operator()(ssh_bind s) {ssh_bind_free(s);} };
  std::unique_ptr<std::remove_pointer_t<ssh_bind>, deleter_> bind_;
  boost::corosio::tcp_acceptor acceptor_;

};

}

