// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#include <corosh/error.hpp>
#include <corosh/acceptor.hpp>
#include <corosh/session.hpp>
#include <corosh/server_options.hpp>

#include <boost/capy/ex/this_coro.hpp>

namespace corosh
{

std::error_code acceptor::bind(boost::corosio::tcp_socket::endpoint_type ep)
{

  std::string addr;
  if (ep.is_v4())
    addr = ep.v4_address().to_string();
  else if (ep.is_v6())
    addr = ep.v6_address().to_string();

  set_option(server_options::bind_addr(addr.c_str()));
  set_option(server_options::bind_port(ep.port()));

  return acceptor_.bind(ep);
}

std::error_code acceptor::listen() { return acceptor_.listen(); }

boost::capy::io_task<> acceptor::accept(session & s)
{
  auto ec = (co_await acceptor_.accept(*s.socket_)).ec;

  if (ec)
    co_return ec;
  
  auto rc = ssh_bind_accept_fd(bind_.get(), s.session_.get(), s.socket_->native_handle());
  if (rc)
    ec.assign(ssh_get_error_code(bind_.get()), ssh_category());

  ssh_set_blocking(s.session_.get(), 0);
  co_return ec;
}


}
