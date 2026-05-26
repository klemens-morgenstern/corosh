#pragma once

#include <boost/capy/io_task.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <libssh/libssh.h>
#include <memory>

namespace corosh
{
struct session;
struct channel
{
  channel(session & s);
  channel() noexcept = delete;
  channel(channel && ) noexcept = default;
  channel& operator=(channel && ) noexcept = default;
  

  bool is_open() const { return ssh_channel_is_open(channel_.get()) != 0; }
  bool eof()     const { return ssh_channel_is_eof(channel_.get()) != 0; }

  boost::capy::io_task<> open_session();



 private:
  channel(
    ssh_channel channel,
    std::shared_ptr<boost::corosio::tcp_socket> socket_) : 
    channel_(channel), socket_(std::move(socket_)) 
  {}
  struct deleter { void operator()(ssh_channel chan) {ssh_channel_free(chan);} };
  std::unique_ptr<std::remove_pointer_t<ssh_channel>, deleter> channel_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;

  template<typename Function>
  boost::capy::io_task<> do_open_(Function f);
};


}

