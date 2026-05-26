#pragma once

#include <boost/capy/io_task.hpp>
#include <boost/corosio/tcp_socket.hpp>

#include <libs/capy/include/boost/capy/buffers.hpp>
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
  boost::capy::io_task<> open_auth_agent();
  boost::capy::io_task<> open_forward(const char * remotehost, int remoteport,
                                      const char * sourcehost, int localport);
  boost::capy::io_task<> open_forward_unix(const char * remotepath,
                                           const char * sourcehost, int localport);
  boost::capy::io_task<> open_x11(const char * orig_addr, int orig_port);
  boost::capy::io_task<> open_reverse_forward(const char * remotehost, int remoteport,
                                              const char * sourcehost, int localport);


  template<boost::capy::MutableBufferSequence MB>
    requires (!std::same_as<MB, boost::capy::mutable_buffer>)
  boost::capy::io_task<std::size_t> read(MB buffer, bool is_stderr = false)
  {
    if (boost::capy::buffer_size(buffer) == 0u)
      return []() -> boost::capy::io_task<std::size_t> {co_return {{}, 0u};}();

    boost::capy::mutable_buffer b = *std::begin(buffer);
    return read(b, is_stderr);
  }

  boost::capy::io_task<std::size_t> read(boost::capy::mutable_buffer buffer, bool is_stderr = false);


  template<boost::capy::ConstBufferSequence CB>
    requires (!std::same_as<CB, boost::capy::mutable_buffer>)
  boost::capy::io_task<std::size_t> write(CB buffer)
  {
    if (boost::capy::buffer_size(buffer) == 0u)
      return []() -> boost::capy::io_task<std::size_t> {co_return {{}, 0u};}();

    boost::capy::mutable_buffer b = *std::begin(buffer);
    return write(b);
  }
  boost::capy::io_task<std::size_t> write(boost::capy::const_buffer buffer);


  template<boost::capy::ConstBufferSequence CB>
    requires (!std::same_as<CB, boost::capy::mutable_buffer>)
  boost::capy::io_task<std::size_t> write_stderr(CB buffer)
  {
    if (boost::capy::buffer_size(buffer) == 0u)
      return []() -> boost::capy::io_task<std::size_t> {co_return {{}, 0u};}();

    boost::capy::mutable_buffer b = *std::begin(buffer);
    return write(b);
  }
  boost::capy::io_task<std::size_t> write_stderr(boost::capy::const_buffer buffer);

  
  boost::capy::io_task<> send_eof();

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

  template<typename Function>
  boost::capy::io_task<std::size_t> do_io_(Function f);

};


}

