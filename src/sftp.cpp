#include <corosh/sftp.hpp>
#include <corosh/session.hpp>
#include <corosh/error.hpp>

#include <boost/capy/error.hpp>
#include <boost/capy/buffers/vector_dynamic_buffer.hpp>
#include <boost/capy/buffers/make_buffer.hpp>
#include <boost/capy/buffers.hpp>
#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/read_until.hpp>
#include <boost/capy/write.hpp>

#include <libs/capy/include/boost/capy/buffers/string_dynamic_buffer.hpp>
#include <libssh/libssh.h>
#include <libssh/sftp.h>


#include <unordered_map>
#include <utility>

namespace corosh::sftp
{
// internal functions.

constexpr std::size_t buffer_size = 32768 * 16; // 32768 is required by the standard, let's go up to half an MB, just to be sure

namespace 
{


std::uint8_t take_u8(boost::capy::const_buffer & buf, std::error_code & ec)
{
  if (!ec && buf.size() < 1u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return {};
    
  auto res = *static_cast<const std::uint8_t*>(buf.data());
  buf += 1u;
  return res;
}

std::uint32_t take_u32(boost::capy::const_buffer & buf, std::error_code & ec)
{
  if (!ec && buf.size() < 4u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return {};
    
  auto res = ntohl(*static_cast<const std::uint32_t*>(buf.data()));
  buf += 4u;
  return res;
}


std::string_view take_str(boost::capy::const_buffer & buf, std::error_code & ec)
{
  auto sz = take_u32(buf, ec);
  
  if (!ec && buf.size() < sz)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());


  if (ec)
    return {};
    

  const char * s = static_cast<const char *>(buf.data());
  buf += sz;
    
  return {s, sz};
}


void put_u8(boost::capy::mutable_buffer & buf, std::uint8_t value, std::error_code & ec)
{
  if (!ec && buf.size() < 1u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return;
    
   *static_cast<std::uint8_t*>(buf.data()) = value;
  buf += 1u;
}

void put_u32(boost::capy::mutable_buffer & buf, std::uint32_t value, std::error_code & ec)
{
  if (!ec && buf.size() < 4u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return;
    
  *static_cast<std::uint32_t*>(buf.data()) = htonl(value);
  buf += 4u;
}


void put_str(boost::capy::mutable_buffer & buf, std::string_view value, std::error_code & ec)
{
  put_u32(buf, value.size(), ec);
  
  if (!ec && buf.size() < value.size())
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return;

  std::memcpy(buf.data(), value.data(), value.size());
  buf += value.size();
}


std::size_t match_packet(std::string_view data, std::size_t* hint )
{
  if (data.size() < 4u)
    return std::string_view::npos;

  const std::uint32_t sz = ntohl(*reinterpret_cast<const std::uint32_t*>(data.data())); 

  if (data.size() >= (sz + 4u))
    return sz + 4u;
  else
    return std::string_view::npos;

}
}



boost::capy::io_task<session> init(boost::capy::any_stream stream)
{
  // this is raw ssh messaging, because that is enough
  // init message
  std::uint32_t init_message[3] = {
    htonl(8),
    SSH_FXP_INIT,
    /* version */
    htonl(LIBSFTP_VERSION)
  };

  auto res = co_await  boost::capy::write(stream, boost::capy::make_buffer(init_message));

  auto & [ec, n] = res;
  if (ec)
    co_return {ec, {}};
  

  std::vector<unsigned char> buffer;
  

  
  auto rbuf = boost::capy::dynamic_buffer(buffer);
  res = co_await boost::capy::read_until(stream, rbuf, &match_packet);
  if (ec)
    co_return {ec, {}};


  const std::uint32_t sz = ntohl(*reinterpret_cast<const std::uint32_t*>(buffer.data())); 

  auto cb = boost::capy::make_buffer(rbuf.data(), sz + 4u);
  
  cb += 4u; // remove the size
  
  // we got the message, now parse it.
  auto type = take_u8(cb, ec);
  if (type != SSH_FXP_VERSION)
  {
    ec.assign(SSH_FATAL, ssh_category());
    co_return {ec, {}};
  }

  auto version = take_u32(cb, ec);

  std::unordered_map<std::string, std::string> extensions;

  while (cb.size() > 0u && !ec)
  {
    auto ext_name = take_str(cb, ec);
    auto ext_value = take_str(cb, ec);
    extensions.emplace(ext_name, ext_value);
  }

  rbuf.consume(sz + 4u);
  co_return {ec, session(std::move(stream), std::move(buffer), std::move(extensions), version)};
}

template<std::size_t N>
struct small_buffer
{
  unsigned char small[N];
  std::vector<unsigned char> dynamic;

  boost::capy::mutable_buffer get(std::size_t n)
  {
    if (n <= N)
      return boost::capy::mutable_buffer(small, n);
    else
    {
      dynamic.resize(n);
      return boost::capy::make_buffer(dynamic);
    } 
  }
};


boost::capy::io_task<> session::read_one_()
{
  // we already hold the lock here
  auto buf = boost::capy::dynamic_buffer(buffer_);
  auto [ec, n] = co_await boost::capy::read_until(stream_, buf, &match_packet);
  if (ec)
  {  
    response_queue_.cancel_all(ec);
    co_return ec;
  }
    
  const std::uint32_t sz = ntohl(*reinterpret_cast<const std::uint32_t*>(buf.data().data())); 
  auto buffer = boost::capy::make_buffer(buf.data(), sz + 4u);
  buffer += 4u; // next read the request_id

  auto tp = take_u8(buffer, ec);
  auto request_id = take_u32(buffer, ec);

  if (ec)
    co_return ec;

  response_queue_.complete(request_id, tp, ec, buffer);

  buf.consume(sz + 4u);
  co_return ec;    
}



struct ssh_fxp_status_response final : detail::response
{
  ssh_fxp_status_response(std::uint32_t id) 
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    
    ec = ec_;
    if (!ec && type != SSH_FXP_STATUS)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());
    
    // 
    auto error = take_u32(payload, ec);
    if (payload.size() > 0)
    {
      message = take_str(payload, ec);
      language_tag = take_str(payload, ec);
    }
    if (!ec && error != SSH_FX_OK)
      ec.assign(error, sftp_category());

    completed = true;
  }

  bool completed = false;
  std::error_code ec;

  /* RESPONSE
     --   uint32     id // read before call to complete already
        uint32     error/status code
        string     error message (ISO-10646 UTF-8 [RFC-2279])
        string     language tag (as defined in [RFC-1766])

  */

  std::uint32_t error;
  std::string_view message;
  std::string_view language_tag;
  
};

boost::capy::io_task<> session::unlink(std::string_view filename)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);
  
  small_buffer<1024> b;
  
  /* REQUEST:
      uint8      type=SSH_FXP_REMOVE
      uint32     id
      string     filename
  */
  const auto length = 1 + 4 + (4 + filename.size());
  
  auto buf = b.get(4 + length); 
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_REMOVE, ec);
  put_u32(buf, id,             ec);
  put_str(buf, filename, ec);

  
  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return ec;
  
  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return ec;


  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return ec;

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      
      write_mutex_.unlock();

  }

  co_return response.ec;
}


/*

SSH_FXP_INIT(version)
SSH_FXP_VERSION(version)


Open:

        uint32        id
        string        filename
        uint32        pflags
        ATTRS         attrs


*/

}

