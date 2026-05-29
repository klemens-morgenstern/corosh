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


std::uint64_t take_u64(boost::capy::const_buffer & buf, std::error_code & ec)
{
  if (!ec && buf.size() < 8u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return {};

  std::uint32_t hi, lo;
  std::memcpy(&hi, buf.data(),                                  4);
  std::memcpy(&lo, static_cast<const unsigned char *>(buf.data()) + 4, 4);
  buf += 8u;
  return (static_cast<std::uint64_t>(ntohl(hi)) << 32) | ntohl(lo);
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

void put_u64(boost::capy::mutable_buffer & buf, std::uint64_t value, std::error_code & ec)
{
  if (!ec && buf.size() < 8u)
    ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

  if (ec)
    return;

  const std::uint32_t hi = htonl(static_cast<std::uint32_t>(value >> 32));
  const std::uint32_t lo = htonl(static_cast<std::uint32_t>(value & 0xFFFFFFFFu));
  std::memcpy(buf.data(),                                  &hi, 4);
  std::memcpy(static_cast<unsigned char *>(buf.data()) + 4, &lo, 4);
  buf += 8u;
}

std::size_t attrs_length(const attributes & attr)
{
  std::size_t n = 4u; // flags
  if (attr.flags & SSH_FILEXFER_ATTR_SIZE)        n += 8u;
  if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)      n += 8u;
  if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS) n += 4u;
  if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)   n += 8u;
  return n;
}

void put_attrs(boost::capy::mutable_buffer & buf, const attributes & attr, std::error_code & ec)
{
  put_u32(buf, attr.flags, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_SIZE)
    put_u64(buf, attr.size, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
  {
    put_u32(buf, attr.uid, ec);
    put_u32(buf, attr.gid, ec);
  }
  if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    put_u32(buf, attr.permissions, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
  {
    put_u32(buf, attr.atime, ec);
    put_u32(buf, attr.mtime, ec);
  }
}


attributes take_attrs(boost::capy::const_buffer & buf, std::error_code & ec)
{
  attributes attr;
  attr.flags = take_u32(buf, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_SIZE)
    attr.size = take_u64(buf, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
  {
    attr.uid = take_u32(buf, ec);
    attr.gid = take_u32(buf, ec);
  }
  if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    attr.permissions = take_u32(buf, ec);
  if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
  {
    attr.atime = take_u32(buf, ec);
    attr.mtime = take_u32(buf, ec);
  }
  if (attr.flags & SSH_FILEXFER_ATTR_EXTENDED)
  {
    auto count = take_u32(buf, ec);
    for (std::uint32_t i = 0; !ec && i < count; ++i)
    {
      (void)take_str(buf, ec); // extended-type
      (void)take_str(buf, ec); // extended-data
    }
  }
  return attr;
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


boost::capy::io_task<> session::mkdir(std::string_view path, mode_t mode)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_MKDIR
      uint32     id
      string     path
      ATTRS      attrs  (flags=PERMISSIONS, permissions=mode)
  */
  const auto attrs_len = 4u + 4u; // flags + permissions
  const auto length    = 1 + 4 + (4 + path.size()) + attrs_len;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,                            ec);
  put_u8 (buf, SSH_FXP_MKDIR,                     ec);
  put_u32(buf, id,                                ec);
  put_str(buf, path,                              ec);
  put_u32(buf, SSH_FILEXFER_ATTR_PERMISSIONS,     ec);
  put_u32(buf, static_cast<std::uint32_t>(mode),  ec);

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


boost::capy::io_task<> session::rmdir(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_RMDIR
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_RMDIR,  ec);
  put_u32(buf, id,             ec);
  put_str(buf, path,           ec);

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


boost::capy::io_task<> session::rename(std::string_view oldpath, std::string_view newpath)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_RENAME
      uint32     id
      string     oldpath
      string     newpath
  */
  const auto length = 1 + 4 + (4 + oldpath.size()) + (4 + newpath.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,          ec);
  put_u8 (buf, SSH_FXP_RENAME,  ec);
  put_u32(buf, id,              ec);
  put_str(buf, oldpath,         ec);
  put_str(buf, newpath,         ec);

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


boost::capy::io_task<> session::chmod(std::string_view path, mode_t mode)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_SETSTAT
      uint32     id
      string     path
      ATTRS      attrs  (flags=PERMISSIONS, permissions=mode)
  */
  const auto attrs_len = 4u + 4u;
  const auto length    = 1 + 4 + (4 + path.size()) + attrs_len;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,                            ec);
  put_u8 (buf, SSH_FXP_SETSTAT,                   ec);
  put_u32(buf, id,                                ec);
  put_str(buf, path,                              ec);
  put_u32(buf, SSH_FILEXFER_ATTR_PERMISSIONS,     ec);
  put_u32(buf, static_cast<std::uint32_t>(mode),  ec);

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


boost::capy::io_task<> session::chown(std::string_view path, uid_t owner, gid_t group)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_SETSTAT
      uint32     id
      string     path
      ATTRS      attrs  (flags=UIDGID, uid, gid)
  */
  const auto attrs_len = 4u + 4u + 4u;
  const auto length    = 1 + 4 + (4 + path.size()) + attrs_len;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,                             ec);
  put_u8 (buf, SSH_FXP_SETSTAT,                    ec);
  put_u32(buf, id,                                 ec);
  put_str(buf, path,                               ec);
  put_u32(buf, SSH_FILEXFER_ATTR_UIDGID,           ec);
  put_u32(buf, static_cast<std::uint32_t>(owner),  ec);
  put_u32(buf, static_cast<std::uint32_t>(group),  ec);

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


boost::capy::io_task<> session::symlink(std::string_view target, std::string_view dest)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_SYMLINK
      uint32     id
      string     targetpath  // OpenSSH-server expects target first, then link
      string     linkpath    // (the spec reverses these; OpenSSH wins de-facto)
  */
  const auto length = 1 + 4 + (4 + target.size()) + (4 + dest.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_SYMLINK,  ec);
  put_u32(buf, id,               ec);
  put_str(buf, target,           ec);
  put_str(buf, dest,             ec);

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


boost::capy::io_task<> session::hardlink(std::string_view oldpath, std::string_view newpath)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST (OpenSSH extension):
      uint8      type=SSH_FXP_EXTENDED
      uint32     id
      string     "hardlink@openssh.com"
      string     oldpath
      string     newpath
  */
  constexpr std::string_view ext_name = "hardlink@openssh.com";
  const auto length = 1 + 4 + (4 + ext_name.size())
                            + (4 + oldpath.size())
                            + (4 + newpath.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,            ec);
  put_u8 (buf, SSH_FXP_EXTENDED,  ec);
  put_u32(buf, id,                ec);
  put_str(buf, ext_name,          ec);
  put_str(buf, oldpath,           ec);
  put_str(buf, newpath,           ec);

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


boost::capy::io_task<> session::setstat(std::string_view path, const attributes & attr)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_SETSTAT
      uint32     id
      string     path
      ATTRS      attrs
  */
  const auto attrs_len = attrs_length(attr);
  const auto length    = 1 + 4 + (4 + path.size()) + attrs_len;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32  (buf, length,          ec);
  put_u8   (buf, SSH_FXP_SETSTAT, ec);
  put_u32  (buf, id,              ec);
  put_str  (buf, path,            ec);
  put_attrs(buf, attr,            ec);

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

struct ssh_fxp_handle_response final : detail::response
{
  ssh_fxp_handle_response(std::uint32_t id)
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    ec = ec_;

    if (!ec && type == SSH_FXP_STATUS)
    {
      auto error = take_u32(payload, ec);
      if (!ec && error != SSH_FX_OK)
        ec.assign(error, sftp_category());
      completed = true;
      return;
    }

    if (!ec && type != SSH_FXP_HANDLE)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

    if (!ec)
    {
      auto h = take_str(payload, ec);
      if (!ec)
        handle.assign(h.begin(), h.end());
    }

    completed = true;
  }

  bool          completed = false;
  std::error_code ec;
  std::string   handle;
};


boost::capy::io_task<dir> session::opendir(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_handle_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_OPENDIR
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_OPENDIR,  ec);
  put_u32(buf, id,               ec);
  put_str(buf, path,             ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, dir{}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, dir{}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, dir{}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  if (response.ec)
    co_return {response.ec, dir{}};

  co_return {{}, dir(this, std::move(response.handle))};
}


boost::capy::io_task<file> session::open(std::string_view path, int accesstype, mode_t mode)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_handle_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_OPEN
      uint32     id
      string     filename
      uint32     pflags
      ATTRS      attrs (PERMISSIONS=mode)
  */
  const auto attrs_len = 4u + 4u; // flags + permissions
  const auto length    = 1 + 4 + (4 + path.size()) + 4 + attrs_len;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,                                  ec);
  put_u8 (buf, SSH_FXP_OPEN,                            ec);
  put_u32(buf, id,                                      ec);
  put_str(buf, path,                                    ec);
  put_u32(buf, static_cast<std::uint32_t>(accesstype),  ec);
  put_u32(buf, SSH_FILEXFER_ATTR_PERMISSIONS,           ec);
  put_u32(buf, static_cast<std::uint32_t>(mode),        ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, file{}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, file{}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, file{}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  if (response.ec)
    co_return {response.ec, file{}};

  co_return {{}, file(this, std::move(response.handle))};
}


struct ssh_fxp_dir_entry_response final : detail::response
{
  ssh_fxp_dir_entry_response(std::uint32_t id, std::vector<dir::entry> & entries_) : entries_(entries_)
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    ec = ec_;

    // SSH_FX_EOF on a directory iteration is the normal end signal.
    if (!ec && type == SSH_FXP_STATUS)
    {
      auto error = take_u32(payload, ec);
      if (!ec && error != SSH_FX_OK)
        ec.assign(error, sftp_category());
      completed = true;
      return;
    }

    if (!ec && type != SSH_FXP_NAME)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

    if (!ec)
    {
      auto count = take_u32(payload, ec);
      if (!ec && count == 0u)
        ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

      while (!ec && count > 0)
      {
        auto fn = take_str(payload, ec);
        auto ln = take_str(payload, ec);
        auto at = take_attrs(payload, ec);
        if (ec)
          break;

        entries_.push_back(
          dir::entry{
            std::move(at),
            std::string(fn),
            std::string(ln)
          });
        
        count --;
      }
    }

    completed = true;
  }

  bool            completed = false;
  std::error_code ec;
  std::vector<dir::entry> & entries_;
};


boost::capy::io_task<> dir::do_read_()
{
  auto id = sess_->response_queue_.get_request_id();

  ssh_fxp_dir_entry_response response(id, buffer_);
  sess_->response_queue_.enqueue_response(response);

  small_buffer<1024> b;
  /* REQUEST:
      uint8      type=SSH_FXP_READDIR
      uint32     id
      string     handle
  */
  const auto length = 1 + 4 + (4 + handle_.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_READDIR,  ec);
  put_u32(buf, id,               ec);
  put_str(buf, handle_,          ec);

  ec = (co_await sess_->read_mutex_.lock()).ec;
  if (ec)
    co_return ec;

  ec = (co_await boost::capy::write(sess_->stream_, to_write)).ec;
  sess_->read_mutex_.unlock();
  if (ec)
    co_return ec;

  while (!ec && !response.completed)
  {
      ec = (co_await sess_->write_mutex_.lock()).ec;
      if (ec)
        co_return ec;

      if (!response.completed)
        ec = (co_await sess_->read_one_()).ec;

      sess_->write_mutex_.unlock();
  }

  co_return {response.ec};
}


boost::capy::io_task<> dir::close()
{
  if (!sess_)
    co_return {};

  auto id = sess_->response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  sess_->response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_CLOSE
      uint32     id
      string     handle
  */
  const auto length = 1 + 4 + (4 + handle_.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_CLOSE,  ec);
  put_u32(buf, id,             ec);
  put_str(buf, handle_,        ec);

  ec = (co_await sess_->read_mutex_.lock()).ec;
  if (ec)
    co_return ec;

  ec = (co_await boost::capy::write(sess_->stream_, to_write)).ec;
  sess_->read_mutex_.unlock();
  if (ec)
    co_return ec;

  while (!ec && !response.completed)
  {
      ec = (co_await sess_->write_mutex_.lock()).ec;
      if (ec)
        co_return ec;

      if (!response.completed)
        ec = (co_await sess_->read_one_()).ec;

      sess_->write_mutex_.unlock();
  }

  // After close completes (or fails), the handle is no longer valid.
  sess_   = nullptr;
  handle_.clear();

  co_return response.ec;
}


boost::capy::io_task<> file::close()
{
  if (!sess_)
    co_return {};

  auto id = sess_->response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  sess_->response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_CLOSE
      uint32     id
      string     handle
  */
  const auto length = 1 + 4 + (4 + handle_.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_CLOSE,  ec);
  put_u32(buf, id,             ec);
  put_str(buf, handle_,        ec);

  ec = (co_await sess_->read_mutex_.lock()).ec;
  if (ec)
    co_return ec;

  ec = (co_await boost::capy::write(sess_->stream_, to_write)).ec;
  sess_->read_mutex_.unlock();
  if (ec)
    co_return ec;

  while (!ec && !response.completed)
  {
      ec = (co_await sess_->write_mutex_.lock()).ec;
      if (ec)
        co_return ec;

      if (!response.completed)
        ec = (co_await sess_->read_one_()).ec;

      sess_->write_mutex_.unlock();
  }

  // After close completes (or fails), the handle is no longer valid.
  sess_   = nullptr;
  handle_.clear();

  co_return response.ec;
}


struct ssh_fxp_data_response final : detail::response
{
  ssh_fxp_data_response(std::uint32_t id, boost::capy::mutable_buffer dest_)
    : dest(dest_)
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    ec = ec_;

    // SSH_FX_EOF is the normal end-of-file marker for read.
    if (!ec && type == SSH_FXP_STATUS)
    {
      auto error = take_u32(payload, ec);
      if (!ec)
      {
        if (error == SSH_FX_EOF)
          ec = boost::capy::error::eof;
        else if (error != SSH_FX_OK)
          ec.assign(error, sftp_category());
      }
      completed = true;
      return;
    }

    if (!ec && type != SSH_FXP_DATA)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

    if (!ec)
    {
      auto data = take_str(payload, ec);
      if (!ec)
      {
        n = std::min(data.size(), dest.size());
        std::memcpy(dest.data(), data.data(), n);
      }
    }

    completed = true;
  }

  bool                          completed = false;
  std::error_code               ec;
  boost::capy::mutable_buffer   dest;
  std::size_t                   n = 0u;
};


boost::capy::io_task<std::size_t> file::read_some_at(std::uint64_t offset, boost::capy::mutable_buffer buffer)
{
  auto id = sess_->response_queue_.get_request_id();

  ssh_fxp_data_response response(id, buffer);
  sess_->response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_READ
      uint32     id
      string     handle
      uint64     offset
      uint32     len
  */
  const auto length = 1 + 4 + (4 + handle_.size()) + 8 + 4;

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,                                   ec);
  put_u8 (buf, SSH_FXP_READ,                             ec);
  put_u32(buf, id,                                       ec);
  put_str(buf, handle_,                                  ec);
  put_u64(buf, offset,                                   ec);
  put_u32(buf, static_cast<std::uint32_t>(buffer.size()), ec);

  ec = (co_await sess_->read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, 0u};

  ec = (co_await boost::capy::write(sess_->stream_, to_write)).ec;
  sess_->read_mutex_.unlock();
  if (ec)
    co_return {ec, 0u};

  while (!ec && !response.completed)
  {
      ec = (co_await sess_->write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, 0u};

      if (!response.completed)
        ec = (co_await sess_->read_one_()).ec;

      sess_->write_mutex_.unlock();
  }

  co_return {response.ec, response.n};
}


boost::capy::io_task<std::size_t> file::write_some_at(std::uint64_t offset, boost::capy::const_buffer buffer)
{
  auto id = sess_->response_queue_.get_request_id();

  ssh_fxp_status_response response(id);
  sess_->response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_WRITE
      uint32     id
      string     handle
      uint64     offset
      string     data
  */
  const auto length = 1 + 4 + (4 + handle_.size()) + 8 + (4 + buffer.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_WRITE,  ec);
  put_u32(buf, id,             ec);
  put_str(buf, handle_,        ec);
  put_u64(buf, offset,         ec);
  put_str(buf,
          std::string_view{static_cast<const char *>(buffer.data()), buffer.size()},
          ec);

  ec = (co_await sess_->read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, 0u};

  ec = (co_await boost::capy::write(sess_->stream_, to_write)).ec;
  sess_->read_mutex_.unlock();
  if (ec)
    co_return {ec, 0u};

  while (!ec && !response.completed)
  {
      ec = (co_await sess_->write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, 0u};

      if (!response.completed)
        ec = (co_await sess_->read_one_()).ec;

      sess_->write_mutex_.unlock();
  }

  // SFTP WRITE is all-or-nothing: success means every byte landed.
  co_return {response.ec, response.ec ? std::size_t{0u} : buffer.size()};
}


struct ssh_fxp_attrs_response final : detail::response
{
  ssh_fxp_attrs_response(std::uint32_t id)
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    ec = ec_;

    if (!ec && type == SSH_FXP_STATUS)
    {
      auto error = take_u32(payload, ec);
      if (!ec && error != SSH_FX_OK)
        ec.assign(error, sftp_category());
      completed = true;
      return;
    }

    if (!ec && type != SSH_FXP_ATTRS)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

    if (!ec)
      attr = take_attrs(payload, ec);

    completed = true;
  }

  bool         completed = false;
  std::error_code ec;
  attributes   attr;
};


boost::capy::io_task<attributes> session::stat(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_attrs_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_STAT
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,        ec);
  put_u8 (buf, SSH_FXP_STAT,  ec);
  put_u32(buf, id,            ec);
  put_str(buf, path,          ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.attr)};
}


boost::capy::io_task<attributes> session::lstat(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_attrs_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_LSTAT
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,         ec);
  put_u8 (buf, SSH_FXP_LSTAT,  ec);
  put_u32(buf, id,             ec);
  put_str(buf, path,           ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.attr)};
}


struct ssh_fxp_name_response final : detail::response
{
  ssh_fxp_name_response(std::uint32_t id)
  {
      this->request_id = id;
  }

  void complete(std::error_code ec_, std::uint8_t type, boost::capy::const_buffer payload)
  {
    ec = ec_;

    // SFTP servers return SSH_FXP_STATUS on error even for NAME-returning ops.
    if (!ec && type == SSH_FXP_STATUS)
    {
      auto error = take_u32(payload, ec);
      if (!ec && error != SSH_FX_OK)
        ec.assign(error, sftp_category());
      completed = true;
      return;
    }

    if (!ec && type != SSH_FXP_NAME && type != SSH_FXP_EXTENDED_REPLY)
      ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());

    if (!ec)
    {
      if (type == SSH_FXP_NAME)
      {
        // count followed by N triples of (filename, longname, attrs); we only
        // need the first filename. Caller copies into std::string before
        // payload is invalidated by buf.consume.
        auto count = take_u32(payload, ec);
        if (!ec && count == 0u)
          ec.assign(SSH_FX_BAD_MESSAGE, sftp_category());
        auto fn = take_str(payload, ec);
        if (!ec)
          name.assign(fn);
      }
      else // SSH_FXP_EXTENDED_REPLY: payload is just one string
      {
        auto fn = take_str(payload, ec);
        if (!ec)
          name.assign(fn);
      }
    }

    completed = true;
  }

  bool          completed = false;
  std::error_code ec;
  std::string   name;
};


boost::capy::io_task<std::string> session::readlink(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_name_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_READLINK
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_READLINK, ec);
  put_u32(buf, id,               ec);
  put_str(buf, path,             ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.name)};
}


boost::capy::io_task<std::string> session::canonicalize_path(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_name_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST:
      uint8      type=SSH_FXP_REALPATH
      uint32     id
      string     path
  */
  const auto length = 1 + 4 + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_REALPATH, ec);
  put_u32(buf, id,               ec);
  put_str(buf, path,             ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.name)};
}


boost::capy::io_task<std::string> session::expand_path(std::string_view path)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_name_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST (OpenSSH extension):
      uint8      type=SSH_FXP_EXTENDED
      uint32     id
      string     "expand-path@openssh.com"
      string     path
     Response is SSH_FXP_NAME with a single name (per OpenSSH PROTOCOL).
  */
  constexpr std::string_view ext_name = "expand-path@openssh.com";
  const auto length = 1 + 4 + (4 + ext_name.size())
                            + (4 + path.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_EXTENDED, ec);
  put_u32(buf, id,               ec);
  put_str(buf, ext_name,         ec);
  put_str(buf, path,             ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.name)};
}


boost::capy::io_task<std::string> session::home_directory(std::string_view username)
{
  auto id = response_queue_.get_request_id();

  ssh_fxp_name_response response(id);
  response_queue_.enqueue_response(response);

  small_buffer<1024> b;

  /* REQUEST (OpenSSH extension):
      uint8      type=SSH_FXP_EXTENDED
      uint32     id
      string     "home-directory"
      string     username   (empty = current user)
     Response is SSH_FXP_NAME with a single name.
  */
  constexpr std::string_view ext_name = "home-directory";
  const auto length = 1 + 4 + (4 + ext_name.size())
                            + (4 + username.size());

  auto buf = b.get(4 + length);
  boost::capy::const_buffer to_write = buf;

  std::error_code ec;

  put_u32(buf, length,           ec);
  put_u8 (buf, SSH_FXP_EXTENDED, ec);
  put_u32(buf, id,               ec);
  put_str(buf, ext_name,         ec);
  put_str(buf, username,         ec);

  ec = (co_await read_mutex_.lock()).ec;
  if (ec)
    co_return {ec, {}};

  ec = (co_await boost::capy::write(stream_, to_write)).ec;
  read_mutex_.unlock();
  if (ec)
    co_return {ec, {}};

  while (!ec && !response.completed)
  {
      ec = (co_await write_mutex_.lock()).ec;
      if (ec)
        co_return {ec, {}};

      if (!response.completed)
        ec = (co_await read_one_()).ec;

      write_mutex_.unlock();
  }

  co_return {response.ec, std::move(response.name)};
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

