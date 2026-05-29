#pragma once

#include <corosh/channel.hpp>

#include <boost/capy/buffers.hpp>
#include <boost/capy/io_task.hpp>

#include <boost/capy/io/any_stream.hpp>
#include <boost/capy/ex/async_mutex.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/capy/io/any_read_source.hpp>
#include <boost/capy/io/any_write_sink.hpp>

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/types.h>
#include <unordered_map>

namespace corosh::sftp
{

namespace detail
{


struct response
{
  response * prev = nullptr, * next = nullptr;
  std::uint32_t request_id;
  virtual void complete(std::error_code ec, std::uint8_t type, boost::capy::const_buffer payload) = 0;
};


struct response_queue
{
  response * first = nullptr, * last = nullptr;

  std::uint32_t request_id_gen = 0u;

  response_queue() noexcept = default;
  response_queue(const response_queue& ) = delete;
  response_queue(response_queue&& rhs) noexcept
      : first(std::exchange(rhs.first, nullptr))
      , request_id_gen(rhs.request_id_gen) 
  {
  }

  response_queue& operator=(response_queue&& rhs) noexcept
  {
    cancel_all(make_error_code(std::errc::broken_pipe));
    first = std::exchange(rhs.first, nullptr);
    request_id_gen = rhs.request_id_gen;
    return *this;
  }

  ~response_queue() 
  {
    cancel_all(make_error_code(std::errc::broken_pipe));
  }

  std::uint32_t get_request_id() {return request_id_gen++;}
  void enqueue_response(response & res)
  {
    if (last == nullptr)
      first = last = &res;
    else
      last = last->next = &res;
  }

  bool complete(std::uint32_t request_id, std::uint8_t type, std::error_code ec, boost::capy::const_buffer buf)
  {
    for (auto it = first; it != nullptr; it = it->next)
    {
      if (it->request_id == request_id)
      {
        if (it->prev != nullptr)
          it->prev->next = it->next;

        it->complete(ec, type, buf);
        return true;
      }    
    }
   return false;
  }
  

  void cancel_all(std::error_code ec)
  {
    while (first != nullptr)
    {
      auto current = std::exchange(first, first->next);
      current->complete(ec, 0, {});
    }

    last = nullptr;
  }
  
};

}

struct sftp_attributs_deleter {void operator()(::sftp_attributes a) const noexcept { sftp_attributes_free(a); } };
using attributes = std::unique_ptr<std::remove_pointer_t<sftp_attributes>, sftp_attributs_deleter>;

struct file
{
  file() noexcept = default;
  file(file &&) noexcept = default;
  file & operator=(file &&) noexcept = default;

  explicit operator bool() const noexcept { return file_ != nullptr; }

  template<boost::capy::MutableBufferSequence MB>
  boost::capy::io_task<std::size_t> read_some(MB buffer);
  boost::capy::io_task<std::size_t> read_some(boost::capy::mutable_buffer buffer);


  template<boost::capy::ConstBufferSequence CB>
  boost::capy::io_task<std::size_t> write_some(CB buffer);
  boost::capy::io_task<std::size_t> write_some(boost::capy::const_buffer buffer);


  template<boost::capy::MutableBufferSequence MB>
  boost::capy::io_task<std::size_t> read_some_at(std::uint64_t offset, MB buffer);
  boost::capy::io_task<std::size_t> read_some_at(std::uint64_t offset, boost::capy::mutable_buffer buffer);


  template<boost::capy::ConstBufferSequence CB>
  boost::capy::io_task<std::size_t> write_some_at(std::uint64_t offset, CB buffer);
  boost::capy::io_task<std::size_t> write_some_at(std::uint64_t offset, boost::capy::const_buffer buffer);

  std::uint64_t seek(std::uint64_t offset);
  std::size_t size();

  boost::capy::io_task<sftp_attributes> fstat();
  boost::capy::io_task<> fsync();
  boost::capy::io_task<> close();

  boost::capy::execution_context & context();

 private:
  friend struct sftp;
  explicit file(::sftp_file f, std::shared_ptr<boost::corosio::tcp_socket> socket) noexcept : file_(f) {}

  struct deleter { void operator()(::sftp_file f) const noexcept { if (f) sftp_close(f); } };
  std::unique_ptr<std::remove_pointer_t<::sftp_file>, deleter> file_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;
};

struct sftp_dir
{
  sftp_dir() noexcept = default;
  sftp_dir(sftp_dir &&) noexcept = default;
  sftp_dir & operator=(sftp_dir &&) noexcept = default;

  explicit operator bool() const noexcept { return dir_ != nullptr; }
  
  bool eof() const { return dir_ ? sftp_dir_eof(dir_.get()) != 0 : true; }

  boost::capy::task<attributes> readdir();
  boost::capy::io_task<> close();

  boost::capy::execution_context & context();

 private:
  friend struct sftp;
  explicit sftp_dir(::sftp_dir d, std::shared_ptr<boost::corosio::tcp_socket> socket) noexcept : dir_(d) {}

  struct deleter { void operator()(::sftp_dir d) const noexcept { if (d) sftp_closedir(d); } };
  std::unique_ptr<std::remove_pointer_t<::sftp_dir>, deleter> dir_;
  std::shared_ptr<boost::corosio::tcp_socket> socket_;
};

struct session
{
  session() = default;
  explicit session (
    boost::capy::any_stream stream, 
    std::vector<unsigned char> buffer, 
    std::unordered_map<std::string, std::string> extensions,
    std::uint32_t server_version)
    : stream_(std::move(stream))
    , buffer_(std::move(buffer))
    , extensions_(std::move(extensions))
    , server_version_(server_version)
  {}
    
  
  session(session && rhs) noexcept 
    : stream_(std::move(rhs.stream_))
    , buffer_(std::move(rhs.buffer_))
    , extensions_(std::move(rhs.extensions_))
    , server_version_(rhs.server_version_) 
  {}
    
  session & operator=(session && rhs) noexcept 
  {
    stream_ = std::move(rhs.stream_);
    buffer_ = std::move(rhs.buffer_);
    extensions_ = std::move(rhs.extensions_);
    server_version_ = rhs.server_version_;
    return *this;
  }

  std::uint32_t server_version() const { return server_version_; }

  boost::capy::io_task<file>       open   (std::string_view path, int accesstype, mode_t mode);
  boost::capy::io_task<sftp_dir>   opendir(std::string_view path);

  boost::capy::io_task<sftp_attributes> stat (std::string_view path);
  boost::capy::io_task<sftp_attributes> lstat(std::string_view path);

  boost::capy::io_task<> unlink  (std::string_view path);
  boost::capy::io_task<> mkdir   (std::string_view path, mode_t mode);
  boost::capy::io_task<> rmdir   (std::string_view path);
  boost::capy::io_task<> rename  (std::string_view original, const char * newname);
  boost::capy::io_task<> chmod   (std::string_view path, mode_t mode);
  boost::capy::io_task<> chown   (std::string_view path, uid_t owner, gid_t group);
  boost::capy::io_task<> symlink (std::string_view target,  std::string_view dest);
  boost::capy::io_task<> hardlink(std::string_view oldpath, std::string_view newpath);
  boost::capy::io_task<> setstat (std::string_view path, sftp_attributes attr);

  boost::capy::io_task<std::string> readlink(std::string_view path);
  boost::capy::io_task<std::string> canonicalize_path(std::string_view path);
  boost::capy::io_task<std::string> expand_path(std::string_view path);
  boost::capy::io_task<std::string> home_directory(std::string_view username);

  const std::unordered_map<std::string, std::string> & extensions() const {return extensions_;}
  
 private:
  boost::capy::any_stream stream_;
  std::vector<unsigned char> buffer_;
  std::unordered_map<std::string, std::string> extensions_;
  detail::response_queue response_queue_;
  std::uint32_t server_version_{};

  boost::capy::async_mutex write_mutex_, read_mutex_;
  boost::capy::io_task<> read_one_();

};

boost::capy::io_task<session> init(boost::capy::any_stream stream);

}
