// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (C) 2026 Klemens Morgenstern

#include <corosh/server_options.hpp>
#include <corosh/acceptor.hpp>
#include <corosh/error.hpp>
#include <corosh/session.hpp>
#include <corosh/sftp.hpp>

#include <boost/corosio.hpp>
#include <boost/capy.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/capy/when_all.hpp>

#include <boost/capy/ex/any_executor.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/this_coro.hpp>
#include <filesystem>
#include <boost/corosio/random_access_file.hpp>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/sftp.h>
#include <libssh/callbacks.h>

#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <source_location>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace capy    = boost::capy;
namespace corosio = boost::corosio;

#ifndef COROSH_EXAMPLE_DIR
#  define COROSH_EXAMPLE_DIR "."
#endif


capy::io_task<> echo(capy::any_stream s)
{
  char buffer[4096];

  while (true)
  {
    auto res = co_await s.read_some(capy::make_buffer(buffer));
    
    if (res.ec)
    {
      co_return res.ec;
      std::cerr << "Error reading from channel: " << res.ec.message() << std::endl;
    }

    res = co_await capy::write(s, capy::make_buffer(buffer, get<1>(res)));
    if (res.ec)  
    {
      std::cerr << "Error writing to channel: " << res.ec.message() << std::endl;
      co_return res.ec;
    }
  }  
}


capy::io_task<> run_shell(corosh::channel c) 
{
  return echo(std::move(c)); 
}


struct sftp_server final  : corosh::sftp::server
{
  sftp_server() = default;

  std::size_t handle_gen = 0;
  std::filesystem::path root_path = std::filesystem::current_path();

  std::unordered_map<std::string, corosio::random_access_file> open_files;
  std::unordered_map<std::string, std::filesystem::directory_iterator> dirs;

  std::filesystem::path sftp_to_local(std::filesystem::path pt) const
  {
    return (root_path / pt.relative_path()).lexically_normal();
  }
  std::filesystem::path local_to_sftp(std::filesystem::path pt) const
  {
    return std::filesystem::path("/") / std::filesystem::relative(pt, root_path);
  }
  
  capy::io_task<std::string> open(std::string_view path, int accesstype, mode_t /*mode*/)
  {
    using flags = corosio::file_base::flags;
    auto f = static_cast<flags>(0);

    // SFTP pflags (SSH_FXF_*) and corosio flags share values for READ/WRITE/APPEND/CREAT,
    // but TRUNC and EXCL are swapped, so translate explicitly.
    if (accesstype & SSH_FXF_READ)   f |= flags::read_only;
    if (accesstype & SSH_FXF_WRITE)  f |= flags::write_only;
    if (accesstype & SSH_FXF_APPEND) f |= flags::append;
    if (accesstype & SSH_FXF_CREAT)  f |= flags::create;
    if (accesstype & SSH_FXF_TRUNC)  f |= flags::truncate;
    if (accesstype & SSH_FXF_EXCL)   f |= flags::exclusive;

    auto ex = co_await capy::this_coro::executor;
    corosio::random_access_file file(ex.context());

    try
    {
      file.open(sftp_to_local(std::filesystem::path(path)), f);
    }
    catch (const std::system_error & se)
    {
      co_return {se.code(), {}};
    }

    std::string handle = std::to_string(++handle_gen);
    open_files.emplace(handle, std::move(file));
    co_return {{}, std::move(handle)};
  }

  capy::io_task<std::size_t> read_at(std::string_view handle, std::uint64_t offset, capy::mutable_buffer buffer)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
      co_return {std::make_error_code(std::errc::bad_file_descriptor), 0u};

    auto & f = it->second;
    std::size_t total = 0u;
    while (buffer.size() > 0u)
    {
      auto [ec, n] = co_await f.read_some_at(offset + total, buffer);
      if (ec)
        co_return {ec, total};
      if (n == 0u) // EOF
        break;
      total  += n;
      buffer += n;
    }
    co_return {{}, total};
  }

  capy::io_task<std::size_t> write_at(std::string_view handle, std::uint64_t offset, capy::const_buffer buffer)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
      co_return {std::make_error_code(std::errc::bad_file_descriptor), 0u};

    auto & f = it->second;
    std::size_t total = 0u;
    while (buffer.size() > 0u)
    {
      auto [ec, n] = co_await f.write_some_at(offset + total, buffer);
      if (ec)
        co_return {ec, total};
      if (n == 0u) // guard against an unexpected zero-byte write
        co_return {std::make_error_code(std::errc::io_error), total};
      total  += n;
      buffer += n;
    }
    co_return {{}, total};
  }

  static corosh::sftp::attributes to_attributes(const struct ::stat & st)
  {
    corosh::sftp::attributes a;
    // SFTP v3 wire carries SIZE / UIDGID / PERMISSIONS / ACMODTIME (atime+mtime as u32).
    a.flags = SSH_FILEXFER_ATTR_SIZE
            | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS
            | SSH_FILEXFER_ATTR_ACMODTIME;
    a.size        = static_cast<std::uint64_t>(st.st_size);
    a.uid         = st.st_uid;
    a.gid         = st.st_gid;
    a.permissions = st.st_mode;
    a.atime       = static_cast<std::uint32_t>(st.st_atime);
    a.mtime       = static_cast<std::uint32_t>(st.st_mtime);
    return a;
  }

  capy::io_task<corosh::sftp::attributes> stat(std::string_view path)
  {
    struct ::stat st{};
    if (::stat(sftp_to_local(std::filesystem::path(path)).c_str(), &st) != 0)
      co_return {std::error_code(errno, std::generic_category()), {}};
    co_return {{}, to_attributes(st)};
  }

  capy::io_task<corosh::sftp::attributes> lstat(std::string_view path)
  {
    struct ::stat st{};
    if (::lstat(sftp_to_local(std::filesystem::path(path)).c_str(), &st) != 0)
      co_return {std::error_code(errno, std::generic_category()), {}};
    co_return {{}, to_attributes(st)};
  }

  capy::io_task<corosh::sftp::attributes> fstat(std::string_view handle)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
      co_return {std::make_error_code(std::errc::bad_file_descriptor), {}};

    struct ::stat st{};
    if (::fstat(it->second.native_handle(), &st) != 0)
      co_return {std::error_code(errno, std::generic_category()), {}};

    co_return {{}, to_attributes(st)};
  }

  capy::io_task<> fsync(std::string_view handle)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
      co_return std::make_error_code(std::errc::bad_file_descriptor);

    try
    {
      it->second.sync_all();
    }
    catch (const std::system_error & se)
    {
      co_return se.code();
    }
    co_return {};
  }

  capy::io_task<> close(std::string_view handle)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
    {
      auto id = dirs.find(std::string(handle));
      if (id ==  dirs.end())
        co_return std::make_error_code(std::errc::bad_file_descriptor);
      else
        dirs.erase(id);
    }
      
    else
      open_files.erase(it);
    co_return {};
  }

  capy::io_task<> fsetstat(std::string_view handle, const corosh::sftp::attributes & attr)
  {
    auto it = open_files.find(std::string(handle));
    if (it == open_files.end())
      co_return std::make_error_code(std::errc::bad_file_descriptor);

    const int fd = it->second.native_handle();

    if (attr.flags & SSH_FILEXFER_ATTR_SIZE)
    {
      if (::ftruncate(fd, static_cast<off_t>(attr.size)) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
      if (::fchmod(fd, static_cast<mode_t>(attr.permissions)) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      if (::fchown(fd, attr.uid, attr.gid) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      struct timespec times[2];
      times[0].tv_sec  = static_cast<time_t>(attr.atime);
      times[0].tv_nsec = 0;
      times[1].tv_sec  = static_cast<time_t>(attr.mtime);
      times[1].tv_nsec = 0;
      if (::futimens(fd, times) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    co_return {};
  }

  capy::io_task<> setstat(std::string_view path, const corosh::sftp::attributes & attr)
  {
    auto local = sftp_to_local(std::filesystem::path(path));
    const auto * cpath = local.c_str();

    if (attr.flags & SSH_FILEXFER_ATTR_SIZE)
    {
      if (::truncate(cpath, static_cast<off_t>(attr.size)) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
      if (::chmod(cpath, static_cast<mode_t>(attr.permissions)) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
    {
      if (::chown(cpath, attr.uid, attr.gid) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
      struct timespec times[2];
      times[0].tv_sec  = static_cast<time_t>(attr.atime);
      times[0].tv_nsec = 0;
      times[1].tv_sec  = static_cast<time_t>(attr.mtime);
      times[1].tv_nsec = 0;
      if (::utimensat(AT_FDCWD, cpath, times, 0) != 0)
        co_return std::error_code(errno, std::generic_category());
    }
    co_return {};
  }



  capy::io_task<std::string> opendir(std::string_view path)
  {
    std::error_code ec;
    std::filesystem::directory_iterator dit(sftp_to_local(std::filesystem::path(path)), ec);
    if (ec)
      co_return {ec, {}};

    std::string handle = "d" + std::to_string(++handle_gen);
    dirs.emplace(handle, std::move(dit));
    co_return {{}, std::move(handle)};
  }

  capy::io_task<std::vector<corosh::sftp::dir::entry>> readdir(std::string handle)
  {
    auto it = dirs.find(handle);
    if (it == dirs.end())
      co_return {std::make_error_code(std::errc::bad_file_descriptor), {}};

    auto & dit = it->second;
    std::vector<corosh::sftp::dir::entry> entries;
    constexpr std::size_t max_batch = 64u;
    std::error_code inc_ec;
    while (dit != std::filesystem::directory_iterator{} && entries.size() < max_batch)
    {
      corosh::sftp::dir::entry e;
      e.name      = dit->path().filename().string();
      e.long_name = e.name;

      struct ::stat st{};
      if (::lstat(dit->path().c_str(), &st) == 0)
        e.attr = to_attributes(st);

      entries.push_back(std::move(e));
      dit.increment(inc_ec);
      if (inc_ec)
        break;
    }

    if (entries.empty())
      co_return {capy::error::eof, {}};

    co_return {{}, std::move(entries)};
  }


  capy::io_task<std::string> readlink(std::string_view path)
  {
    std::error_code ec;
    auto target = std::filesystem::read_symlink(
        sftp_to_local(std::filesystem::path(path)), ec);
    if (ec)
      co_return {ec, {}};
    co_return {{}, target.string()};
  }

  capy::io_task<std::string> canonicalize_path(std::string_view path)
  {
    std::error_code ec;
    auto resolved = std::filesystem::weakly_canonical(
        sftp_to_local(std::filesystem::path(path)), ec);
    if (ec)
      co_return {ec, {}};
    co_return {{}, local_to_sftp(resolved).string()};
  }

  capy::io_task<std::string> expand_path(std::string_view path)
  {
    // Normalize lexically without touching the filesystem; symlinks are not resolved.
    auto p = std::filesystem::path(path).lexically_normal();
    co_return {{}, p.string()};
  }

  capy::io_task<std::string> home_directory(std::string_view /*username*/) { co_return {{}, "/"}; }


  capy::io_task<> unlink(std::string_view path)
  {
    if (::unlink(sftp_to_local(std::filesystem::path(path)).c_str()) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> mkdir(std::string_view path, mode_t mode)
  {
    if (::mkdir(sftp_to_local(std::filesystem::path(path)).c_str(), mode) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> rmdir(std::string_view path)
  {
    if (::rmdir(sftp_to_local(std::filesystem::path(path)).c_str()) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> rename(std::string_view original, std::string_view newname)
  {
    auto from = sftp_to_local(std::filesystem::path(original));
    auto to   = sftp_to_local(std::filesystem::path(newname));
    if (::rename(from.c_str(), to.c_str()) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> chmod(std::string_view path, mode_t mode)
  {
    if (::chmod(sftp_to_local(std::filesystem::path(path)).c_str(), mode) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> chown(std::string_view path, uid_t owner, gid_t group)
  {
    if (::chown(sftp_to_local(std::filesystem::path(path)).c_str(), owner, group) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> symlink(std::string_view target, std::string_view dest)
  {
    // `target` is the literal symlink content (what readlink will return).
    // Only `dest` is a real filesystem path that needs sandbox translation.
    auto link = sftp_to_local(std::filesystem::path(dest));
    std::string tgt(target);
    if (::symlink(tgt.c_str(), link.c_str()) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

  capy::io_task<> hardlink(std::string_view oldpath, std::string_view newpath)
  {
    auto from = sftp_to_local(std::filesystem::path(oldpath));
    auto to   = sftp_to_local(std::filesystem::path(newpath));
    if (::link(from.c_str(), to.c_str()) != 0)
      co_return std::error_code(errno, std::generic_category());
    co_return {};
  }

};

capy::io_task<> run_sftp(corosh::channel c) 
{
  sftp_server s;
  co_return co_await corosh::sftp::serve(&c, s);
}




struct channel_callbacks final : corosh::channel::callbacks
{
  corosio::timer timeout;

  static capy::io_task<> on_timeout(corosh::channel) {co_return std::make_error_code(std::errc::timed_out);}
  static capy::io_task<> on_closed(corosh::channel) {co_return std::make_error_code(std::errc::broken_pipe);}
  capy::io_task<> (*work)(corosh::channel) = &on_timeout;
  
  channel_callbacks(capy::execution_context & ctx) : timeout(ctx) {}

  /*void signal(const char *signal);
  void exit_status(int exit_status);
  void exit_signal(const char *signal, int core,
                           const char *errmsg, const char *lang);
  void x11_req(int single_connection, const char *auth_protocol,
                       const char *auth_cookie, std::uint32_t screen_number);
*/
  void close()
  {
    std::cout << "Closed " << std::endl;
    timeout.cancel();
    work = &on_closed;  
  }

  bool pty_request(const char *term, int width, int height,
                           int pxwidth, int pwheight) { return false; }
  bool pty_window_change(int width, int height, int pxwidth, int pwheight) {return false; }
  bool shell_request() 
  {
    timeout.cancel();
    work = &run_shell;
  
    std::cout << "Shell request " << std::endl;
    return true ; 
  }
  bool exec_request(const char *command)
  {
    std::cout << "Exec request " << std::endl;
    
    timeout.cancel();
    if (command == std::string_view("echo"))
    {
      work = &run_shell;
      return true;
    }
    else
      return false;
  }
  bool env_request(const char *env_name, const char *env_value)
  {
    std::cout << "Received env request: "  << env_name << '=' << env_value << std::endl;
    return true;
  }
  bool subsystem_request(const char *subsystem)
  {
    if (subsystem == std::string_view("sftp"))
    {
      work =  &run_sftp;
      return true;
    }
    else
      return false;
  }

};


struct tracked_work
{
  capy::async_event event;
  std::size_t working = 0u;

  tracked_work() = default;

  struct work
  {
    tracked_work & j;
    work(tracked_work & j) : j(j)
    {
      j.working++;
    }
    work(const work& w) : work(w.j) {}
    ~work()
    {
      j.complete();
    }
  };

  work track() {return work(*this); }

  void complete() 
  {
    working --;
    event.set();
  }

  capy::io_task<> wait()
  {
    while (working > 0U)
    {
      auto [ec] = co_await event.wait();
      if (ec)
        co_return ec;
      event.clear();
    }
    co_return {};
  }
  
};

capy::io_task<> wait_for_channel_request(corosh::channel ch, tracked_work::work)
{
  auto cc = std::make_unique<channel_callbacks>((co_await capy::this_coro::executor).context());
  ch.add_callbacks(*cc);
  
  cc->timeout.expires_after(std::chrono::seconds(1));
  std::ignore = co_await cc->timeout.wait();

  auto w = cc->work;

  cc.reset();
  co_return co_await w(std::move(ch));
}

struct server_callbacks final : corosh::session::server_callbacks
{
  corosh::session & s;
  capy::any_executor ex;
  std::stop_token st;
  tracked_work w;
  
  server_callbacks(corosh::session & s, capy::any_executor ex, std::stop_token st) : s(s), ex(ex), st(st) {}

  bool        service_request(const char * service) final
  {
    std::cout << "Service request : " << service << std::endl;
    return true;
  }

  ssh_auth_e auth_password(const char * user, const char * password)
  {
    std::cout << "User '" << user << "' authenticating via passowrd, accepting pw unseen" << std::endl;
    return SSH_AUTH_SUCCESS;
  }
  ssh_auth_e auth_none(const char * user)
  {
    std::cout << "User '" << user << "' authenticating with no auth, accepting" << std::endl;
    return SSH_AUTH_SUCCESS;
  }
  ssh_auth_e auth_pubkey(const char * user, ssh_key pubkey,
                                 char signature_state)
  {
    std::cout << "User '" << user << "' authenticating via pubkey, accepting key unseen" << std::endl;
    return SSH_AUTH_SUCCESS;
  }

  ssh_channel channel_open_request_session()
  {
    corosh::channel c(s);
    auto h = c.native_handle();
    capy::run_async(ex, st)(wait_for_channel_request(std::move(c), w.track()));
    return h;
  }

  
};


capy::task<int> ssh_main()
try
{
  auto ex = co_await capy::this_coro::executor;
  corosh::acceptor acc{ex.context()};

  
  acc.set_option(corosh::server_options::host_key(
      (std::filesystem::path(std::source_location::current().file_name()).parent_path() / "host_key").c_str()
    ));
    
  acc.open();
  if (auto ec = acc.bind(corosio::endpoint(8080)); ec)
  { 
    std::cerr << "bind: "   << ec.message() << "\n"; 
    co_return 1; 
  }
  if (auto ec = acc.listen(); ec)
  { 
    std::cerr << "listen: " << ec.message() << "\n"; 
    co_return 1; 
  }

  std::cout << "[server] listening on :8080\n";


  corosh::session s{ex.context()};

  s.set_option(corosh::options::log_verbosity(SSH_LOG_TRACE));
  
  if (auto [ec] = co_await acc.accept(s); ec)
  {
    std::cerr << "Failed accepting " << ec.message() << std::endl;
    co_return 1;
  }

  if (auto [ec] = co_await s.handle_key_exchange(); ec)
  {
    std::cerr << "kex failed " << ec.message() << std::endl;
    co_return 1;
  }


  std::cout << "[Server] kex is done " << std::endl;

  std::stop_source ss;
  

  auto scb = std::make_unique<server_callbacks>(
          s, 
          co_await capy::this_coro::executor,
          ss.get_token());
  
  auto & work = scb->w;
  s.install_server_callbacks(std::move(scb));

  


  while (s.is_open())
  {
    std::cout << "Get message" << std::endl;
    auto me = co_await s.get_message();  
    auto & [ec, msg] = me;

    if (ec)
    {
      std::cerr << "Get message error: " << ec.message() << std::endl;
      // this needs to wait for the channels, so session doesn't go out of scope before channel
     error:
      ss.request_stop();
      std::ignore = co_await work.wait();
      std::cerr << "Exiting with error" << std::endl;
      co_return 1;
    }

    switch (msg.type())
    {
      case SSH_REQUEST_AUTH:
        std::cout << "Requested auth" << std::endl;
        break;
      case SSH_REQUEST_CHANNEL:
        std::cout << "Requested channel" << std::endl;
        
        break;
      case SSH_REQUEST_SERVICE:
        if (msg.service() == std::string_view("ssh-userauth"))
        {
          auto [ec] = co_await msg.service_reply_success();
          if (ec)
          {
            std::cerr << "service reply error " << ec.message() <<std::endl;
            goto error;;
          }
        }
        else
        {
          auto [ec] = co_await msg.reply_default();
          if (ec)
          {
            std::cerr << "service reply error " << ec.message() <<std::endl;
            goto error;
          } 
        }
        std::cout << "Requested service: " << msg.service() << std::endl;
        break;
      case SSH_REQUEST_CHANNEL_OPEN:
        std::cout << "Request channel open" << std::endl;
        break;
      case SSH_REQUEST_GLOBAL:
        std::cout << "Request global " << msg.global_request_address() <<  " : " << msg.global_request_port() << std::endl;
        break;
    }
  }
  
  co_return 0;
}
catch (std::exception & ex)
{
  std::cerr << "exception: " << ex.what() << "\n";
  co_return 1;
}

int main()
{
  corosio::io_context ctx;
  int res = -1;
  capy::run_async(
      ctx.get_executor(),
      [&](int r) { res = r; })(ssh_main());

  ctx.run();

  std::cout << "Ran test server\n";
  return res;
}
