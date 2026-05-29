#include "corosh/error.hpp"
#include <corosh/session.hpp>
#include <corosh/sftp.hpp>

#include <boost/corosio.hpp>
#include <boost/capy.hpp>

#include <boost/corosio/endpoint.hpp>
#include <libssh/libssh.h>

#include <iostream>
#include <sys/types.h>
#include <unistd.h>


namespace capy  = boost::capy;

capy::task<int> ssh_main()
try {

  int verbosity = SSH_LOG_PROTOCOL;
  int port = 22;

  corosh::session ses{co_await capy::this_coro::executor};

  ses.set_option(corosh::options::host("localhost"));
  ses.set_option(corosh::options::log_verbosity(SSH_LOG_TRACE));
  ses.set_option(corosh::options::port(22));
  ses.set_option(corosh::options::user("klemens"));
  

  if (auto [ec] = co_await ses.connect(
      boost::corosio::endpoint(
        boost::corosio::ipv4_address::loopback(), 22)
        ); ec)
  {
    std::cerr << "Error connecting: " << ec << " : " << ec.message() << std::endl; 
    co_return ec ? 1 : 0;
  }
    
  {
    auto res = co_await ses.userauth_none();
    const auto & [ec, r] = res;
    const auto md = ses.userauth_list();

    if (!ec && r == SSH_AUTH_DENIED && (md & SSH_AUTH_METHOD_PUBLICKEY))
      res = co_await ses.userauth_publickey_auto(nullptr);

    if (!ec && r == SSH_AUTH_DENIED && (md & SSH_AUTH_METHOD_PASSWORD))
    {
      std::cout << "Enter password : ";
      auto pw = getpass("get ssh password: ");
      res = co_await ses.userauth_password(pw);
    }
  }

  {
    corosh::channel c(ses);
    if (auto [ec] = co_await c.open_session(); ec)
    {
      std::cerr << "Error opening session: " << ec << " : " << ec.message() << std::endl; 
      co_return ec ? 1 : 0;
    }

    if (auto [ec] = co_await c.request_sftp(); ec)
    {
      std::cerr << "Error requesting exec: " << ec << " : " << ec.message() << std::endl; 
      co_return ec ? 1 : 0;
    }    

    auto [ec, s] = co_await corosh::sftp::init(std::move(c));

    if (ec)
    {
      std::cerr << "Error initializing sftp: " << ec << " : " << ec.message() << std::endl; 
      co_return ec ? 1 : 0;
    }

    auto [ec_h, h] = co_await s.home_directory("klemens");
    if (ec_h)
    {
      std::cerr << "Error getting home directory sftp: " << ec_h << " : " << ec.message() << std::endl; 
      co_return ec_h ? 1 : 0;
    }

    std::cout << "Home folder: " << h << std::endl;

    auto [ec_dir, dir_it] = co_await s.opendir(h);
    if (ec_dir)
    {
      std::cerr << "opendir failed: " << ec_dir << std::endl;
      co_return 1;
    }

    while (true)
    {
      auto [ec, e] = co_await dir_it.read();
      auto [attr, name, long_name] = e;
      if (ec)
      {
        if (ec != std::error_code(SSH_FX_EOF, corosh::sftp_category()))
          std::cerr << "Error reading directory: " << ec.message() << std::endl;
        break;
      }

      std::cout << name << " :: " << long_name << std::endl;      
    }

    std::ignore = co_await dir_it.close();

    auto [ec_f, f] = co_await s.open(h + "/.bash_history", SSH_FXF_READ, 0);
    if (ec_f)
    {
      std::cerr << "open failed [" << h << "]: " << ec_f  << " - " << ec_f.message() << std::endl;
      co_return 1;
    }

    char buffer[256];

    auto [ecr, r] = co_await f.read_some_at(0, boost::capy::make_buffer(buffer));

    if (ecr)
      std::cerr << "read failed :" << ecr  << " - " << ecr.message() << std::endl;
    else
      std::cout << std::string_view(buffer, r) << std::endl;

    std::ignore = co_await f.close();
  }
  co_return 0;  
}
catch (std::exception & e)
{
  std::cerr << "Exception " << e.what() << std::endl;
  co_return 1;
}

int main() 
{
  boost::corosio::io_context ctx;
  int res = -1;
  boost::capy::run_async(
      ctx.get_executor(),
      [&](int r) {res = r;})(ssh_main());
    
  ctx.run();

  std::cout << "Ran test client"  << std::endl; 

  return res;
}
