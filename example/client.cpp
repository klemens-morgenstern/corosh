#include <corosh/session.hpp>

#include <boost/corosio.hpp>
#include <boost/capy.hpp>

#include <libs/corosio/include/boost/corosio/endpoint.hpp>
#include <libssh/libssh.h>

#include <iostream>
#include <unistd.h>


namespace capy  = boost::capy;

capy::task<int> ssh_main()
try {

  int verbosity = SSH_LOG_PROTOCOL;
  int port = 22;

  corosh::session ses{co_await capy::this_coro::executor};

  ses.set_option(corosh::options::host("localhost"));
  ses.set_option(corosh::options::log_verbosity(SSH_LOG_PACKET));
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

    if (auto [ec] = co_await c.request_exec("ls"); ec)
    {
      std::cerr << "Error requesting exec: " << ec << " : " << ec.message() << std::endl; 
      co_return ec ? 1 : 0;
    }    

    std::string buffer;
    buffer.resize(4096);
    auto res = co_await c.read(boost::capy::make_buffer(buffer));
    const auto & [ec, n] = res;
    printf("N %ld\n", n);
    std::string_view s{buffer.data(), n};
    std::cout << "Input: '" << s << "'" << std::endl;
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

  std::cout << "Ran "  << std::endl; 

  return res;
}
