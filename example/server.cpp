#include <corosh/acceptor.hpp>
#include <corosh/error.hpp>
#include <corosh/session.hpp>

#include <boost/corosio.hpp>
#include <boost/capy.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/capy/when_all.hpp>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/sftp.h>
#include <libssh/callbacks.h>

#include <iostream>
#include <string_view>
#include <unistd.h>

namespace capy    = boost::capy;
namespace corosio = boost::corosio;

#ifndef COROSH_EXAMPLE_DIR
#  define COROSH_EXAMPLE_DIR "."
#endif


struct channel_callbacks
{
  channel_callbacks() 
  {
    ssh_callbacks_init(&impl_);
  }
   channel_callbacks(const channel_callbacks & ) = delete;
private:
  ssh_channel_callbacks_struct impl_;
};


capy::task<int> ssh_main()
try
{
  auto ex = co_await capy::this_coro::executor;
  corosh::acceptor acc{ex.context()};
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
  
  if (auto [ec] = co_await acc.accept(s); ec)
  {
    std::cerr << "Failed accepting " << ec.message() << std::endl;
  }

  if (auto [ec] = co_await s.server_init_kex(); ec)
  {
    std::cerr << "kex failed " << ec.message() << std::endl;
  }


  std::cout << "[Server] kex is done" << std::endl;

  
  
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
