#include <corosh/error.hpp>



namespace corosh
{

struct ssh_category_t final : std::error_category
{
  ssh_category_t() = default;

  std::string message( int ev ) const override
  {
    switch (ev)
    {
      case SSH_NO_ERROR:       return "no error";
      case SSH_REQUEST_DENIED: return "request denied";
      case SSH_FATAL:          return "fatal";
      case SSH_EINTR:          return "interrupted";
      default:
        return "unknown error";
    }
  }

  const char * name() const noexcept override
  {
    return "libssh";
  }
};

std::error_category & ssh_category()
{
  static ssh_category_t cat;
  return cat;
}

}
