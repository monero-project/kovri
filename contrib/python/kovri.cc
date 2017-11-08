#include <boost/python.hpp>

#include "client/instance.h"

void Run()
{
  auto core = std::make_unique<kovri::core::Instance>();
  auto client = std::make_unique<kovri::client::Instance>(std::move(core));

  client->Initialize();
  client->Start();
  client->Stop();
}

// Trivial Boost.Python extending model PoC for kovri
BOOST_PYTHON_MODULE(kovri_python)
{
  // TODO(anonimal): in-tandem API development
  boost::python::def("Run", Run);
}
