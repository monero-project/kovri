#include <boost/test/unit_test.hpp>
#include "util/HTTP.h"

BOOST_AUTO_TEST_SUITE(UtilityTests)

using namespace i2p::util::http;

BOOST_AUTO_TEST_CASE(DecodeEmptyUri)
{
    BOOST_CHECK_EQUAL(DecodeURI(""), "");
}

BOOST_AUTO_TEST_CASE(DecodeUri)
{
    BOOST_CHECK_EQUAL(DecodeURI("%20"), " ");
}

BOOST_AUTO_TEST_SUITE_END()