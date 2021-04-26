#include "ConnTest.h"

#include <libutils/Logger.h>
#include <libutils/NetServices.h>
#include <sstream>
#include <vector>

using namespace Utils;
ConnTest::ConnTest(const string &host): HttpClient(host)
{
}

Json::Value ConnTest::DoTest()
{
	using namespace Utils::Net::Service;

	vector<long> ports( { SMTP, HTTP, IMAP2, HTTPS, IMAPS, ALT_SMTP });
	Json::Value ret;

	for( long port: ports )
	{
		stringstream key;
		key << "p"<<port;
		ret[key.str() ] = this->TestPort(port);
	}

	return ret;
}

ConnTest::~ConnTest() = default;

bool ConnTest::TestPort(long port)
{
	logg << Logger::Debug << "Testing port " << static_cast<int>(port) << lend;
	bool ret = false;

	try
	{
		map<string,string> arg;

		this->setPort(port);
		this->setTimeout(10);
		string body = this->DoGet("/", arg);

		Json::Value res;
		if( this->reader.parse(body, res) )
		{
			if( res.isMember("connection") && res["connection"].isString() )
			{
				ret = (res["connection"].asString() == "success");
			}
		}

	}
	catch( runtime_error& err)
	{
		logg << Logger::Debug << "Failed to contact server on port "<<port<<" ("<<err.what()<<")"<<lend;
		ret = false;
	}

	return ret;
}
