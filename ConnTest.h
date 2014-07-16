#ifndef CONNTEST_H
#define CONNTEST_H

#include "Config.h"
#include "HttpClient.h"

#include <json/json.h>

class ConnTest : public HttpClient
{
public:
	ConnTest();

	Json::Value DoTest();

	virtual ~ConnTest();
private:
	bool TestPort(long port);

	Json::Reader reader;
};

#endif // CONNTEST_H
