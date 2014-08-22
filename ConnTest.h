#ifndef CONNTEST_H
#define CONNTEST_H

#include "Config.h"
#include <libopi/HttpClient.h>

#include <json/json.h>

class ConnTest : public OPI::HttpClient
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
