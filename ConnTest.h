#ifndef CONNTEST_H
#define CONNTEST_H

#include "Config.h"
#include <libopi/HttpClient.h>

#include <json/json.h>
#include <string>

class ConnTest : public OPI::HttpClient
{
public:
	ConnTest(const std::string& host);

	Json::Value DoTest();

	virtual ~ConnTest();
private:
	bool TestPort(long port);

	Json::Reader reader;
};

#endif // CONNTEST_H
