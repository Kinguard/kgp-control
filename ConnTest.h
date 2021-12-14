#ifndef CONNTEST_H
#define CONNTEST_H

#include "Config.h"
#include <libopi/HttpClient.h>

#include <nlohmann/json.hpp>
#include <string>

using json = nlohmann::json;

class ConnTest : public OPI::HttpClient
{
public:
	ConnTest(const std::string& host);

	json DoTest();

	virtual ~ConnTest();
private:
	bool TestPort(long port);
};

#endif // CONNTEST_H
