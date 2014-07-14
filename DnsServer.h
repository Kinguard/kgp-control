#ifndef DNSSERVER_H
#define DNSSERVER_H

#include "HttpClient.h"
#include "Config.h"

#include <json/json.h>

#include <string>
#include <tuple>

using namespace std;

class DnsServer : public HttpClient
{
public:
	DnsServer( const string& host=OP_HOST);

	tuple<int, Json::Value> CheckOPIName( const string& opiname );


	virtual ~DnsServer();
private:
	Json::Reader reader;
	Json::FastWriter writer;

};

#endif // DNSSERVER_H
