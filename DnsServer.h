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

	bool RegisterPublicKey(const string& unit_id, const string& key, const string& token );

	bool UpdateDynDNS(const string& unit_id, const string& name);

	virtual ~DnsServer();
private:

	bool Auth(const string& unit_id);
	// Duplicated from authserver, consider refactoring?
	tuple<int, string> GetChallenge(const string &unit_id);
	tuple<int, Json::Value> SendSignedChallenge(const string &unit_id, const string &challenge);

	string token;
	Json::Reader reader;
	Json::FastWriter writer;

};

#endif // DNSSERVER_H
