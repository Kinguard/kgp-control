#ifndef AUTHSERVER_H
#define AUTHSERVER_H

#include <string>
#include <tuple>

#include <curl/curl.h>
#include <json/json.h>

#include "HttpClient.h"

#include "Config.h"

using namespace std;

class AuthServer: public HttpClient
{
public:
	AuthServer(const string& unit_id, const string& host = OP_HOST);

	tuple<int,string> GetChallenge();

	tuple<int, Json::Value> SendSignedChallenge( const string& challenge);

	tuple<int, Json::Value> SendSecret(const string& secret, const string& pubkey);

	void GetAuth(const string &unit_id);

	virtual ~AuthServer();
private:

	Json::Reader reader;
	Json::FastWriter writer;
	string unit_id;
};

#endif // AUTHSERVER_H
