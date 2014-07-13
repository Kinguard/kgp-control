#ifndef AUTHSERVER_H
#define AUTHSERVER_H

#include <map>
#include <string>
#include <sstream>
#include <tuple>

#include <curl/curl.h>
#include <json/json.h>

using namespace std;

#define HOST "https://auth.openproducts.com/"

class AuthServer
{
public:
	AuthServer(const string& unit_id, const string& host = HOST);

	tuple<int,string> GetChallenge();

	tuple<int, Json::Value> SendSignedChallenge( const string& challenge);

	tuple<int, Json::Value> SendSecret(const string& secret, const string& pubkey);

	void GetAuth(const string &unit_id);

	virtual ~AuthServer();
private:
	void CurlPre();
	std::string DoGet(std::string path, map<string, string> data);
	std::string DoPost(std::string path, map<string, string> data);
	string CurlPerform();

	string MakeFormData(map<string,string> data);
	string EscapeString(const string& arg);

	static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

	CURL *curl;
	Json::Reader reader;
	Json::FastWriter writer;
	long result_code;
	string host;
	string unit_id;
	stringstream body;
};

#endif // AUTHSERVER_H
