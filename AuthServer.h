#ifndef AUTHSERVER_H
#define AUTHSERVER_H

#include <string>
#include <sstream>

#include <curl/curl.h>
#include <json/json.h>

class AuthServer
{
public:
	AuthServer();

	virtual ~AuthServer();
private:
	std::string DoGet(std::string path, std::string query);

	static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

	CURL *curl;
	Json::Reader reader;
	long result_code;
	std::string host;
	std::stringstream body;
};

#endif // AUTHSERVER_H
