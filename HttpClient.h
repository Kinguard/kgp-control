#ifndef HTTPCLIENT_H
#define HTTPCLIENT_H

#include <sstream>
#include <string>
#include <map>

#include <curl/curl.h>


using namespace std;

class HttpClient
{
public:
	HttpClient(const string& host);

	virtual ~HttpClient();

	void setPort(long value);
	void setTimeout( long value );
protected:
	void CurlPre();
	void CurlSetHeaders(const map<string, string> &headers);
	std::string DoGet(std::string path, map<string, string> data);
	std::string DoPost(std::string path, map<string, string> data);
	string CurlPerform();

	string MakeFormData(map<string,string> data);
	string EscapeString(const string& arg);

	static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);

	CURL *curl;
	long result_code;
	string host;
	string unit_id;
	stringstream body;
private:
	void setheaders();
	void clearheaders();
	struct curl_slist *slist;
	map<string,string> headers;
	long port;
	long timeout;
};

#endif // HTTPCLIENT_H
