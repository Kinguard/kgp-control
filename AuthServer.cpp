#include "AuthServer.h"

#include <stdexcept>

using namespace std;

#define HOST "https://auth.openproducts.com/"

AuthServer::AuthServer(): host( HOST )
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	this->curl = curl_easy_init();
	if( ! this->curl )
	{
		throw runtime_error("Unable to init Curl");
	}
}

AuthServer::~AuthServer()
{
	curl_easy_cleanup( this->curl );
	curl_global_cleanup();
}

string AuthServer::DoGet(string path, string query)
{
	curl_easy_reset( this->curl );
	this->body.str("");

	//TODO: Setup to use our CA and verify host, setting CURLOPT_CAPATH
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AuthServer::WriteCallback );
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)this);

	string url = this->host+path+"?"+query;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	CURLcode res = curl_easy_perform(curl);

	if(res != CURLE_OK)
	{
		throw runtime_error( curl_easy_strerror(res) );
	}

	res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE ,  &this->result_code);
	if(res != CURLE_OK)
	{
		throw runtime_error( curl_easy_strerror(res) );
	}

	return this->body.str();
}

size_t
AuthServer::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	AuthServer* serv = static_cast<AuthServer*>(userp);
	serv->body.write((char*)contents, size*nmemb);
	return size*nmemb;
}
