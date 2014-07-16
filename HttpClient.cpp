#include "HttpClient.h"

HttpClient::HttpClient(const string& host): host(host),port(0)
{
	this->curl = curl_easy_init();
	if( ! this->curl )
	{
		throw runtime_error("Unable to init Curl");
	}
}

HttpClient::~HttpClient()
{
	curl_easy_cleanup( this->curl );
}

void HttpClient::CurlPre()
{
	curl_easy_reset( this->curl );
	this->body.str("");

	//TODO: Setup to use our CA and verify host, setting CURLOPT_CAPATH
	curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, HttpClient::WriteCallback );
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)this);

	// Override protocol default port
	if( port != 0 )
	{
		curl_easy_setopt(this->curl, CURLOPT_PORT, this->port);
	}

	if( this->timeout != 0)
	{
		curl_easy_setopt(this->curl, CURLOPT_CONNECTTIMEOUT, this->timeout);
	}

}

/*
 *Set headers for next request, headers reset after request
 */
void HttpClient::CurlSetHeaders(const map<string, string>& headers)
{
	this->headers = headers;
}

string HttpClient::DoGet(string path, map<string, string> data)
{
	this->CurlPre();

	string url = this->host+path+"?"+this->MakeFormData(data);
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	return this->CurlPerform();
}

string HttpClient::DoPost(string path, map<string, string> data)
{
	this->CurlPre();

	string url = this->host+path;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	string poststring = this->MakeFormData(data);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, poststring.c_str() );

	return this->CurlPerform();
}

string HttpClient::CurlPerform()
{

	this->setheaders();

	CURLcode res = curl_easy_perform(curl);

	this->clearheaders();

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

string HttpClient::MakeFormData(map<string, string> data)
{
	stringstream postdata;
	bool first = true;
	for(auto arg: data )
	{
		if (!first)
		{
			postdata << "&";
		}
		else
		{
			first = false;
		}
		postdata << this->EscapeString(arg.first) << "=" << this->EscapeString(arg.second);
	}

	return postdata.str();
}

string HttpClient::EscapeString(const string &arg)
{
	char *tmparg = curl_easy_escape(curl, arg.c_str(), arg.length());
	if( ! tmparg )
	{
		throw runtime_error("Failed to escape url");
	}
	string escarg(tmparg);
	curl_free(tmparg);

	return escarg;
}

size_t HttpClient::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	HttpClient* serv = static_cast<HttpClient*>(userp);
	serv->body.write((char*)contents, size*nmemb);
	return size*nmemb;
}

void HttpClient::setheaders()
{
	if( this->headers.size() > 0 )
	{
		this->slist = NULL;
		for(auto h: this->headers )
		{
			string header = h.first+ ":" + h.second;
			this->slist = curl_slist_append( this->slist, header.c_str() );
			if( ! this->slist )
			{
				throw runtime_error("Failed to append custom header");
			}
		}
		curl_easy_setopt( this->curl , CURLOPT_HTTPHEADER, this->slist);
	}
}

void HttpClient::clearheaders()
{
	if( this->headers.size() > 0 )
	{
		 curl_slist_free_all( this->slist );
		 this->headers.clear();
	}
}

void HttpClient::setPort(long value)
{
	port = value;
}

void HttpClient::setTimeout(long value)
{
	this->timeout = value;
}

