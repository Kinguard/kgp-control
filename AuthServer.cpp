#include "AuthServer.h"
#include "CryptoHelper.h"
#include <stdexcept>

using namespace std;
using namespace CryptoHelper;


AuthServer::AuthServer(const string &unit_id, const string &host): host( host ), unit_id(unit_id)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	this->curl = curl_easy_init();
	if( ! this->curl )
	{
		throw runtime_error("Unable to init Curl");
	}
}

tuple<int, string> AuthServer::GetChallenge()
{
	string ret = "";
	map<string,string> arg = {{ "unit_id", this->unit_id }};

	string s_res = this->DoGet("auth.php", arg);

	Json::Value res;
	if( this->reader.parse(s_res, res) )
	{
		if( res.isMember("challange") && res["challange"].isString() )
		{
			ret = res["challange"].asString();
		}
	}
	return tuple<int,string>(this->result_code,ret);
}

tuple<int, Json::Value> AuthServer::SendSignedChallenge(const string &challenge)
{
	Json::Value data;
	data["unit_id"] = this->unit_id;
	data["signature"] = challenge;

	map<string,string> postargs = {
		{"data", this->writer.write(data) }
	};

	Json::Value retobj = Json::objectValue;
	string body = this->DoPost("auth.php", postargs);

	this->reader.parse(body, retobj);

	return tuple<int,Json::Value>(this->result_code, retobj );
}

tuple<int, Json::Value> AuthServer::SendSecret(const string &secret, const string &pubkey)
{
	Json::Value data;
	data["unit_id"] = this->unit_id;
	data["response"] = secret;
	data["PublicKey"] = pubkey;

	map<string,string> postargs = {
		{"data", this->writer.write(data) }
	};

	string body = this->DoPost("register_public.php", postargs);

	Json::Value retobj = Json::objectValue;
	if( ! this->reader.parse(body, retobj) )
	{
		retobj = Json::objectValue;
		retobj["error"]=body;
	}

	return tuple<int,Json::Value>(this->result_code, retobj );
}

void AuthServer::GetAuth(const string& unit_id)
{
	map<string,string> arg = {{ "unit_id", unit_id }};

	string s_res = this->DoGet("auth.php", arg);

	Json::Value res;
	if( this->reader.parse(s_res, res) )
	{
		string chal = res["challange"].asString();

		RSAWrapper c;
		c.GenerateKeys();

		vector<byte> signature = c.SignMessage(chal);
		string sig = Base64Encode(signature);

		cout << sig << endl;

		Json::Value data;
		data["unit_id"] = unit_id;
		data["signature"] = sig;

		map<string,string> postargs = {
			{"data", this->writer.write(data) }
		};

		cout << this->DoPost("auth.php", postargs)<<endl;
		cout << this->result_code<<endl;

	}

}

AuthServer::~AuthServer()
{
	curl_easy_cleanup( this->curl );
	curl_global_cleanup();
}

void AuthServer::CurlPre()
{
	curl_easy_reset( this->curl );
	this->body.str("");

	//TODO: Setup to use our CA and verify host, setting CURLOPT_CAPATH
	curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYHOST, 0L);

	curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, AuthServer::WriteCallback );
	curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, (void *)this);

}

string AuthServer::DoGet(string path, map<string, string> data)
{

	this->CurlPre();

	string url = this->host+path+"?"+this->MakeFormData(data);
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	return this->CurlPerform();
}

string AuthServer::DoPost(string path, map<string, string> data)
{
	this->CurlPre();

	string url = this->host+path;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

	string poststring = this->MakeFormData(data);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, poststring.c_str() );

	return this->CurlPerform();
}

string AuthServer::CurlPerform()
{
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

string AuthServer::MakeFormData(map<string, string> data)
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

string AuthServer::EscapeString(const string &arg)
{
	char *tmparg = curl_easy_escape(curl, arg.c_str(), arg.length());
	if( ! tmparg )
	{
		cerr << "Failed to escape url"<<endl;
	}
	string escarg(tmparg);
	curl_free(tmparg);

	return escarg;
}

size_t
AuthServer::WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	AuthServer* serv = static_cast<AuthServer*>(userp);
	serv->body.write((char*)contents, size*nmemb);
	return size*nmemb;
}
