#include "AuthServer.h"
#include "CryptoHelper.h"
#include <stdexcept>

using namespace std;
using namespace CryptoHelper;


AuthServer::AuthServer(const string &unit_id, const string &host): HttpClient( host ), unit_id(unit_id)
{
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

tuple<int, Json::Value> AuthServer::GetCertificate(const string &csr, const string &token)
{
	map<string,string> postargs = {
		{"unit_id", this->unit_id },
		{"csr", csr }
	};

	map<string,string> headers = {
		{"token", token}
	};

	this->CurlSetHeaders(headers);

	Json::Value retobj = Json::objectValue;
	string body = this->DoPost("get_cert.php", postargs);

	this->reader.parse(body, retobj);

	return tuple<int,Json::Value>(this->result_code, retobj );
}

AuthServer::~AuthServer()
{
}
