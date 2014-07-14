#include "DnsServer.h"

DnsServer::DnsServer(const string &host): HttpClient(host)
{
}

tuple<int, Json::Value> DnsServer::CheckOPIName(const string &opiname)
{
	map<string,string> postargs = {
		{"fqdn", opiname+".op-i.me"},
		{"checkname",  "1"}
	};

	string body = this->DoPost("update_dns.php", postargs);

	Json::Value retobj = Json::objectValue;
	this->reader.parse(body, retobj);

	return tuple<int,Json::Value>(this->result_code, retobj );
}

DnsServer::~DnsServer()
{

}
