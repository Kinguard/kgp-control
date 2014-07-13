
#include "Secop.h"


#include <libutils/Logger.h>

using namespace Utils;

Secop::Secop(): tid(0), secop("/tmp/secop")
{

}

bool Secop::Init(const string& pwd)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]= "init";
	cmd["pwd"]=pwd;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

Secop::State Secop::Status()
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]="status";

	Json::Value rep = this->DoCall(cmd);

	if( this->CheckReply(rep) )
	{
		return static_cast<Secop::State>(rep["server"]["state"].asInt());
	}
	return Secop::Unknown;
}

bool Secop::SockAuth()
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]= "auth";
	cmd["type"]="socket";

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::PlainAuth(const string& user, const string& pwd)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "auth";
	cmd["type"]		= "plain";
	cmd["username"]	= user;
	cmd["password"]	= pwd;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::CreateUser(const string& user, const string& pwd)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "createuser";
	cmd["username"]	= user;
	cmd["password"]	= pwd;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::RemoveUser(const string& user)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "removeuser";
	cmd["username"]	= user;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}


vector<string> Secop::GetUsers()
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]= "getusers";

	Json::Value rep = this->DoCall(cmd);

	vector<string> users;
	if( this->CheckReply(rep) )
	{
		for(auto x: rep["users"])
		{
			users.push_back(x.asString() );
		}
	}
	return users;
}

vector<string> Secop::GetServices(const string& user)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "getservices";
	cmd["username"]	= user;

	Json::Value rep = this->DoCall(cmd);

	vector<string> services;
	if( this->CheckReply(rep) )
	{
		for(auto x: rep["services"])
		{
			services.push_back(x.asString() );
		}
	}
	return services;
}

bool Secop::AddService(const string& user, const string& service)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "addservice";
	cmd["username"]		= user;
	cmd["servicename"]	= service;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::RemoveService(const string& user, const string& service)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "removeservice";
	cmd["username"]		= user;
	cmd["servicename"]	= service;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

vector<string> Secop::GetACL(const string& user, const string& service)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "getacl";
	cmd["username"]	= user;
	cmd["servicename"]	= service;

	Json::Value rep = this->DoCall(cmd);

	vector<string> acl;
	if( this->CheckReply(rep) )
	{
		for(auto x: rep["acl"])
		{
			acl.push_back(x.asString() );
		}
	}
	return acl;
}

bool Secop::AddACL(const string& user, const string& service, const string& acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "addacl";
	cmd["username"]		= user;
	cmd["servicename"]	= service;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::RemoveACL(const string& user, const string& service, const string& acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "removeacl";
	cmd["username"]		= user;
	cmd["servicename"]	= service;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::HasACL(const string& user, const string& service, const string& acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "hasacl";
	cmd["username"]		= user;
	cmd["servicename"]	= service;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);
	bool ret = false;

	if ( this->CheckReply(rep) )
	{
		ret = rep["hasacl"].asBool();
	}

	return ret;
}

/* Limited, can only add key value string pairs */
bool Secop::AddIdentifier(const string& user, const string& service, const map<string,string>& identifier)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "addidentifier";
	cmd["username"]		= user;
	cmd["servicename"]	= service;

	for(const auto& x: identifier)
	{
		cmd["identifier"][ x.first ] = x.second;
	}

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

/* Identifier has to contain user &| service */
bool Secop::RemoveIdentifier(const string& user, const string& service, const map<string,string>& identifier)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "removeidentifier";
	cmd["username"]		= user;
	cmd["servicename"]	= service;

	for(const auto& x: identifier)
	{
		cmd["identifier"][ x.first ] = x.second;
	}

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

list<map<string,string>> Secop::GetIdentifiers(const string& user, const string& service)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "getidentifiers";
	cmd["username"]		= user;
	cmd["servicename"]	= service;

	Json::Value rep = this->DoCall(cmd);

	list<map<string,string> > ret;
	//logg << Logger::Debug << rep.toStyledString()<< lend;
	if ( this->CheckReply(rep) )
	{
		for( auto x: rep["identifiers"] )
		{
			Json::Value::Members mems = x.getMemberNames();
			map<string,string> id;
			for( auto mem: mems)
			{
				id[ mem ] = x[mem].asString();
			}
			ret.push_back( id );
		}
	}

	return ret;
}

bool Secop::AppAddID(const string &appid)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "createappid";
	cmd["appid"]	= appid;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

vector<string> Secop::AppGetIDs()
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]= "getappids";

	Json::Value rep = this->DoCall(cmd);

	vector<string> users;
	if( this->CheckReply(rep) )
	{
		for(auto x: rep["appids"])
		{
			users.push_back(x.asString() );
		}
	}
	return users;

}

bool Secop::AppRemoveID(const string &appid)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "removeappid";
	cmd["appid"]	= appid;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::AppAddIdentifier(const string &appid, const map<string, string> &identifier)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "addappidentifier";
	cmd["appid"]		= appid;

	for(const auto& x: identifier)
	{
		cmd["identifier"][ x.first ] = x.second;
	}

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

list<map<string, string> > Secop::AppGetIdentifiers(const string &appid)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "getappidentifiers";
	cmd["appid"]		= appid;

	Json::Value rep = this->DoCall(cmd);

	list<map<string,string> > ret;
	//logg << Logger::Debug << rep.toStyledString()<< lend;
	if ( this->CheckReply(rep) )
	{
		for( auto x: rep["identifiers"] )
		{
			Json::Value::Members mems = x.getMemberNames();
			map<string,string> id;
			for( auto mem: mems)
			{
				id[ mem ] = x[mem].asString();
			}
			ret.push_back( id );
		}
	}

	return ret;
}

bool Secop::AppRemoveIdentifier(const string &appid, const map<string, string> &identifier)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "appremoveidentifier";
	cmd["appid"]		= appid;

	for(const auto& x: identifier)
	{
		cmd["identifier"][ x.first ] = x.second;
	}

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::AppAddACL(const string &appid, const string &acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "addappacl";
	cmd["appid"]		= appid;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

vector<string> Secop::AppGetACL(const string &appid)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]		= "getappacl";
	cmd["appid"]	= appid;

	Json::Value rep = this->DoCall(cmd);

	vector<string> acl;
	if( this->CheckReply(rep) )
	{
		for(auto x: rep["acl"])
		{
			acl.push_back(x.asString() );
		}
	}
	return acl;

}

bool Secop::AppRemoveACL(const string &appid, const string &acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "removeappacl";
	cmd["appid"]		= appid;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);

	return this->CheckReply(rep);
}

bool Secop::AppHasACL(const string &appid, const string &acl)
{
	Json::Value cmd(Json::objectValue);

	cmd["cmd"]			= "hasappacl";
	cmd["appid"]		= appid;
	cmd["acl"]			= acl;

	Json::Value rep = this->DoCall(cmd);
	bool ret = false;

	if ( this->CheckReply(rep) )
	{
		ret = rep["hasacl"].asBool();
	}

	return ret;
}

Secop::~Secop()
{

}

Json::Value Secop::DoCall(Json::Value& cmd)
{
	cmd["tid"]=this->tid;
	cmd["version"]=1.0;
	string r = this->writer.write( cmd );

	this->secop.Write(r.c_str(), r.size() );

	char buf[16384];
	int rd;

	Json::Value resp;

	if( ( rd = this->secop.Read( buf, sizeof(buf) ) ) > 0  )
	{

		if( ! this->reader.parse( buf, buf+rd, resp ) )
		{
			logg << Logger::Error << "Failed to parse response"<<lend;
		}

	}

	return resp;
}

bool Secop::CheckReply( const Json::Value& val )
{
	bool ret = false;

	if( val.isMember("status") && val["status"].isObject() )
	{
		ret = val["status"]["value"].asInt() == 0;
	}

	return ret;
}
