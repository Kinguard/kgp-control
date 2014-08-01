#include "WebServer.h"
#include "Config.h"
#include "mongoose.h"
#include "DnsServer.h"

#include <libutils/Logger.h>

#include <string>
#include <map>

#ifdef OPI_BUILD_PACKAGE

#define DOCUMENT_ROOT	"/usr/share/opi-control/web"
#define SSL_CERT_PATH	"/etc/opi/opi.cert"
#define SSL_KEY_PATH	"/etc/opi/dnspriv.pem"
#define LISTENING_PORT	"443"

#else

#define DOCUMENT_ROOT	"../opi-control/html"
#define SSL_CERT_PATH	"certificate.pem"
#define SSL_KEY_PATH	"priv_key.pem"

#define LISTENING_PORT	"443"

#endif

using namespace Utils;
using namespace std;

std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *)> > WebServer::routes;
std::function<Json::Value(Json::Value)> WebServer::callback;
int WebServer::state;

WebServer::WebServer(int initial_state, std::function<Json::Value(Json::Value)> cb):
	Utils::Thread(false),
	doRun(true),
	server(NULL)
{
	WebServer::callback = cb;
	WebServer::state = initial_state;
	routes[std::make_pair("/configure","POST")] = WebServer::handle_init;
	routes[std::make_pair("/init","POST")] = WebServer::handle_init;
	routes[std::make_pair("/reinit","POST")] = WebServer::handle_reinit;
	routes[std::make_pair("/unlock","POST")] = WebServer::handle_unlock;
	routes[std::make_pair("/status","GET")] = WebServer::handle_status;
	routes[std::make_pair("/user","POST")] = WebServer::handle_user;
	routes[std::make_pair("/checkname","POST")] = WebServer::handle_checkname;
	routes[std::make_pair("/opiname","POST")] = WebServer::handle_selectname;
	routes[std::make_pair("/portstatus","GET")] = WebServer::handle_portstatus;
	routes[std::make_pair("/terminate","POST")] = WebServer::handle_terminate;
	routes[std::make_pair("/shutdown","POST")] = WebServer::handle_shutdown;

}

void WebServer::Stop()
{
	this->doRun = false;
}

void WebServer::PreRun()
{
	this->server = mg_create_server(NULL, WebServer::ev_handler);
	mg_set_option(this->server, "document_root", DOCUMENT_ROOT);

	mg_set_option(this->server, "ssl_certificate",SSL_CERT_PATH);
	mg_set_option(this->server, "ssl_private_key",SSL_KEY_PATH);

	mg_set_option(this->server, "listening_port",LISTENING_PORT);

	// Redirect all 404 to our index page
	mg_set_option(this->server, "url_rewrites","404=/");

#if 0
	mg_set_option( this->server, "access_log_file", "mg_logfile.txt");
#endif
}

void WebServer::Run()
{
	logg << Logger::Debug << "Starting webserver on port " << mg_get_option(server, "listening_port") <<lend;
	while ( this->doRun ) {
		mg_poll_server(this->server, 1000);
	}
}

void WebServer::PostRun()
{
	// Cleanup, and free server instance
	logg << Logger::Debug << "Webserver shutting down!" << lend;
	mg_destroy_server(&server);
}

WebServer::~WebServer()
{

}

static bool validate_initdata(const Json::Value& v)
{
	if( ! v.isMember("masterpassword") || !v["masterpassword"].isString() )
	{
		return false;
	}

	if( ! v.isMember("unit_id") || !v["unit_id"].isString() )
	{
		return false;
	}


	return true;
}

int WebServer::handle_init(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for init"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if(  validate_initdata( req ) )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="init";
			cmd["password"]=req["masterpassword"];
			cmd["unit_id"] = req["unit_id"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str());
	}
	else
	{
		mg_printf_data( conn, "Missing argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;
}

int WebServer::handle_reinit(mg_connection *conn)
{
	// Almost like init but from an initialized unut
	logg << Logger::Debug << "Got request for reinit"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if(   req.isMember("masterpassword") && req["masterpassword"].isString()  )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="reinit";
			cmd["password"]=req["masterpassword"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str());
	}
	else
	{
		mg_printf_data( conn, "Missing argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;
}

int WebServer::handle_unlock(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for unlock"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if( req.isMember("masterpassword") && req["masterpassword"].isString() )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="unlock";
			cmd["password"]=req["masterpassword"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str() );
	}
	else
	{
		mg_printf_data( conn, "Missing argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;
}

int WebServer::handle_status(mg_connection *conn)
{
	mg_send_header( conn, "Content-Type", "application/json");
	mg_printf_data( conn, "{\"state\":%d}", WebServer::state );
	return MG_TRUE;
}

static bool validate_user(const Json::Value& v)
{

	if( ! v.isMember("username") || !v["username"].isString() )
	{
		return false;
	}

	if( ! v.isMember("displayname") || !v["displayname"].isString() )
	{
		return false;
	}

	if( ! v.isMember("password") || !v["password"].isString() )
	{
		return false;
	}

	return true;
}

int WebServer::handle_user(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for adduser"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if( validate_user(req) )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="adduser";
			cmd["username"]=req["username"];
			cmd["displayname"]=req["displayname"];
			cmd["password"]=req["password"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str() );
	}
	else
	{
		logg << Logger::Debug << "Request for add user had invalid arguments"<<lend;
		mg_printf_data( conn, "Invalid argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;
}

int WebServer::handle_checkname(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for checkname"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if( req.isMember("opiname") && req["opiname"].isString() )
	{
		DnsServer dns;
		int result_code;
		Json::Value ret;
		tie(result_code, ret) = dns.CheckOPIName(req["opiname"].asString() );

		if( result_code == 200 || result_code == 403 )
		{

			mg_send_header( conn, "Content-Type", "application/json");
			mg_printf_data( conn, "{\"available\":%d}", result_code==200?1:0);
		}
		else
		{
			logg << Logger::Debug << "Request for dns check name failed"<<lend;
			mg_printf_data( conn, "Operation failed");
			mg_send_status(conn, 502);

		}
	}
	else
	{
		logg << Logger::Debug << "Request for add user had invalid arguments"<<lend;
		mg_printf_data( conn, "Invalid argument!");
		mg_send_status(conn, 400);
	}
	return MG_TRUE;
}

int WebServer::handle_selectname(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for update dnsname"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}
	if( req.isMember("opiname") && req["opiname"].isString() )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="opiname";
			cmd["opiname"]=req["opiname"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str() );
	}
	else
	{
		logg << Logger::Debug << "Request for add user had invalid arguments"<<lend;
		mg_printf_data( conn, "Invalid argument!");
		mg_send_status(conn, 400);
	}
	return MG_TRUE;

}

int WebServer::handle_portstatus(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for portstatus"<<lend;


	Json::Value ret;
	if( WebServer::callback != nullptr ){
		Json::Value cmd;
		cmd["cmd"]="portstatus";
		ret = WebServer::callback( cmd );
	}

	mg_send_header( conn, "Content-Type", "application/json");
	mg_printf_data( conn, ret.toStyledString().c_str() );

	return MG_TRUE;
}

int WebServer::handle_terminate(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for terminate"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if( req.isMember("shutdown") && req["shutdown"].isBool() )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="terminate";
			cmd["shutdown"]=req["shutdown"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str() );
	}
	else
	{
		mg_printf_data( conn, "Missing argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;

}

int WebServer::handle_shutdown(mg_connection *conn)
{
	logg << Logger::Debug << "Got request for shutdown"<<lend;

	Json::Value req;

	if( ! WebServer::parse_json(conn, req) )
	{
		// True in the sense that we handled the req.
		return MG_TRUE;
	}

	if( req.isMember("action") && req["action"].isString() )
	{
		Json::Value ret;
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="shutdown";
			cmd["action"]=req["action"];
			ret = WebServer::callback( cmd );
			WebServer::state = ret["state"].asInt();
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, ret.toStyledString().c_str() );
	}
	else
	{
		mg_printf_data( conn, "Missing argument!");
		mg_send_status(conn, 400);
	}

	return MG_TRUE;

}

int WebServer::ev_handler(mg_connection *conn, mg_event ev)
{
	int result = MG_FALSE;

	if (ev == MG_REQUEST) {
#if 0
		mg_printf_data(conn, "URI      [%s]\n", conn->uri);
		mg_printf_data(conn, "Querystr [%s]\n", conn->query_string);
		mg_printf_data(conn, "Method   [%s]\n", conn->request_method);
		mg_printf_data(conn, "version  [%s]\n", conn->http_version);
#endif

		auto val = std::make_pair(conn->uri, conn->request_method);

		if( WebServer::routes.find(val) != WebServer::routes.end() )
		{
			result = WebServer::routes[val](conn);
		}

	}else if (ev == MG_AUTH) {
		result = MG_TRUE;
	}

	return result;

}

bool WebServer::parse_json(mg_connection *conn, Json::Value &val)
{
	string postdata(conn->content, conn->content_len);

	if( ! Json::Reader().parse(postdata, val) )
	{
		logg << Logger::Debug << "Failed to parse input"<<lend;
		mg_printf_data( conn, "Unable to parse input");
		mg_send_status(conn, 400);

		return false;
	}

	return true;
}
