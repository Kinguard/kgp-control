#include "WebServer.h"
#include "Config.h"
#include "mongoose.h"

#include <libutils/Logger.h>

#include <string>
#include <map>

#ifdef OPI_BUILD_PACKAGE

#define DOCUMENT_ROOT	"/usr/share/opi-control/web"
#define SSL_CERT_PATH	"/etc/ssl/certs/opi.pem"
#define SSL_KEY_PATH	"/etc/ssl/private/opi.key"
#define LISTENING_PORT	"4443"

#else

#define DOCUMENT_ROOT	"../opi-control/html"
#define SSL_CERT_PATH	"certificate.pem"
#define SSL_KEY_PATH	"priv_key.pem"

#define LISTENING_PORT	"8080"

#endif

using namespace Utils;
using namespace std;

std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *)> > WebServer::routes;
std::function<int(Json::Value)> WebServer::callback;

WebServer::WebServer(std::function<int(Json::Value)> cb):
	Utils::Thread(false),
	doRun(true),
	server(NULL)
{
	WebServer::callback = cb;

	routes[std::make_pair("/configure","POST")] = WebServer::handle_configure;
	routes[std::make_pair("/init","POST")] = WebServer::handle_configure;
	routes[std::make_pair("/status","GET")] = WebServer::handle_status;
	routes[std::make_pair("/user","POST")] = WebServer::handle_user;

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
}

void WebServer::Run()
{
	printf("Starting on port %s\n", mg_get_option(server, "listening_port"));
	while ( this->doRun ) {
		mg_poll_server(this->server, 1000);
	}
}

void WebServer::PostRun()
{
	// Cleanup, and free server instance
	printf("Webserver shutting down!\n");
	mg_destroy_server(&server);
}

WebServer::~WebServer()
{

}

int WebServer::handle_configure(mg_connection *conn)
{
	char buf[513];
	int ret=0;

	logg << Logger::Debug << "Got request for init"<<lend;

	string postdata(conn->content, conn->content_len);

	Json::Value req;

	if( ! Json::Reader().parse(postdata, req) )
	{
		mg_printf_data( conn, "Unable to parse input");
		mg_send_status(conn, 400);

		return MG_TRUE;
	}

	if( req.isMember("masterpassword") )
	{
		if( WebServer::callback != nullptr ){
			Json::Value cmd;
			cmd["cmd"]="init";
			cmd["password"]=req["masterpassword"];
			ret = WebServer::callback( cmd );
		}
		mg_send_header( conn, "Content-Type", "application/json");
		mg_printf_data( conn, "{\"status\":%d}",ret);
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
	mg_printf_data(conn, "{\"status\":3}");
	return MG_TRUE;
}

int WebServer::handle_user(mg_connection *conn)
{
	mg_send_header( conn, "Content-Type", "application/json");
	mg_printf_data(conn, "{\"status\":5}");
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
