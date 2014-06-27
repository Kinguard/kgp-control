#include "WebServer.h"
#include "Config.h"
#include "mongoose.h"

#include <string>

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

std::function<void(std::string)> WebServer::callback;

WebServer::WebServer(std::function<void(std::string)> cb):
	Utils::Thread(false),
	doRun(true),
	server(NULL)
{
	WebServer::callback = cb;
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

		if( conn->uri == std::string("/configure") && conn->request_method == std::string("POST") )
		{
			char buf[513];
			if( mg_get_var(conn, "password",buf,sizeof(buf)) > 0 )
			{
				if( WebServer::callback != nullptr ){
					WebServer::callback(std::string(buf) );
				}
				mg_printf_data(conn, "Password: [%s]\n", buf);
			}
			mg_printf_data(conn, "Querystr [%s]\n", conn->query_string);
			mg_printf_data(conn, "Method   [%s]\n", conn->request_method);
			mg_printf_data(conn, "version  [%s]\n", conn->http_version);
			result = MG_TRUE;
		}
	}else if (ev == MG_AUTH) {
		result = MG_TRUE;
	}

	return result;

}
