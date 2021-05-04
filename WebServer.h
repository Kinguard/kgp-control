#ifndef WEBSERVER_H
#define WEBSERVER_H


#include <functional>
#include <map>
#include <memory>
#include <string>
#include <libutils/Thread.h>
#include <libutils/ClassTools.h>
#include <json/json.h>
#include "mongoose.h"


class WebServer : public Utils::Thread, Utils::NoCopy
{
public:
	WebServer(std::function<Json::Value(Json::Value)> cb, const std::string &docroot, uint16_t port=443);

	void Stop();

	virtual void PreRun();
	virtual void Run();
	virtual void PostRun();

	virtual ~WebServer();
private:

	static int handle_init(struct mg_connection *conn, struct http_message *http);
	static int handle_reinit(struct mg_connection *conn, struct http_message *http);
	static int handle_restore(struct mg_connection *conn, struct http_message *http);
	static int handle_unlock(struct mg_connection *conn, struct http_message *http);
	static int handle_status(struct mg_connection *conn, struct http_message *http);
	static int handle_user(struct mg_connection *conn, struct http_message *http);
	static int handle_checkname(struct mg_connection *conn, struct http_message *http);
	static int handle_selectname(struct mg_connection *conn, struct http_message *http);
	static int handle_portstatus(struct mg_connection *conn, struct http_message *http);
	static int handle_terminate(struct mg_connection *conn, struct http_message *http);
	static int handle_shutdown(struct mg_connection *conn, struct http_message *http);
	static int handle_type(struct mg_connection *conn, struct http_message *http);
	static int handle_domains(struct mg_connection *conn, struct http_message *http);
	static int handle_theme(struct mg_connection *conn, struct http_message *http);
	static int handle_storagedevices(struct mg_connection *conn, struct http_message *http);
	static int handle_devices(struct mg_connection *conn, struct http_message *http);

	static void ev_handler(struct mg_connection *conn, int ev, void *p);
	static bool parse_json(struct mg_connection *conn, http_message *hm, Json::Value& val);
	static 	std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *, struct http_message *)> > routes;
	static std::function<Json::Value(Json::Value)> callback;
	bool doRun;
	struct mg_mgr mgr;
	struct mg_connection *conn;
	static struct mg_serve_http_opts s_http_server_opts;
	static std::string documentroot;
	std::string portstring;
	uint16_t port;
};

typedef std::shared_ptr<WebServer> WebServerPtr;

#endif // WEBSERVER_H
