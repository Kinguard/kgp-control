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
	WebServer(int initial_state, std::function<int(Json::Value)>);

	void Stop();

	virtual void PreRun();
	virtual void Run();
	virtual void PostRun();

	virtual ~WebServer();
private:

	static int handle_init(struct mg_connection *conn);
	static int handle_status(struct mg_connection *conn);
	static int handle_user(struct mg_connection *conn);
	static int handle_checkname(struct mg_connection *conn);

	static int ev_handler(struct mg_connection *conn, enum mg_event ev);
	static bool parse_json(struct mg_connection *conn, Json::Value& val);
	static 	std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *)> > routes;
	static std::function<int(Json::Value)> callback;
	static int state;
	bool doRun;
	struct mg_server *server;
};

typedef std::shared_ptr<WebServer> WebServerPtr;

#endif // WEBSERVER_H
