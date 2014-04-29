#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <functional>
#include <memory>
#include <string>
#include <libutils/Thread.h>
#include <libutils/ClassTools.h>

#include "mongoose.h"

class WebServer : public Utils::Thread, Utils::NoCopy
{
public:
	WebServer(std::function<void(std::string)> cb);

	void Stop();

	virtual void PreRun();
	virtual void Run();
	virtual void PostRun();

	virtual ~WebServer();
private:

	static int ev_handler(struct mg_connection *conn, enum mg_event ev);

	static std::function<void(std::string)> callback;

	bool doRun;
	struct mg_server *server;
};

typedef std::shared_ptr<WebServer> WebServerPtr;

#endif // WEBSERVER_H
