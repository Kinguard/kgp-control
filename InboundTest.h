#ifndef INBOUNDTEST_H
#define INBOUNDTEST_H

#include <vector>
#include <memory>
#include <map>

#include <libutils/Socket.h>
#include <libutils/Thread.h>
#include <libutils/ClassTools.h>

using namespace std;
using namespace Utils;
using namespace Utils::Net;

class TcpServer: public Thread, NoCopy {
private:
	TCPServerSocket s;
	int port;
	bool dorun;

	map<string,string> headers;
	string url;
	char buf[8192]{};

	void ParseRequest(const Utils::Net::SocketPtr& c);
	void Redirect( const Utils::Net::SocketPtr& c );
public:

	TcpServer(uint16_t port);

	int Port();

	void Stop();

	virtual void Run();
};

typedef shared_ptr<TcpServer> TcpServerPtr;

class InboundTest : public NoCopy
{
public:
	InboundTest(const vector<uint16_t>& ports);

	void Start();

	void Stop();

	virtual ~InboundTest();
private:
	vector<TcpServerPtr> servers;

};

typedef shared_ptr<InboundTest> InboundTestPtr;


#endif // INBOUNDTEST_H
