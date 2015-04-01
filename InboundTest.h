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
	char buf[8192];

	void ParseRequest(Utils::Net::SocketPtr c);
	void Redirect( Utils::Net::SocketPtr c );
public:

	TcpServer(int port);

	int Port();

	void Stop();

	virtual void Run();
};

typedef shared_ptr<TcpServer> TcpServerPtr;

class InboundTest : public NoCopy
{
public:
	InboundTest(const vector<int>& ports);

	void Start();

	void Stop();

	virtual ~InboundTest();
private:
	vector<TcpServerPtr> servers;

};

typedef shared_ptr<InboundTest> InboundTestPtr;


#endif // INBOUNDTEST_H
