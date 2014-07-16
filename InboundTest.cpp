#include "InboundTest.h"

#include <libutils/Logger.h>
#include <libutils/Thread.h>
#include <libutils/Socket.h>
#include <libutils/ClassTools.h>

using namespace Utils::Net;

class TcpServer: public Thread, NoCopy {
private:
	TCPServerSocket s;
	int port;
	bool dorun;
public:

	TcpServer(int port):
		Thread(false),
		s("eth0",port),
		port(port),
		dorun(true)
	{}

	void Stop()
	{
		this->dorun = false;
		this->Join();
	}

	virtual void Run()
	{
		logg << Logger::Debug << "Test server starting at " << this->port << lend;
		string msg("{\"connection\" : \"success\"}\n");
		while( dorun )
		{
			s.SetTimeout(1,0);
			Utils::Net::SocketPtr c = s.Accept();
			if( c )
			{
				c->Write(msg.c_str(), msg.size());
			}
		}
		logg << Logger::Debug << "Test server at " << this->port << " terminating" << lend;
	}
};



InboundTest::InboundTest(const vector<int> &ports)
{
	for(int port: ports)
	{
		try
		{
			TcpServerPtr server(new TcpServer(port) );
			servers.push_back( server );
		}
		catch(runtime_error& err)
		{
			logg << Logger::Error << "Failed to start server at port " << port << " ("<<err.what()<<")"<<lend;
		}
	}
}

void InboundTest::Start()
{
	for(auto server: this->servers)
	{
		try
		{
			server->Start();
		}
		catch(runtime_error& err)
		{
			logg << Logger::Error << "Failed to start server "<<err.what()<<lend;
		}
	}
}

void InboundTest::Stop()
{
	for(auto server: this->servers)
	{
		server->Stop();
	}
}

InboundTest::~InboundTest()
{

}
