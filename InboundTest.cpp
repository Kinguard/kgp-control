#include "InboundTest.h"

#include <libutils/Logger.h>
#include <libutils/String.h>

#include <fcntl.h>

#include <list>

using namespace std;
using namespace Utils;

void TcpServer::ParseRequest(Utils::Net::SocketPtr c)
{
	this->headers.clear();
	size_t r = c->Read(buf, sizeof(buf) );
	if( r>0 )
	{
		buf[r]=0;
		list<string> rows = String::Split(buf,"\r\n");
		for( auto row: rows )
		{
			list<string> words = String::Split(row, ": ",2);
			if( words.size() == 2 )
			{
				headers[ String::ToLower( words.front() ) ] = words.back();
			}
		}
	}
}

void TcpServer::Redirect( Utils::Net::SocketPtr c )
{
	ostringstream ss;
	ss << "HTTP/1.1 307 Temporary Redirect\r\n"
		  //<< "Location: https://www.openproducts.com\r\n"
	   << "Location: https://"<<this->headers["host"]<<"\r\n"
		<< "Connection: close\n\n";

	c->Write(ss.str().c_str(), ss.str().size());
}

TcpServer::TcpServer(int port):
		Thread(false),
		s("eth0",port),
		port(port),
		dorun(true)
{
	int fd = this->s.getSocketFd();

	int flags = fcntl( fd, F_GETFD, 0);

	if( flags < 0 )
	{
		throw ErrnoException("Failed to get socket flags");
	}

	if( fcntl( fd, F_SETFD, flags | FD_CLOEXEC ) != 0 )
	{
		throw ErrnoException("Failed to update socket fd");
	}
}

void TcpServer::Stop()
{
	this->dorun = false;
	this->Join();
}

void TcpServer::Run()
{
	logg << Logger::Debug << "Test server starting at " << this->port << lend;
	string msg("{\"connection\" : \"success\"}\n");
	while( dorun )
	{
		s.SetTimeout(1,0);
		Utils::Net::SocketPtr c = s.Accept();
		if( c )
		{
			this->ParseRequest(c);
			if( this->headers.find("host") != this->headers.end() )
			{
				this->Redirect(c);
			}
			else
			{
				c->Write(msg.c_str(), msg.size());
			}
		}
	}
	logg << Logger::Debug << "Test server at " << this->port << " terminating" << lend;
}

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
