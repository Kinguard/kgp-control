#include "InboundTest.h"

#include <libutils/Logger.h>
#include <libutils/String.h>
#include <libopi/SysInfo.h>
#include <fcntl.h>

#include <list>

using namespace std;
using namespace Utils;

void TcpServer::ParseRequest(const Utils::Net::SocketPtr& c)
{
	this->headers.clear();
	size_t r = c->Read(buf, sizeof(buf) );
	if( r>0 )
	{
		buf[r]=0;
		list<string> rows = String::Split(buf,"\r\n");
		for( const auto& row: rows )
		{
			if( row.compare(0, 3, "GET") == 0)
			{
				// remove 'GET ' and split the remainder on ' ' (has a ' HTTP/1.0' at the end)
				list<string> request = String::Split(row.substr(4, string::npos), " ",2);
				this->url = request.front();
			}
			list<string> words = String::Split(row, ": ",2);
			if( words.size() == 2 )
			{
				headers[ String::ToLower( words.front() ) ] = words.back();
			}
		}
	}
}

void TcpServer::Redirect( const Utils::Net::SocketPtr& c )
{
	ostringstream ss;
	string url = this->headers["host"]+this->url;

	ss << "HTTP/1.1 307 Temporary Redirect\r\n"
		<< "Location: https://"<<url<<"\r\n"
		<< "Connection: close\n\n";

	c->Write(ss.str().c_str(), ss.str().size());
}

TcpServer::TcpServer(uint16_t port):
		Thread(false),
		s( OPI::sysinfo.NetworkDevice(), port),
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

int TcpServer::Port()
{
	return this->port;
}

void TcpServer::Stop()
{
	this->dorun = false;
	this->Join();
}

void TcpServer::Run()
{
	logg << Logger::Debug << "Inbound test server starting at " << this->port << lend;
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

InboundTest::InboundTest(const vector<uint16_t> &ports)
{
	for(uint16_t port: ports)
	{
		try
		{
			logg << Logger::Debug << "Create ibound test server at port "<< port << lend;
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
	for(const TcpServerPtr& server: this->servers)
	{
		try
		{
			logg << Logger::Debug << "Start inbound test server at "<< server->Port()<<lend;
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
	for(const auto& server: this->servers)
	{
		server->Stop();
	}
}

InboundTest::~InboundTest() = default;
