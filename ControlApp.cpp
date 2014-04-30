#include "ControlApp.h"
#include "Config.h"

#include "Secop.h"
#include "WebServer.h"

#include <functional>

#include <unistd.h>

using namespace Utils;
using namespace std::placeholders;


ControlApp::ControlApp() : DaemonApplication("ControlApp","/var/run","root","root")
{
}

void ControlApp::Startup()
{
	logg << Logger::Debug << "Starting up!"<< lend;
	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ControlApp::SigHup, this, _1) );
}

void ControlApp::Main()
{
	if ( ! this->SecopUnlocked() )
	{
		logg << Logger::Debug << "Secop not unlocked"<<lend;

		this->ws = WebServerPtr( new WebServer( std::bind(&ControlApp::Unlock,this, _1)) );

		this->ws->Start();

		this->ws->Join();

	}
}

void ControlApp::ShutDown()
{
	logg << Logger::Debug << "Shutting down"<< lend;
}

void ControlApp::SigTerm(int signo)
{
	// Possibly shutdown webserver
	if( this->ws != nullptr )
	{
		this->ws->Stop();
	}

}

void ControlApp::SigHup(int signo)
{

}

ControlApp::~ControlApp()
{

}

void ControlApp::Unlock(string pwd)
{
	Secop s;

	if( s.Init(pwd) && this->ws != nullptr )
	{
		this->ws->Stop();
	}
}

bool ControlApp::SecopUnlocked()
{
	Secop s;

	Secop::State st  = s.Status();

	logg << Logger::Debug << "Secop status : "<< st << lend;

	return (st != Secop::Uninitialized) && (st != Secop::Unknown);
}
