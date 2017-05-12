#include "PwdCtrlApp.h"

#include "PasswordFile.h"

#include <string>
#include <cstdio>
#include <iostream>

#include <libutils/FileUtils.h>
#include <libutils/String.h>

using namespace Utils;
using namespace std;

PwdCtrlApp::PwdCtrlApp(): Application("pwdctrl"),password(""), path("")
{

}

void PwdCtrlApp::Startup()
{
	this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );
	this->options.AddOption( Option('p', "path", Option::ArgRequired,"/root/.keepcfg/","Path where to store passwordfile") );
	this->options.AddOption( Option('P', "password", Option::ArgRequired,"","Password to use in passwordfile") );
	this->options.AddOption( Option('i', "infile", Option::ArgRequired,"0","File to read password from, use - for stdin") );

}

void PwdCtrlApp::Main()
{

	if( this->options["debug"] == "1" )
	{
		logg.SetLevel(Logger::Debug);
		logg << Logger::Info << "Increase logging to debug level "<<lend;
	}

	logg << Logger::Debug << "starting up" << lend;

	// Work out destination path
	try
	{

		if( File::DirExists( this->options["path"]) )
		{
			this->path = this->options["path"]+"/"+"opicred.bin";
		}
		else
		{
			logg << Logger::Error << "Directory '" << this->options["path"] << "' does not exist"<< lend;
			this->SetExitcode(1);
		}
	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Error << "Failed to check destination path for password file ("
			 << this->options["path"]
				<< "): '" << err.what()<<"'"<<lend;
		this->SetExitcode(1);
	}

	if( this->exitcode == 0)
	{
		// Retrieve password
		if( this->options["infile"] != "0" )
		{
			this->ReadPassword( this->options["infile"] );
		}
		else if( this->options["password"] != "" )
		{
			this->password = this->options["password"];
		}
		else
		{
			this->SetExitcode(1);
		}
	}

	if( this->exitcode == 0)
	{
		logg << Logger::Info << "Writing password file to '" << this->path<<"'"<<lend;

		PasswordFile::Write(this->path, this->password);

	}


	logg << Logger::Debug << "shutting down"<< lend;
}

PwdCtrlApp::~PwdCtrlApp()
{

}

void PwdCtrlApp::ReadPassword(const string &path)
{
	if( path == "-" )
	{
		logg << Logger::Debug << "Reading password from stdin"<< lend;

		if( ! getline(cin, this->password) )
		{
			logg << Logger::Error << "Failed to read password from stdin"<< lend;
			this->SetExitcode(1);
		}

		if( this->password == "" )
		{
			logg << Logger::Error << "Empty password from stdin"<< lend;
			this->SetExitcode(1);
		}

		logg << Logger::Debug << "Read '" << this->password << "' from stdin"<<lend;

	}
	else
	{
		logg << Logger::Debug << "Reading password from file '" << path << "'" << lend;

	}
}
