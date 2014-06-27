#include "ControlApp.h"
#include "Config.h"

#include "Secop.h"
#include "WebServer.h"
#include "DiskHelper.h"
#include "ServiceHelper.h"
#include "Luks.h"

#include <functional>

#include <unistd.h>

using namespace Utils;
using namespace std::placeholders;

#ifdef OPI_BUILD_LOCAL
#define OPI_MMC_DEV "sdg"
#define OPI_MMC_PART "sdg1"
#define STORAGE_DEV  "/dev/sdg"
#define STORAGE_PART "/dev/sdg1"
#endif

#ifdef OPI_BUILD_PACKAGE
#define OPI_MMC_DEV "mmcblk0"
#define OPI_MMC_PART "mmcblk0p1"
#define STORAGE_DEV  "/dev/mmcblk0"
#define STORAGE_PART "/dev/mmcblk0p1"
#endif


ControlApp::ControlApp() : DaemonApplication("opi-control","/var/run","root","root")
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


	logg << Logger::Debug << "Checking device: "<< STORAGE_DEV <<lend;

	if( ! DiskHelper::DeviceExists( STORAGE_DEV ) )
	{
		logg << Logger::Error << "Device not present"<<lend;
		return;
	}

	if( DiskHelper::DeviceSize( OPI_MMC_DEV ) == 0 )
	{
		logg << Logger::Error << "No space on device"<< lend;
		return;
	}

	if( ! Luks::isLuks( OPI_MMC_PART ) )
	{
		logg << Logger::Notice << "No Luks volume on device, "<< STORAGE_PART<<", creating"<<lend;

		DiskHelper::PartitionDevice( STORAGE_DEV );
		Luks l( STORAGE_PART);
		l.Format("secret");
		l.Open("opi","secret");

		DiskHelper::FormatPartition("/dev/mapper/opi","OPI");
	}
	else
	{
		logg << Logger::Notice << "LUKS volume found on "<<STORAGE_PART<< lend;

		Luks l( STORAGE_PART);

		if( ! l.Active("opi") )
		{
			logg << Logger::Debug << "Activating LUKS volume"<<lend;
			l.Open("opi","secret");
		}
	}

	string mpoint = DiskHelper::IsMounted("/dev/mapper/opi");
	if(  mpoint != "/var/opi" )
	{
		// Mounted somewhere else? (Should not be possible)
		if( mpoint != "" )
		{
			DiskHelper::Umount("/dev/mapper/opi");
		}
		DiskHelper::Mount("/dev/mapper/opi","/var/opi");
	}

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;
		}
	}

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
	ServiceHelper::Stop("secop");
	DiskHelper::Umount("/var/opi");
	Luks( STORAGE_PART).Close("opi");
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
	Secop::State st = Secop::Unknown;
	try
	{
		Secop s;

		st  = s.Status();
	}
	catch( runtime_error& e)
	{
		logg << Logger::Notice << "Failed to check status "<<e.what()<<lend;
	}

	logg << Logger::Debug << "Secop status : "<< st << lend;

	return (st != Secop::Uninitialized) && (st != Secop::Unknown);
}
