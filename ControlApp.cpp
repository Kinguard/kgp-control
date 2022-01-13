#include "Config.h"

#include "WebServer.h"
#include "InboundTest.h"
#include "ConnTest.h"
#include "PasswordFile.h"


#include <libutils/HttpStatusCodes.h>
#include <libutils/NetServices.h>
#include <libutils/FileUtils.h>
#include <libutils/ConfigFile.h>
#include <libutils/UserGroups.h>
#include <libutils/Process.h>
#include <libutils/Thread.h>
#include <libutils/String.h>

#include <libopi/Secop.h>
#include <libopi/SysInfo.h>
#include <libopi/SysConfig.h>
#include <libopi/DnsServer.h>
#include <libopi/JsonHelper.h>
#include <libopi/DiskHelper.h>
#include <libopi/AuthServer.h>
#include <libopi/Notification.h>
#include <libopi/ServiceHelper.h>

#include <kinguard/MailManager.h>
#include <kinguard/UserManager.h>
#include <kinguard/BackupManager.h>
#include <kinguard/SystemManager.h>
#include <kinguard/StorageManager.h>
#include <kinguard/IdentityManager.h>

#include <functional>
#include <memory>

#include <syslog.h>
#include <unistd.h>

#include "ControlApp.h"


// Convenience defines
#define SCFG	(OPI::SysConfig())
#define SAREA (SCFG.GetKeyAsString("filesystem","storagemount"))

using namespace Utils;
using namespace Utils::HTTP;
using namespace std::placeholders;

using namespace OPI;
using namespace OPI::CryptoHelper;

using namespace KGP;

//#define DEBUG (logg << Logger::Debug)

ControlApp::ControlApp() :
	DaemonApplication("opi-control","/var/run","root","root"),
	state(ControlState::State::AskInitCheckRestore),
	skiprestore(false),
	storagemanager(StorageManager::Instance())
{
}

void ControlApp::Startup()
{
	// Divert logger to syslog
	openlog( "opi-control", LOG_PERROR, LOG_DAEMON);
	logg.SetOutputter( [](const string& msg){ syslog(LOG_INFO, "%s",msg.c_str());});
	logg.SetLogName("");

	logg << Logger::Info << "Starting"<<lend;

	Utils::SigHandler::Instance().AddHandler(SIGTERM, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGINT, std::bind(&ControlApp::SigTerm, this, _1) );
	Utils::SigHandler::Instance().AddHandler(SIGHUP, std::bind(&ControlApp::SigHup, this, _1) );

	sigignore(SIGUSR1);

	this->options.AddOption( Option('D', "debug", Option::ArgNone,"0","Debug logging") );
	this->options.AddOption( Option('r', "webroot", Option::ArgRequired, "/usr/share/opi-control/web", "webroot to use"));
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

bool ControlApp::DoLogin()
{
	logg << Logger::Debug << "Logging in to OP backend" << lend;
	AuthServer s( this->unit_id);
	int resultcode = Status::Ok;
	json ret;

	tie(resultcode, ret) = s.Login();

	if( resultcode != Status::Ok && resultcode != Status::Forbidden )
	{
		logg << Logger::Error << "Unexpected reply from server "<< resultcode <<lend;
		this->global_error ="Unexpected reply from OP server ("+ ret["desc"].get<string>()+")";
		return false;
	}

	if( resultcode == Status::Forbidden )
	{
		logg << Logger::Debug << "Send Secret"<<lend;

		if( ! ret.contains("reply") || ! ret["reply"].contains("challange")  )
		{
			logg << Logger::Error << "Missing argument from server "<< resultcode <<lend;
			this->global_error ="Missing argument in reply from server";
			return false;
		}

		// Got new challenge to encrypt with master
		string challenge = ret["reply"]["challange"].get<string>();

		RSAWrapperPtr c = AuthServer::GetKeysFromSecop();

		SecVector<byte> key = PBKDF2(SecString(this->masterpassword.c_str(), this->masterpassword.size() ), 32 );
		AESWrapper aes( key );

		string cryptchal = Base64Encode( aes.Encrypt( challenge ) );

		tie(resultcode, ret) = s.SendSecret(cryptchal, Base64Encode(c->PubKeyAsPEM()) );
		if( resultcode != Status::Ok )
		{
			if( resultcode == Status::Forbidden)
			{
				this->global_error ="Failed to authenticate with OP server. Wrong activation code or password.";
			}
			else
			{
				this->global_error ="Failed to communicate with OP server";
			}
			return false;
		}

		if( ret.contains("token") && ret["token"].is_string() )
		{
			this->token = ret["token"].get<string>();
		}
		else
		{
			logg << Logger::Error << "Missing argument in reply"<<lend;
			this->global_error ="Failed to communicate with OP server (Missing argument)";
			return false;
		}

	}
	else
	{
		if( ret.contains("token") && ret["token"].is_string() )
		{
			this->token = ret["token"].get<string>();
		}
		else
		{
			this->global_error ="Missing argument in reply from OP server";
			logg << Logger::Error << "Missing argument in reply"<<lend;
			return false;
		}
	}

	return true;
}

void ControlApp::StopWebserver()
{
	logg << Logger::Debug << "Stopping webserver" << lend;
	if( this->ws != nullptr )
	{
		// ID manager might have outstanding work, make sure its completed
		// before we shutdown webserver
		IdentityManager::Instance().CleanUp();

		this->ws->Stop();
	}
}

void ControlApp::WorkOutInitialState()
{
	// Workout initial state

	this->state = ControlState::State::AskInitCheckRestore;
	this->skiprestore = false;

	bool hasUnitId = false;
	bool isOPDevice = SysInfo::isOP();

	bool isConfigured = SystemManager::Instance().IsConfigured();
	bool hasStorage = this->storagemanager.StorageAreaExists();

	StorageConfig scfg;

	if ( ! hasStorage && scfg.isValid() && scfg.UsePhysicalStorage(Storage::Physical::None) )
	{
		// Device uses same physical device as OS, thus no separate storage
		hasStorage = true;
	}

	if( SCFG.HasKey("hostinfo", "unitid") )
	{
		this->state = ControlState::State::AskUnlock;
		this->unit_id = SCFG.GetKeyAsString("hostinfo", "unitid");
		hasUnitId = true;
	}

	using UnitID = bool;
	using OPDevice = bool;
	using StorageAvailable = bool;
	using UnitConfigured = bool;
	using StartCond = std::tuple<UnitConfigured, StorageAvailable, UnitID, OPDevice>;

	static const map<StartCond, int> start =
	{	//  conf	storage	Unitid	OPdev
		{ { 0,		0,		0,		0 },	ControlState::State::AskDevice },
		{ { 0,		0,		0,		1 },	ControlState::State::AskInitCheckRestore },
		{ { 0,		0,		1,		0 },	ControlState::State::AskReInitCheckRestore },
		{ { 0,		0,		1,		1 },	ControlState::State::AskReInitCheckRestore },
		{ { 0,		1,		0,		0 },	ControlState::State::AskInitCheckRestore },
		{ { 0,		1,		0,		1 },	ControlState::State::AskInitCheckRestore },
		{ { 0,		1,		1,		0 },	ControlState::State::AskReInitCheckRestore },
		{ { 0,		1,		1,		1 },	ControlState::State::AskReInitCheckRestore },
		{ { 1,		0,		0,		0 },	ControlState::State::AskInitCheckRestore },
		{ { 1,		0,		0,		1 },	ControlState::State::AskInitCheckRestore },
		{ { 1,		0,		1,		0 },	ControlState::State::AskReInitCheckRestore },
		{ { 1,		0,		1,		1 },	ControlState::State::AskReInitCheckRestore },
		{ { 1,		1,		0,		0 },	ControlState::State::AskUnlock },
		{ { 1,		1,		0,		1 },	ControlState::State::Error },
		{ { 1,		1,		1,		0 },	ControlState::State::AskUnlock },
		{ { 1,		1,		1,		1 },	ControlState::State::AskUnlock },
	};

	logg << Logger::Debug << "Start conditions: " << isConfigured << "," << hasStorage<< "," << hasUnitId<< "," << isOPDevice << lend;

	this->state = start.at( {isConfigured, hasStorage, hasUnitId, isOPDevice} );

	logg << Logger::Debug << "Seleced start state " << this->state << lend;

	// Check environment
	if( SysInfo::fixedStorage() && ! this->storagemanager.DeviceExists() )
	{
		// We should have a fixed storage and that is not present!
		logg << Logger::Error << "Device not present"<<lend;
		this->state = ControlState::State::Error;
	}

	// Initial state determined
}

void ControlApp::Main()
{

	logg << Logger::Info << "------ !!!   TODO  !!!! ---------"<<lend;
	logg << Logger::Info << "Wrap/test reading of sysconfig keys to not get unwanted exceptions."<<lend;
	logg << Logger::Info << "------ !!!   End TODO  !!!! ---------"<<lend;

	if( this->options["debug"] == "1" )
	{
		logg << Logger::Info << "Increase logging to debug level "<<lend;
		logg.SetLevel(Logger::Debug);
	}

	logg << Logger::Info << "Running on: " << sysinfo.SysTypeText[sysinfo.Type()] << lend;

	logg << Logger::Debug << "Using storage device: "<< this->storagemanager.DevicePath() <<lend;


	// Preconditions
	// Secop should not be running
	if( ServiceHelper::IsRunning("secop") )
	{
		if( this->SecopUnlocked() )
		{
			// We are running on an already started system, exit gracefully
			logg << Logger::Notice << "Secop already unlocked, system likely up. Terminating opi-control"<<lend;
			return;
		}

		logg << Logger::Debug << "Stop running secop instance"<<lend;
		ServiceHelper::Stop("secop");
	}
	// Temp mountpoint must exist
	if( !File::DirExists(TMP_MOUNT) )
	{
		File::MkPath(TMP_MOUNT, File::UserRWX | File::GroupRX | File::OtherRX );
	}

	this->WorkOutInitialState();

	// Try use password from USB or cfg in /root to unlock device if possible
	if( this->state == ControlState::State::AskUnlock )
	{
		if( this->GetPasswordUSB() || this->GetPasswordRoot() )
		{
			if( this->DoUnlock( this->masterpassword, false ) )
			{
				this->state = ControlState::State::Completed;
			}
		}
	}

	using namespace Utils::Net::Service;

	InboundTestPtr ibt;
	TcpServerPtr redirector;

	if( this->state == ControlState::State::AskInitCheckRestore )
	{
		// Initial setup of clean device, start connection tests.
		logg << Logger::Debug << "Starting inbound connection tests"<<lend;
		ibt = make_shared<InboundTest>( vector<uint16_t>({SMTP,Service::HTTP,IMAP2, Submission, IMAPS, ALT_SMTP }) );
		ibt->Start();

		logg << Logger::Debug << "Doing connection tests"<<lend;
		ConnTest ct(SCFG.GetKeyAsString( "setup", "conntesthost"));
		this->connstatus = ct.DoTest();
	}
	else if ( this->state != ControlState::State::Completed )
	{
		logg << Logger::Debug << "Starting redirect service on port 80"<<lend;
		redirector = make_shared<TcpServer>( Service::HTTP );

		redirector->Start();
	}

	if( this->state != ControlState::State::Completed )
	{

		this->statemachine = make_shared<ControlState>( this, static_cast<uint8_t>(this->state) );

		this->ws = make_shared<WebServer>( std::bind(&ControlApp::WebCallback,this, _1), this->options["webroot"] );

		if( this->state == ControlState::State::Error )
		{
			OPI::notification.Notify( OPI::Notification::Error, "Possible error: " + this->global_error);
		}
		else
		{
			OPI::notification.Notify( OPI::Notification::Waiting, "Waiting for user");
		}

		this->ws->Start();

		this->ws->Join();
	}

	if( ibt )
	{
		logg << Logger::Debug << "Stopping inbound connection tests"<<lend;
		ibt->Stop();
		ibt.reset();
	}

	if( redirector )
	{
		logg << Logger::Debug << "Stopping redirect service"<<lend;
		redirector->Stop();
		redirector.reset();
	}

	if( this->state == ControlState::State::Completed )
	{
		// We should have reached a positive end of init, start services
		logg << Logger::Debug << "Init completed, start servers"<<lend;
		ServiceHelper::Start( "mysql" );
		ServiceHelper::Start( "postfix" );
		ServiceHelper::Start( "dovecot" );
		ServiceHelper::Start( "fetchmail" );
		ServiceHelper::Start( "nginx" );

		// Add eventhandler to process completed startup
		this->evhandler.AddEvent( 90, std::bind(
									  Process::Exec,
									  "/bin/run-parts --lsbsysinit  -- /etc/opi-control/completed" ));

		OPI::notification.Notify( OPI::Notification::Completed, "Opi Control completed ");
	}
	else if( this->state == ControlState::State::ShutDown )
	{
		logg << Logger::Debug << "Register power off opi"<<lend;

		this->evhandler.AddEvent( 99, bind(Process::Exec, "/sbin/poweroff") );
	}
	else if( this->state == ControlState::State::Reboot )
	{
		logg << Logger::Debug << "Register reboot opi"<<lend;
		this->evhandler.AddEvent( 99, bind(Process::Exec, "/sbin/reboot") );
	}

	logg << Logger::Debug << "Calling all eventhandlers"<< lend;
	this->evhandler.CallEvents();

	logg << Logger::Debug << "OPI control finnished " <<lend;
}

void ControlApp::ShutDown()
{
	curl_global_cleanup();
	logg << Logger::Debug << "Shutting down"<< lend;
}

void ControlApp::SigTerm(int signo)
{
	(void) signo;
	// Possibly shutdown webserver
	if( this->ws != nullptr )
	{
		this->StopWebserver();
	}

}

void ControlApp::SigHup(int signo)
{
	(void) signo;
}

ControlApp::~ControlApp() = default;

json ControlApp::WebCallback(json v)
{

#if 0
	logg << Logger::Debug << "Got call from webserver\n"<<v.toStyledString()<<lend;
#endif

	json ret;
	bool status = true;

	this->statemachine->ResetReturnData();

	if( v.contains("cmd") )
	{
		string cmd = v["cmd"].get<string>();

		try
		{
			if( cmd == "init" )
			{
				this->masterpassword = v["password"].get<string>();
				this->unit_id = v["unit_id"].get<string>();
				this->WriteConfig();

				this->statemachine->Init( v["save"].get<bool>() );
			}
			else if( cmd == "reinit" )
			{
				this->masterpassword = v["password"].get<string>();

				this->statemachine->ReInit( v["save"].get<bool>() );
			}
			else if( cmd == "restore" )
			{
				this->statemachine->Restore(v["restore"].get<bool>(), v["path"].get<string>() );
			}
			else if( cmd == "adduser" )
			{
				this->statemachine->AddUser( v["username"].get<string>(), v["displayname"].get<string>(), v["password"].get<string>());
			}
			else if( cmd == "opiname" )
			{
				this->statemachine->OpiName( v["hostname"].get<string>(), v["domain"].get<string>() );
			}
			else if( cmd == "unlock" )
			{
				this->statemachine->Unlock( v["password"].get<string>(), v["save"].get<bool>()  );
			}
			else if( cmd == "terminate" )
			{
				this->statemachine->Terminate();
			}
			else if( cmd == "shutdown" )
			{
				this->statemachine->ShutDown( v["action"].get<string>() );
			}
			else if( cmd == "portstatus" )
			{
				return this->connstatus;
			}
			else if( cmd == "gettype" )
			{
				json ret;
				ret["type"] = sysinfo.SysTypeText[sysinfo.Type()];

				// Short circuit for now
				// Todo: revisit and refactor when we have better method
				if ( OPI::SysInfo::isOP() )
				{
					ret["provider"] = "openproducts";
				}
				else
				{
					ret["provider"] = "kgp";
				}
				return ret;
			}
			else if( cmd == "getdomains" )
			{
				json ret = json::object();
				ret["domains"]=json::array();
				list<string> domains;
				IdentityManager& idmgr = IdentityManager::Instance();

				if( idmgr.HasDnsProvider() )
				{
					list<string> domains = idmgr.DnsAvailableDomains();
					for(const auto &domain: domains)
					{
						ret["domains"].push_back(domain);
					}
					if( domains.size() > 0 )
					{
						ret["domain"]=domains.front();
					}
					else
					{
						// Really should not happen
						logg << Logger::Error << "Missing DNS providers!"<<lend;
					}
				}
				return ret;
			}
			else if( cmd == "getstoragedevices")
			{
				json ret;

				StorageManager& mgr = StorageManager::Instance();

				list<Storage::Physical::Physical> pts = mgr.QueryPhysical();

				list<Storage::Physical::Physical> phys;
				list<Storage::Logical::Logical> logical;
				list<Storage::Encryption::Encryption> encrypt;

				for(const auto& pt : pts)
				{
					phys.emplace_back( pt);

					list<Storage::Logical::Logical> lts = mgr.QueryLogical(pt.Type());
					for(const auto& lt : lts)
					{
						logical.emplace_back( lt);

						list<Storage::Encryption::Encryption> encs = mgr.QueryEncryption(pt.Type(), lt.Type());
						for( const auto& enc : encs)
						{
							encrypt.emplace_back( enc);
						}
					}

				}
				phys.sort();
				phys.unique();
				ret["storagephysical"] = json::array();
				for(const auto& ph: phys)
				{
					json p;
					p["name"] = ph.Name();
					p["description"] = ph.Description();

					ret["storagephysical"].push_back(p);
				}

				logical.sort();
				logical.unique();
				ret["storagelogical"] = json::array();
				for(const auto& log: logical)
				{
					json p;
					p["name"] = log.Name();
					p["description"] = log.Description();

					ret["storagelogical"].push_back(p);
				}

				encrypt.sort();
				encrypt.unique();
				ret["storageencryption"]= json::array();
				for(const auto& enc: encrypt)
				{
					json p;
					p["name"] = enc.Name();
					p["description"] = enc.Description();

					ret["storageencryption"].push_back(p);
				}

				list<StorageDevice> partitions = mgr.QueryStoragePartitions();
				ret["storagepartitions"] = json::array();
				for(const auto& part: partitions)
				{
					json d;
					d["devname"]=part.DeviceName();
					d["devpath"]=part.DevicePath();
					d["model"] = part.Model();
					d["size"] =  Utils::String::ToHuman( part.Size() );
					ret["storagepartitions"].push_back(d);
				}

				list<StorageDevice> disks = mgr.QueryStorageDevices();
				ret["storagedevices"] = json::array();
				for(const auto& disk: disks)
				{
					json d;
					d["devname"]=disk.DeviceName();
					d["devpath"]=disk.DevicePath();
					d["model"] = disk.Model();
					d["size"] =  Utils::String::ToHuman( disk.Size());
					ret["storagedevices"].push_back(d);
				}

				return ret;
			}
			else if( cmd == "deviceconfig" )
			{
				list<string> devices = JsonHelper::FromJsonArray(v["devices"]);
				this->statemachine->StorageConfig(
							v["physical"].get<string>(),
							v["logical"].get<string>(),
							v["encryption"].get<string>(),
							devices
							);
			}
			else if( cmd == "status" )
			{
				json ret;
				json progress;

				uint8_t state = this->statemachine->State();
				ret["state"] = state;
				if( this->cache.find( state) != this->cache.end() )
				{
					ret["cache"] = this->cache[state];
				}

				bool retval = false;
				string strprog;

				tie(retval,strprog) = Process::Exec( "/usr/share/opi-backup/progress.sh" );
				if ( retval )
				{
					try
					{
						progress = json::parse(strprog);
						ret["progress"] = progress;
						retval = true;
					}
					catch (json::parse_error& err)
					{
						logg << Logger::Error << "Failed to parse restore progress (" << err.what()<< ")" << lend;
						retval = false;
					}
				}
				else
				{
					logg << Logger::Error << "Failed to run restore progress check." << lend;
				}
				return ret;
			}
			else
			{
				status = false;
				this->global_error = "Unknown command";
			}
		}
		catch( std::runtime_error& err)
		{
			status = false;
			logg << Logger::Error << "Statemachine failed "<< err.what() << lend;
			this->global_error = string("Internal error (") + err.what() +")";
		}

		if( status )
		{
			// Statemachine run, i.e no error, return result
			this->state = this->statemachine->State();
			tie(status, ret) = this->statemachine->RetValue();
		}

		ret["status"]=status;
		ret["state"]=this->state;
		if(!status)
		{
			ret["errmsg"]=this->global_error;
		}
	}
	else
	{
		ret["status"] = false;
		ret["state"] = this->state;
		ret["errmsg"] = "Internal error (Missing command)";
	}

	return ret;
}

bool ControlApp::DoUnlock(const string &pwd, bool savepass)
{
	logg << Logger::Debug << "Unlock storage"<<lend;

	if( ! this->storagemanager.Open(pwd) )
	{
		this->global_error = "Unable to unlock crypto storage. (Wrong password?)";
		return false;
	}

	logg << Logger::Debug << "Storage device opened"<< lend;

	StorageConfig scfg;

	if( ! scfg.UsePhysicalStorage(Storage::Physical::None) )
	{
		if( ! this->storagemanager.mountDevice( SCFG.GetKeyAsString("filesystem","storagemount") ) )
		{
			this->global_error = "Unable to access storage";
			return false;
		}
	}

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;

			sleep(1);

			if( ! ServiceHelper::IsRunning("secop") )
			{
				this->global_error = "Failed to start password database";
				return false;
			}

		}
		else
		{
			// Give daemon time to start.
			sleep(1);
		}
	}

	try{
		if( ! this->SecopUnlocked())
		{
			logg << Logger::Debug << "Trying to unlock secop"<<lend;
			if( ! Secop().Init(pwd) )
			{
				this->global_error = "Failed to unlock password database";
				return false;
			}
		}
	}
	catch(std::runtime_error& err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Failed to unlock password database ("+string(err.what() )+")";
		return false;
	}

	if( savepass )
	{
		logg << Logger::Debug << "Try saving password on successful unlock"<<lend;
		this->masterpassword = pwd;
		if( ! this->SetPasswordUSB() )
		{
			logg << Logger::Error << "Failed to write password to USB device"<<lend;
			return false;
		}
	}
	else
	{
		logg << Logger::Debug << "Not saving password on successful unlock"<<lend;
	}
	return true;
}

bool ControlApp::DoInit( bool savepassword )
{

	if ( ! this->InitializeStorage() )
	{
		logg << Logger::Error << "Failed to initialize storage area" <<lend;
		return false;
	}

	if( ! ServiceHelper::IsRunning("secop") )
	{
		logg << Logger::Debug << "Starting Secop server"<<lend;
		if( ! ServiceHelper::Start("secop") )
		{
			logg << Logger::Notice << "Failed to start secop"<<lend;
			this->global_error = "Failed to start krypto database";
			return false;
		}
		else
		{
			// Give daemon time to start.
			sleep(1);
		}
	}

	try{
		if( ! this->SecopUnlocked())
		{
			logg << Logger::Debug << "Trying to unlock secop"<<lend;

			if( ! Secop().Init( this->masterpassword ) )
			{
				this->global_error = "Wrong password for password store";
				return false;
			}
		}
	}
	catch(std::runtime_error& err)
	{
		logg << Logger::Error << "Failed to unlock Secop:"<<err.what()<<lend;
		this->global_error = "Wrong password for password store";
		return false;
	}

	if( !this->RegisterKeys() )
	{
		return false;
	}

	this->WriteConfig( );

	// We only try to login if we run an OP enabled device
	bool loggedin = false;
	if( this->hasUnitID() )
	{
		for( int i=0; i<3; i++ )
		{
			try
			{
				if( this->DoLogin() )
				{
					loggedin = true;
					break;
				}
			}
			catch(runtime_error& err )
			{
				this->global_error ="Failed to login with OP server ("+string(err.what())+")";
				logg << Logger::Notice << "Failed to login to backend: "<< err.what()<<lend;
				return false;
			}
		}
	}
	else
	{
		// None OP, we are by definition logged in.
		// Todo: Revise when needed.
		loggedin = true;
	}

	// Possibly save password to usb device
	if(  loggedin && savepassword )
	{
		logg << Logger::Debug << "Try saving password on successful init"<<lend;
		if( ! this->SetPasswordUSB() )
		{
			return false;
		}
	}
	else
	{
		logg << Logger::Debug << "Not saving password on successful init"<<lend;
	}

	// Save password for backup encryption

	// Setup backup config
	logg << Logger::Debug << "Save backup config"<<lend;
	json backupcfg;
	backupcfg["password"] = this->masterpassword;
	BackupManager::Configure( backupcfg );

	//Only on OP-enabled devices
	if( this->hasUnitID() )
	{
		// TODO: THis have to go into IdManager somehow.
		// Function exists in Manager but is private.
		// Maybe integrate in AddDNSname or similar
		logg << Logger::Debug << "Register public dnskey with backend"<< lend;
		stringstream pk;
		for( const auto &row: File::GetContent(SCFG.GetKeyAsString("dns","dnspubkey")) )
		{
			pk << row << "\n";
		}
		DnsServer dns;
		string pubkey = Base64Encode( pk.str() );
		if( ! dns.RegisterPublicKey(this->unit_id, pubkey, this->token ) )
		{
			this->global_error ="Failed to register dns key";
			logg << Logger::Error << this->global_error << lend;
			return false;
		}
	}

	return true;
}

bool ControlApp::AddUser(const string& user, const string& display, const string& password)
{
	logg << "Add user "<<user<<" "<< display << lend;

	if(! this->SecopUnlocked() )
	{
		this->global_error = "Failed to connect with password database";
		return false;
	}

	UserManagerPtr umgr = UserManager::Instance();

	if( ! umgr->AddUser(user, password, display, true) )
	{
		this->global_error = umgr->StrError();
		return false;
	}

	this->first_user = user;

	return true;
}
bool ControlApp::SetDNSName()
{
	return this->SetDNSName(this->hostname,this->domain);
}
bool ControlApp::SetDNSName(const string &hostname,const string &domain)
{

	// Allow empty domain by setting it to default localdomain
	string fixdomain = (domain.length()==0)?"localdomain":domain;

	logg << Logger::Debug << "Set dns, hostname: " << hostname << " domain: " << fixdomain << lend;

	IdentityManager& idmgr = IdentityManager::Instance();

	/* If the domain is in the list of available domains, check with provider.
	*  if the domain is "custom", there is no DNS provider to check with...
	*/
	if (idmgr.DnsDomainAvailable(fixdomain) )
	{
		logg << Logger::Debug << "Domain is managed" << lend;
		if( ! idmgr.HasDnsProvider() )
		{
			logg << Logger::Error << "No DNS provider available" << lend;
			this->global_error = "No DNS provider available";
			return false;
		}

		if( ! idmgr.DnsNameAvailable(hostname, domain))
		{
			this->global_error = "Hostname not available";
			logg << Logger::Notice << "Set dns name: " << this->global_error << lend;
			return false;
		}

		if( ! idmgr.AddDnsName(hostname, fixdomain ) )
		{
			this->global_error = idmgr.StrError();
			logg << Logger::Error << this->global_error << lend;
			return false;
		}
	}
	else
	{
		SysConfig sysconfig(true);
		sysconfig.PutKey("dns","enabled",false);
	}

	logg << Logger::Debug << "Setting new hostname and domain to: " << hostname << "." << domain << lend;
	if( ! idmgr.SetFqdn(hostname, fixdomain) )
	{
		this->global_error = idmgr.StrError();
		logg << Logger::Error << this->global_error<< lend;
		return false;
	}

	logg << Logger::Info << "Generate certificate for unit" << lend;

	// Backend should be set by certhandler
	if( ! idmgr.CreateCertificate() )
	{
		this->global_error ="Failed to generate certificate:";
		this->global_error += idmgr.StrError();
		logg << Logger::Error << this->global_error << lend;
		return false;
	}


	/*
	 * If we have no first user this indicates old SD card with info and users
	 * skip adding in this case.
	 */
	if( this->first_user != "" )
	{
		try
		{
			// Add first user email on opidomain
			string fqdn = hostname +"."+fixdomain;

			MailManager& mmgr = MailManager::Instance();
			mmgr.SetAddress(fqdn,this->first_user,this->first_user);
		}
		catch(runtime_error& err)
		{
			logg << Logger::Error << "Failed to add first user email"<<err.what()<<lend;
			this->global_error = "Failed to update mailsettings for user";
			return false;
		}
	}

	return true;
}

/**
 * @brief ControlApp::SetHostName, set static hostname and get self signed cert
 *        THis is the alternative/fallback if we have no DNS-provider
 * @return true upon success
 */
bool ControlApp::SetHostName()
{
	// CUrrently hardcode this, most likely change this later and ask user?
	try {
		IdentityManager& idmgr = IdentityManager::Instance();

		if( ! idmgr.SetFqdn("kgpunit", "localdomain") )
		{
			logg << Logger::Notice << "Failed to set hostname or domain" << lend;
			this->global_error = "Failed to set hostname or domain";
			return false;
		}

		if( ! idmgr.CreateCertificate() )
		{
			logg << Logger::Notice << "Failed to create certificate" << lend;
			this->global_error = "Failed to create certificate";
			return false;
		}

	}
	catch( runtime_error& err)
	{
		logg << Logger::Error << "Failed to set hostname: "<< err.what() << lend;
		this->global_error = string("Failed to set hostname (") + err.what() + string(")");
		return false;
	}

	return true;
}

bool ControlApp::SecopUnlocked()
{
	Secop::State st = Secop::Unknown;
	int retries = 3;

	while( st == Secop::Unknown && retries > 0)
	{
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

		if( st == Secop::Unknown && retries > 0 )
		{
			// Give secop some more time getting up and running
			sleep(1);
		}

		--retries;
	}

	return (st != Secop::Uninitialized) && (st != Secop::Unknown);
}

bool ControlApp::InitializeStorage()
{
	logg << Logger::Debug << "Initialize storage device" << lend;

	return this->storagemanager.Initialize(this->masterpassword);
}

bool ControlApp::RegisterKeys( )
{
	logg << Logger::Debug << "Register keys"<<lend;

	IdentityManager& idmgr = IdentityManager::Instance();

	if( ! idmgr.RegisterKeys() )
	{
		this->global_error = idmgr.StrError();
		logg << Logger::Error << this->global_error <<lend;
		return false;
	}

	return true;
}

bool ControlApp::GetPasswordUSB()
{
	logg << Logger::Debug << "Get password from "<< sysinfo.PasswordDevice() <<lend;

	bool ret = false;

	if( ! DiskHelper::DeviceExists( sysinfo.PasswordDevice() ) )
	{
		return false;
	}

	try
	{
		if( ! File::DirExists("/mnt/usb") )
		{
			File::MkDir("/mnt/usb", File::UserRWX | File::GroupRX | File::OtherRX);
		}

		DiskHelper::Mount( sysinfo.PasswordDevice(), "/mnt/usb", false, false, "");

		if( File::DirExists( "/mnt/usb/opi") && File::FileExists("/mnt/usb/opi/opicred.bin") )
		{
			this->masterpassword = PasswordFile::Read("/mnt/usb/opi/opicred.bin");
			ret = true;
		}
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}

	if( DiskHelper::IsMounted( sysinfo.PasswordDevice() ) != "" )
	{
		DiskHelper::Umount( sysinfo.PasswordDevice() );
	}

	return ret;
}

bool ControlApp::GetPasswordRoot()
{
	logg << Logger::Debug << "Get password from os storage"<<lend;

	bool ret = false;

	try
	{
		if( File::FileExists("/root/.keepcfg/opicred.bin"))
		{
			this->masterpassword = PasswordFile::Read("/root/.keepcfg/opicred.bin");
			ret = true;
		}
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to retrieve password "<< e.what()<<lend;
	}


	return ret;
}

bool ControlApp::SetPasswordUSB()
{
	logg << Logger::Debug << "Store password on device "<<sysinfo.PasswordDevice()<<lend;
	bool ret = false;
	bool wasmounted = false;

	if( ! DiskHelper::DeviceExists( sysinfo.PasswordDevice() ) )
	{
		this->global_error ="Failed to save password on device (Device not found)";
		return false;
	}

	try
	{
		if( ! File::DirExists("/mnt/usb") )
		{
			File::MkDir("/mnt/usb", File::UserRWX | File::GroupRX | File::OtherRX);
		}

		string mpath = DiskHelper::IsMounted( sysinfo.PasswordDevice());
		wasmounted = mpath != "";

		if( ! wasmounted  )
		{
			DiskHelper::Mount( sysinfo.PasswordDevice(), "/mnt/usb", false, false, "");
			mpath = "/mnt/usb";
		}

		if( ! File::DirExists( mpath + "/opi" ) )
		{
			File::MkDir(mpath + "/opi", File::UserRWX | File::GroupRX | File::OtherRX);
		}

		logg << Logger::Debug << "Storing password at " << mpath + "/opi/opicred.bin" << lend;
		PasswordFile::Write( mpath + "/opi/opicred.bin", this->masterpassword );

		ret = true;
	}
	catch( CryptoPP::Exception& e)
	{
		logg << Logger::Info << "Failed to save password "<< e.what()<<lend;
		this->global_error ="Failed to save password on device (Crypto error)";
	}
	catch( ErrnoException& e)
	{
		logg << Logger::Info << "Failed to save password "<< e.what()<<lend;
		this->global_error ="Failed to save password on device";
	}

	if( ! wasmounted && DiskHelper::IsMounted( sysinfo.PasswordDevice() ) != "" )
	{
		DiskHelper::Umount( sysinfo.PasswordDevice() );
	}

	return ret;
}

bool ControlApp::SetPasswordRoot()
{
	return false;
}

bool ControlApp::GuessOPIName()
{
	logg << Logger::Debug << "Guess opi-name"<<lend;
	IdentityManager& idmgr = IdentityManager::Instance();
	try
	{

		string name, domain;

		tie(name, domain) = idmgr.GetFqdn();

		if( name != "" && domain != "" )
		{
			this->hostname = name;
			this->domain = domain;

			logg << Logger::Debug << "OPI-name, " << this->hostname << " domain: " << this->domain << ", sucessfully read from sysconfig"<<lend;
			return true;
		}
		logg << Logger::Notice << "OPI-name not found in sysconfig ("<<name<<")"<<", ("<<domain<<")"<<lend;
	}
	catch (std::runtime_error& e)
	{
		logg << Logger::Notice << "Failed to retrieve hostname or domain (" << e.what() << ")" <<lend;
	}

	// If not found try figure out from mail-addresses
	try
	{
		logg << Logger::Notice << "Trying to guess fqdn from mailconfig" <<lend;

		MailManager& mmgr = MailManager::Instance();

		list<string> valid_domains = idmgr.DnsAvailableDomains();
		list<string> names;
		list<string> domains = mmgr.GetDomains();
		for( const string& domain: domains )
		{
			list<string> parts=String::Split(domain, ".",2);
			if( find( valid_domains.begin(), valid_domains.end(), parts.back() ) != valid_domains.end() )
			{
				names.push_back(domain);
			}
		}

		// If we have only one match we assume this is our opi-name and try with that.
		if( names.size() != 1 )
		{
			return false;
		}
		list<string> fqdn = String::Split(names.front(),".",2);
		this->hostname = fqdn.front();
		this->domain = fqdn.back();

		return true;
	}
	catch(runtime_error& err)
	{
		logg << Logger::Notice << "Failed to guess OPIName: "<< err.what()<<lend;
		return false;
	}
}

bool ControlApp::SetupStorageConfig(const string &phys, const string &log, const string &enc, const list<string>& devs)
{
	logg << Logger::Debug << "Setup storage config with phys: " << phys << " logical: " << log << " encryption: " << enc << lend;
	try {
		StorageConfig cfg;

		cfg.PhysicalStorage( Storage::Physical::Physical::toType(phys.c_str()) );
		cfg.LogicalStorage( Storage::Logical::Logical::toType( log.c_str() ));
		cfg.EncryptionStorage( Storage::Encryption::Encryption::toType( enc.c_str() ));



		if( cfg.PhysicalStorage().Type() == Storage::Physical::Block )
		{
			cfg.PhysicalStorage(devs);
		}
		else if( cfg.PhysicalStorage().Type() == Storage::Physical::Partition )
		{
			if( devs.size() == 1 )
			{
				cfg.PhysicalStorage( devs.front() );
			}
			else
			{
				logg << Logger::Notice << "Partition storage requested but no device provided" << lend;
			}
		}

		bool isValid = cfg.isValid();

		if( ! isValid )
		{
			logg << Logger::Notice << "Storage config is NOT valid" << lend;
		}

		return isValid;

	}
	catch (std::exception& e)
	{
		logg << Logger::Error << "Failed set storage configuration" << e.what() << lend;
	}
	return false;
}

void ControlApp::WriteConfig()
{
	logg << Logger::Notice << "Uppdating sysconfig" <<lend;
	SysConfig sysconfig(true);

	if( this->unit_id != "" )
	{
		sysconfig.PutKey("hostinfo","unitid",this->unit_id);
	}
}

bool ControlApp::hasUnitID()
{
	return this->unit_id != "";
}


json ControlApp::CheckRestore()
{
	logg << Logger::Debug << "Check if restore should be performed"<<lend;

	if( this->skiprestore )
	{
		logg << Logger::Debug << "Restore manually cancelled"<<lend;
		return json();
	}

	if( this->storagemanager.UseLocking() && this->storagemanager.StorageAreaExists()  )
	{
		// We never do a restore if we have a locked device
		logg << Logger::Notice << "Found locked device, aborting"<<lend;
		return json();
	}

	if( this->masterpassword == "" )
	{
		// Need password to be able to get backups
		logg << Logger::Notice << "Missing password, restore impossible" << lend;

		return json();
	}

	logg << Logger::Debug << "Initializing backup manager" << lend;
	// Setup backup config
	json backupcfg;
	backupcfg["password"] = this->masterpassword;
	BackupManager::Configure( backupcfg );

	// Call backupmanager get backups
	json retval = BackupManager::Instance().GetBackups();

	if( ! retval.is_null() )
	{
		//Update cache with backups
		if( retval.contains("local") )
		{
			this->cache[ControlState::State::AskRestore]["local"] = retval["local"];
		}

		if( retval.contains("remote") )
		{
			this->cache[ControlState::State::AskRestore]["remote"] = retval["remote"];
		}
	}

	return retval;
}

bool ControlApp::DoRestore(const string &path)
{
	logg << Logger::Debug << "Do restore backup"<<lend;
	// Setup SD-card
	if( ! this->InitializeStorage() )
	{
		this->global_error ="Restore backup - failed to initialize storage device";
		return false;
	}


	if( ! BackupManager::Instance().RestoreBackup(path) )
	{
		this->global_error = BackupManager::Instance().StrError();
		return false;
	}

	// Reload state that could have changed
	if( SCFG.HasKey("hostinfo", "unitid") )
	{
		this->unit_id = SCFG.GetKeyAsString("hostinfo", "unitid");
		logg << Logger::Debug << "Setting unit-id: [" << this->unit_id << "]" << lend;
	}
	else
	{
		logg << Logger::Debug << "No unitid available after restore." << lend;
	}
	return true;
}
