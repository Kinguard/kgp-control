#include "ControlState.h"

#include <libutils/Process.h>
#include <libutils/Thread.h>
#include <libutils/String.h>

#include <kinguard/IdentityManager.h>
#include <kinguard/StorageManager.h>
#include <kinguard/UserManager.h>

#include <libopi/JsonHelper.h>

#include "ControlApp.h"
#include "Config.h"

using namespace OPI;
using namespace KGP;
using namespace Utils;

ControlState::ControlState(ControlApp *app, uint8_t state): status(true), app(app)
{
	this->statemap =
	{
		{ State::Idle,					[this](EventData* data){this->StIdle(data);}},
		{ State::Error,					[this](EventData* data){this->StError(data);}},
		{ State::InitCheckRestore,		[this](EventData* data){this->StInitCheckRestore(data);}},
		{ State::Init,					[this](EventData* data){this->StInit(data);}},
		{ State::ReInitCheckrestore,	[this](EventData* data){this->StReInitCheckrestore(data);}},
		{ State::ReInit,				[this](EventData* data){this->StReInit(data);}},
		{ State::AskRestore,			[this](EventData* data){this->StAskRestore(data);}},
		{ State::Restore,				[this](EventData* data){this->StRestore(data);}},
		{ State::AskUnlock,				[this](EventData* data){this->StAskUnlock(data);}},
		{ State::Unlock,				[this](EventData* data){this->StDoUnlock(data);}},
		{ State::Terminate,				[this](EventData* data){this->StTerminate(data);}},
		{ State::ShutDown,				[this](EventData* data){this->StShutDown(data);}},
		{ State::Reboot,				[this](EventData* data){this->StReboot(data);}},
		{ State::Completed,				[this](EventData* data){this->StCompleted(data);}},
		{ State::AskAddUser,			[this](EventData* data){this->StAskAddUser(data);}},
		{ State::AddUser,				[this](EventData* data){this->StAddUser(data);}},
		{ State::AskOpiName,			[this](EventData* data){this->StAskOpiName(data);}},
		{ State::OpiName,				[this](EventData* data){this->StOpiName(data);}},
		{ State::Hostname,				[this](EventData* data){this->StHostName(data);}},
		{ State::AskInitCheckRestore,	[this](EventData* data){this->StAskInitCheckRestore(data);}},
		{ State::AskReInitCheckRestore,	[this](EventData* data){this->StAskReInitCheckRestore(data);}},
		{ State::AskDevice,				[this](EventData* data){this->StAskDevice(data);}},
		{ State::SelectDevices,			[this](EventData* data){this->StDevice(data);}},
	};

	this->TriggerEvent( state, nullptr);
}

/*
 * External events
 */
void ControlState::Init(bool savepassword)
{
	ScopedLog l("Init");

	if( ! this->ValidState( {State::Idle, State::Init, State::AskInitCheckRestore} ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData* data = new ControlData;
	data->data["savepassword"] = savepassword;

	this->TriggerEvent( ControlState::State::InitCheckRestore, data );
}

void ControlState::ReInit(bool savepassword)
{
	ScopedLog l("Reinit");

	if( ! this->ValidState( {State::Idle, State::ReInit, State::AskReInitCheckRestore } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["savepassword"] = savepassword;

	this->TriggerEvent( ControlState::State::ReInitCheckrestore, data );

}

void ControlState::Restore(bool dorestore, const string &path)
{
	ScopedLog l("Restore");

	if( ! this->ValidState( {State::AskRestore } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["restore"] = dorestore;
	data->data["path"] = path;

	this->TriggerEvent( State::Restore, data );
}

void ControlState::AddUser(const string &username, const string &displayname, const string &password)
{
	ScopedLog l("AddUser");

	if( ! this->ValidState( {State::AskAddUser } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["username"] = username;
	data->data["displayname"] = displayname;
	data->data["password"] = password;

	this->TriggerEvent( State::AddUser, data );
}

void ControlState::OpiName(const string &hostname, const string& domain)
{
	ScopedLog l("OpiName");

	if( ! this->ValidState( {State::AskOpiName } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["hostname"] = hostname;
	data->data["domain"] = domain;

	this->TriggerEvent( State::OpiName, data );
}

void ControlState::Unlock(const string &password, bool save)
{
	ScopedLog l("Unlock");

	if( ! this->ValidState( {State::Idle, State::AskUnlock } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["password"] = password;
	data->data["save"] = save;

	this->TriggerEvent( State::Unlock, data );
}

void ControlState::Terminate()
{
	ScopedLog l("Terminate");

	if( ! this->ValidState( {State::Idle, State::Completed } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	this->TriggerEvent( State::Terminate, nullptr);
}

void ControlState::ShutDown(const string &action)
{
	ScopedLog l("Shutdown");

/* TODO: check which states
	if( ! this->ValidState( {State::Idle, State::Completed } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}
*/

	if( action == "shutdown")
	{
		this->TriggerEvent( State::ShutDown, nullptr );
	}
	else if( action == "reboot" )
	{
		this->TriggerEvent( State::Reboot, nullptr );
	}
	else
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
	}
}

void ControlState::StorageConfig(const string &phys, const string &log, const string &enc, list<string> &devices)
{
	ScopedLog l("StorageConfig");

	if( ! this->ValidState( {State::AskDevice} ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["physical"] = phys;
	data->data["logical"] = log;
	data->data["encryption"] = enc;
	data->data["devices"] = OPI::JsonHelper::ToJsonArray(devices);

	this->TriggerEvent( State::SelectDevices, data );
}

void ControlState::ResetReturnData()
{
	this->status = true;
	this->retvalue = Json::objectValue;
}

uint8_t ControlState::State()
{
	return this->state;
}

tuple<bool, Json::Value> ControlState::RetValue()
{
	return make_tuple(this->status, this->retvalue);
}

ControlState::~ControlState() = default;

/*
 * State handlers
 */
void ControlState::StIdle(EventData *data)
{
	ScopedLog l("StIdle");
	(void)data;

}

void ControlState::StAskInitCheckRestore(EventData *data)
{
	ScopedLog l("StAskInitCheckrestore");
	(void)data;
}

void ControlState::StInitCheckRestore(EventData *data)
{
	ScopedLog l("StInitCheckrestore");

	auto *arg = dynamic_cast<ControlData*>(data);

	Json::Value ret = this->app->CheckRestore();

	if( ret != Json::nullValue )
	{
		this->retvalue = ret;
		this->RegisterEvent( State::AskRestore, nullptr );
	}
	else
	{
		this->RegisterEvent( State::Init, new ControlData(arg->data));
	}

}

void ControlState::StInit(EventData *data)
{
	ScopedLog l("StInit");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( arg == nullptr )
	{
		logg << Logger::Emerg << "Missing arguments to reinit!"<<lend;
		logg.flush();

		this->RegisterEvent( State::Error, nullptr );
		return;
	}

	if( this->app->DoInit( arg->data["savepassword"].asBool() ) )
	{
		this->app->evhandler.AddEvent( 50, std::bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinstall"));
		this->RegisterEvent( State::AskOpiName, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskInitCheckRestore, nullptr);
	}

}

void ControlState::StAskReInitCheckRestore(EventData *data)
{
	ScopedLog l("StAskReInitCheckrestore");
	(void)data;
}

void ControlState::StReInitCheckrestore(EventData *data)
{
	ScopedLog l("StReInitCheckrestore");

	auto *arg = dynamic_cast<ControlData*>(data);

	Json::Value ret = this->app->CheckRestore();

	if( ret != Json::nullValue )
	{
		this->retvalue = ret;
		this->RegisterEvent( State::AskRestore, nullptr );
	}
	else
	{
		this->RegisterEvent( State::ReInit, new ControlData(arg->data));
	}

}

void ControlState::StReInit(EventData *data)
{
	ScopedLog l("StReInit");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( arg == nullptr )
	{
		logg << Logger::Emerg << "Missing arguments to reinit!"<<lend;
		logg.flush();

		this->RegisterEvent( State::Error, nullptr );
		return;
	}

	if( this->app->DoInit(arg->data["save"].asBool() ) )
	{
		this->app->evhandler.AddEvent( 50, bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinit") );
		this->RegisterEvent( State::AskOpiName, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskReInitCheckRestore, nullptr);
	}
}

// Not nice at all :(
static Thread::Function f;

void ControlState::StRestore(EventData *data)
{
	ScopedLog l("StRestore");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( arg->data["restore"].asBool() )
	{
		f = std::bind(&ControlState::DoRestore, this, arg->data["path"].asString());

		Thread::Async( &f );
	}
	else
	{
		// Mark that user don't want to restore
		this->app->skiprestore = true;

		// Figure out what state to return to
		if( ! StorageManager::Instance().StorageAreaExists() )
		{
			this->RegisterEvent( State::ReInit, new ControlData( arg->data ) );
		}
		else
		{
			this->RegisterEvent( State::Init, new ControlData( arg->data ) );
		}
	}
}

void ControlState::StAskRestore(EventData *data)
{
	ScopedLog l("StAskRestore");
	(void)data;
}

void ControlState::StAskAddUser(EventData *data)
{
	ScopedLog l("StAskAddUser");
	(void)data;
}

void ControlState::StAddUser(EventData *data)
{
	ScopedLog l("StAddUser");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( this->app->AddUser(arg->data["username"].asString(), arg->data["displayname"].asString(), arg->data["password"].asString()) )
	{
		this->RegisterEvent( State::Completed, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskAddUser, nullptr);
	}
}

void ControlState::StAskOpiName(EventData *data)
{
	ScopedLog l("StAskOpiName");
	(void)data;
}

void ControlState::StOpiName(EventData *data)
{
	ScopedLog l("StOpiName");
	if ( data == nullptr)
	{
		logg << Logger::Error << "Got Nullpointer" <<lend;
		this->status = false;
		this->RegisterEvent( State::AskOpiName, nullptr);
	}
	else
	{
		auto *arg = dynamic_cast<ControlData*>(data);

		string host = arg->data["hostname"].asString();
		string domain = arg->data["domain"].asString();

		logg << Logger::Info << "Got name: [" << host << "] [" << domain << "]" << lend;
		if( this->app->SetDNSName(host , domain ) )
		{
			list<UserPtr> users = UserManager::Instance()->GetUsers();
			if( users.size() > 0 )
			{
				// Users exist, we are done
				this->RegisterEvent( State::Completed, nullptr);
			}
			else
			{
				this->RegisterEvent( State::AskAddUser, nullptr );
			}
		}
		else
		{
			this->status = false;
			this->RegisterEvent( State::AskOpiName, nullptr);
		}
	}
}

void ControlState::StHostName(EventData *data)
{
	ScopedLog l("StHostName");
	(void) data;

	if( this->app->SetHostName() )
	{
		this->RegisterEvent( State::Completed, nullptr);
	}
	else
	{
		this->RegisterEvent( State::Error, nullptr );
	}
}

void ControlState::StAskUnlock(EventData *data)
{
	ScopedLog l("StAskUnlock");
	(void)data;
}

void ControlState::StDoUnlock(EventData *data)
{
	ScopedLog l("StDoUnlock");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( this->app->DoUnlock(arg->data["password"].asString(), arg->data["save"].asBool() ) )
	{
		this->RegisterEvent( State::Completed, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskUnlock, nullptr);
	}
}

void ControlState::StTerminate(EventData *data)
{
	ScopedLog l("StTerminate");
	(void)data;

	this->app->StopWebserver();

	this->RegisterEvent( State::Completed, nullptr );
}

void ControlState::StShutDown(EventData *data)
{
	ScopedLog l("StShutdown");
	(void)data;

	this->app->StopWebserver();

}

void ControlState::StReboot(EventData *data)
{
	ScopedLog l("StReboot");
	(void)data;

	this->app->StopWebserver();

	this->retvalue["url"] = "/";
	this->retvalue["timeout"] = 50;
}

void ControlState::StCompleted(EventData *data)
{
	ScopedLog l("StCompleted");
	(void)data;
}

void ControlState::StError(EventData *data)
{
	ScopedLog l("StError");
	(void)data;
}

void ControlState::StAskDevice(EventData *data)
{
	ScopedLog l("StAskDevice");
	(void)data;

}

void ControlState::StDevice(EventData *data)
{
	ScopedLog l("StDevice");

	auto *arg = dynamic_cast<ControlData*>(data);

	if( this->app->SetupStorageConfig(
				arg->data["physical"].asString(),
				arg->data["logical"].asString(),
				arg->data["encryption"].asString(),
				JsonHelper::FromJsonArray(arg->data["devices"])
				) )
	{
		this->RegisterEvent( State::AskInitCheckRestore, nullptr);
	}
	else
	{
		this->status = false;
		this->RegisterEvent( State::AskDevice, nullptr);
	}

}

// Todo: We really should have more internal states here
// this is getting overly complicated
void ControlState::DoRestore(const string &path)
{
	ScopedLog l("Detached restore");

	if( this->app->DoRestore( path ) )
	{

		// Reinit

		this->app->evhandler.AddEvent( 50, [](){ Process::Exec( "/bin/run-parts --lsbsysinit  -- /etc/opi-control/restore");} );

		if( this->app->DoInit( false ) )
		{
			UserManagerPtr umgr = UserManager::Instance();
			list<UserPtr> users = umgr->GetUsers();

			if( users.size() > 0 )
			{

				if( this->app->GuessOPIName() )
				{
					if( this->app->SetDNSName() )
					{
						// Trigger not register since we call this outside of process context
						this->TriggerEvent( State::Completed, nullptr);
					}
					else
					{
						logg << Logger::Error << "Failed to set DNS-name ("
							<< this->app->hostname << "): "
							<< this->app->global_error
							<< lend;
						this->TriggerEvent( State::AskOpiName, nullptr);
					}
				}
				else
				{
					logg << Logger::Debug << "Unable to guess opiname"<<lend;
					this->TriggerEvent( State::AskOpiName, nullptr);
				}
			}
			else
			{
				logg << Logger::Debug << "No users in system not able to set name"<<lend;
				this->TriggerEvent( State::AskOpiName, nullptr);
			}

		}
		else
		{
			// Init failed
			logg << Logger::Error << "Init failed" << lend;
			this->status = false;
			this->TriggerEvent( State::Error, nullptr);
		}

	}
	else
	{
		// Restore failed return to previous state
		// TODO: howto handle failure?
		//status = false;

		// Figure out what state to return to
		if( ! StorageManager::Instance().StorageAreaExists() )
		{
			this->TriggerEvent( State::ReInit, nullptr);
		}
		else
		{
			this->TriggerEvent( State::Init, nullptr);
		}
	}

}

bool ControlState::ValidState(const vector<uint8_t>& vals)
{
	for( uint8_t val: vals)
	{
		if( val == this->state )
		{
			return true;
		}
	}
	return false;
}

