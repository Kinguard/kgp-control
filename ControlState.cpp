#include "ControlState.h"

#include <libutils/Process.h>
#include <libutils/Thread.h>
#include <libutils/String.h>
#include <libopi/Secop.h>
#include <libopi/SysInfo.h>

#include "IdentityManager.h"
#include "StorageManager.h"
#include "ControlApp.h"
#include "Config.h"

using namespace OPI;
using namespace Utils;

class ScopedLog
{
public:
	ScopedLog() = delete;
	ScopedLog(const ScopedLog&) = delete;
	ScopedLog& operator=(const ScopedLog&) = delete;

	ScopedLog(const string& message, Logger::LogLevel level = Logger::Debug): msg(message), level(level)
	{
		logg << this->level << "ControlState " << this->msg << " : started"<< lend;
	}


	virtual ~ScopedLog()
	{
		logg << this->level << "ControlState " << this->msg << " : completed"<< lend;
	}
private:
	string msg;
	Logger::LogLevel level;
};

ControlState::ControlState(ControlApp *app, uint8_t state): app(app)
{
	this->statemap =
	{
		{ State::Idle,					std::bind( &ControlState::StIdle, this, std::placeholders::_1 )},
		{ State::Error,					std::bind( &ControlState::StError, this, std::placeholders::_1 )},
		{ State::InitCheckRestore,		std::bind( &ControlState::StInitCheckRestore, this, std::placeholders::_1 )},
		{ State::Init,					std::bind( &ControlState::StInit, this, std::placeholders::_1 )},
		{ State::ReInitCheckrestore,	std::bind( &ControlState::StReInitCheckrestore, this, std::placeholders::_1 )},
		{ State::ReInit,				std::bind( &ControlState::StReInit, this, std::placeholders::_1 )},
		{ State::AskRestore,			std::bind( &ControlState::StAskRestore, this, std::placeholders::_1 )},
		{ State::Restore,				std::bind( &ControlState::StRestore, this, std::placeholders::_1 )},
		{ State::AskUnlock,				std::bind( &ControlState::StAskUnlock, this, std::placeholders::_1 )},
		{ State::Unlock,				std::bind( &ControlState::StDoUnlock, this, std::placeholders::_1 )},
		{ State::Terminate,				std::bind( &ControlState::StTerminate, this, std::placeholders::_1 )},
		{ State::ShutDown,				std::bind( &ControlState::StShutDown, this, std::placeholders::_1 )},
		{ State::Reboot,				std::bind( &ControlState::StReboot, this, std::placeholders::_1 )},
		{ State::Completed,				std::bind( &ControlState::StCompleted, this, std::placeholders::_1 )},
		{ State::AskAddUser,			std::bind( &ControlState::StAskAddUser, this, std::placeholders::_1 )},
		{ State::AddUser,				std::bind( &ControlState::StAddUser, this, std::placeholders::_1 )},
		{ State::AskOpiName,			std::bind( &ControlState::StAskOpiName, this, std::placeholders::_1 )},
		{ State::OpiName,				std::bind( &ControlState::StOpiName, this, std::placeholders::_1 )},
		{ State::AskInitCheckRestore,	std::bind( &ControlState::StAskInitCheckRestore, this, std::placeholders::_1 )},
		{ State::AskReInitCheckRestore,	std::bind( &ControlState::StAskReInitCheckRestore, this, std::placeholders::_1 )},
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
	ControlData *data = new ControlData;
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

void ControlState::OpiName(const string &opiname)
{
	ScopedLog l("OpiName");

	if( ! this->ValidState( {State::AskOpiName } ) )
	{
		this->TriggerEvent( StateMachine::EVENT_ERROR, nullptr );
		return;
	}

	ControlData *data = new ControlData;
	data->data["opiname"] = opiname;

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

ControlState::~ControlState()
{

}

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

	ControlData *arg = dynamic_cast<ControlData*>(data);

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

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( this->app->DoInit( arg->data["savepassword"].asBool() ) )
	{
		Secop s;
		s.SockAuth();
		vector<string> users = s.GetUsers();

		if( users.size() > 0 )
		{
			// We have users on SD, skip register user
			if( this->app->GuessOPIName() && this->app->SetDNSName() )
			{
				this->RegisterEvent( State::Completed, nullptr );
			}
			else
			{
				this->RegisterEvent( State::AskOpiName, nullptr);
			}
			this->app->evhandler.AddEvent( 50, std::bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinstall"));
		}
		else
		{
			this->RegisterEvent( State::AskAddUser, nullptr );
		}
		// TODO: try reuse opi-name and opi_unitid
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

	ControlData *arg = dynamic_cast<ControlData*>(data);

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

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( arg == nullptr )
	{
		logg << Logger::Emerg << "Missing arguments to reinit!"<<lend;
		logg.flush();
	}

	if( this->app->DoInit(arg->data["save"].asBool() ) )
	{
		this->app->evhandler.AddEvent( 50, bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/reinit") );
		this->RegisterEvent( State::AskAddUser, nullptr);
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

	ControlData *arg = dynamic_cast<ControlData*>(data);

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
		if( ! StorageManager::StorageAreaExists() )
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

	ControlData *arg = dynamic_cast<ControlData*>(data);

	if( this->app->AddUser(arg->data["username"].asString(), arg->data["displayname"].asString(), arg->data["password"].asString()) )
	{
		if( IdentityManager::Instance().HasDNSProvider() )
		{
			this->RegisterEvent( State::AskOpiName, nullptr);
		}
		else
		{
			this->RegisterEvent( State::Completed, nullptr );
		}
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
		ControlData *arg = dynamic_cast<ControlData*>(data);
		logg << Logger::Info << "StOpiName 2";

		list<string> fqdn = String::Split(arg->data["opiname"].asString(), ".",2);
		logg << Logger::Info << "Got fqdn: " << fqdn.front() << "." << fqdn.back() << lend;
		if( this->app->SetDNSName(fqdn.front(),fqdn.back() ) )
		{
			this->RegisterEvent( State::Completed, nullptr);
		}
		else
		{
			this->status = false;
			this->RegisterEvent( State::AskOpiName, nullptr);
		}
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

	ControlData *arg = dynamic_cast<ControlData*>(data);

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

// Todo: We really should have more internal states here
// this is getting overly complicated
void ControlState::DoRestore(const string &path)
{
	ScopedLog l("Detached restore");

	if( this->app->DoRestore( path ) )
	{

		this->app->evhandler.AddEvent( 50, bind( Process::Exec, "/bin/run-parts --lsbsysinit  -- /etc/opi-control/restore") );

		if( this->app->DoInit( false ) )
		{
			Secop s;
			s.SockAuth();
			vector<string> users = s.GetUsers();

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
							<< this->app->opi_name << "): "
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
				this->TriggerEvent( State::AskAddUser, nullptr);
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
		if( ! StorageManager::StorageAreaExists() )
		{
			this->TriggerEvent( State::ReInit, nullptr);
		}
		else
		{
			this->TriggerEvent( State::Init, nullptr);
		}
	}

}

bool ControlState::ValidState(vector<uint8_t> vals)
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

