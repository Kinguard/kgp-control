#ifndef CONTROLSTATE_H
#define CONTROLSTATE_H

#include <libutils/StateMachine.h>
#include <json/json.h>

#include <memory>

using namespace Utils;

class ControlApp;

class ControlData: public EventData
{
public:
	ControlData(Json::Value data): EventData(), data(data) {}
	ControlData(): ControlData(Json::nullValue) {}

	Json::Value data;

	virtual ~ControlData(){}
};

class ControlState : public StateMachine
{
public:

	struct State
	{
		enum
		{
			InitCheckRestore=1,		//  1
			Init,					//  2
			ReInitCheckrestore,		//  3
			ReInit,					//  4
			AskRestore,				//  5
			Restore,				//  6
			AskAddUser,				//  7
			OpiName,				//  8
			AddUser,				//  9
			AskUnlock,				// 10
			Unlock,					// 11
			Terminate,				// 12
			ShutDown,				// 13
			Reboot,					// 14
			Completed,				// 15
			Idle,					// 16
			Error,					// 17
			AskOpiName,				// 18
			AskReInitCheckRestore,	// 19
			AskInitCheckRestore,	// 20
			Hostname,				// 21
			AskDevice,				// 22
			SelectDevices,			// 23
		};
	};

	ControlState(ControlApp* app, uint8_t state = State::Idle);

	// External events
	void Init(bool savepassword);
	void ReInit(bool savepassword);
	void Restore(bool dorestore, const string& path);
	void AddUser(const string& username, const string& displayname, const string& password);
	void OpiName(const string& opiname);
	void Unlock(const string& password, bool save);
	void Terminate();
	void ShutDown(const string& action);

	void ResetReturnData();

	uint8_t State();
	tuple<bool, Json::Value> RetValue();

	virtual ~ControlState();
protected:
	void StIdle(EventData* data);
	void StAskInitCheckRestore(EventData* data);
	void StInitCheckRestore(EventData* data);
	void StInit(EventData* data);
	void StAskReInitCheckRestore(EventData* data);
	void StReInitCheckrestore(EventData* data);
	void StReInit(EventData* data);
	void StRestore(EventData* data);
	void StAskRestore(EventData* data);
	void StAskAddUser(EventData* data);
	void StAddUser(EventData* data);
	void StAskOpiName(EventData* data);
	void StOpiName(EventData* data);
	void StHostName(EventData* data);
	void StAskUnlock(EventData* data);
	void StDoUnlock(EventData* data);
	void StTerminate(EventData* data);
	void StShutDown(EventData* data);
	void StReboot(EventData* data);
	void StCompleted(EventData* data);
	void StError(EventData* data);
	void StAskDevice(EventData* data);
	void StDevice(EventData* data);

private:

	void DoRestore(const string& path);

	bool ValidState(const vector<uint8_t>& vals);
	bool status;
	Json::Value retvalue;
	ControlApp* app;
};

typedef shared_ptr<ControlState> ControlStatePtr;


#endif // CONTROLSTATE_H
