#ifndef SECOP_H
#define SECOP_H

#include <libutils/Socket.h>
#include <libutils/ClassTools.h>
#include <json/json.h>

#include <string>
#include <list>
#include <map>

using namespace std;
using namespace Utils::Net;

// Todo: make nicer, enum?
#define UNINITIALIZED	0x01
#define INITIALIZED		0x02
#define AUTHENTICATED	0x04


class Secop: public Utils::NoCopy
{
public:
	enum State {
		Unknown			= 0x00,
		Uninitialized	= 0x01,
		Initialized		= 0x02,
		Authenticated	= 0x04
	};

	Secop();

	bool Init(const string& pwd);

	State Status();

	bool SockAuth();
	bool PlainAuth(const string& user, const string& pwd);

	// User commands
	bool CreateUser(const string& user, const string& pwd, const string& display="");
	bool UpdateUserPassword(const string& user, const string& pwd);
	bool RemoveUser(const string& user);
	vector<string> GetUsers();

	bool AddAttribute(const string& user, const string& attr, const string& value);
	bool RemoveAttribute(const string& user, const string& attr);
	vector<string> GetAttributes(const string& user);
	string GetAttribute(const string& user, const string& attr);


	vector<string> GetServices(const string& user);
	bool AddService(const string& user, const string& service);
	bool RemoveService(const string& user, const string& service);

	vector<string> GetACL(const string& user, const string& service);
	bool AddACL(const string& user, const string& service, const string& acl);
	bool RemoveACL(const string& user, const string& service, const string& acl);
	bool HasACL(const string& user, const string& service, const string& acl);

	/* Limited, can only add key value string pairs */
	bool AddIdentifier(const string& user, const string& service, const map<string,string>& identifier);

	/* Identifier has to contain user &| service */
	bool RemoveIdentifier(const string& user, const string& service, const map<string,string>& identifier);

	list<map<string,string>> GetIdentifiers(const string& user, const string& service);

	// Group commands
	bool AddGroup(const string& group);
	bool AddGroupMember(const string& group, const string& member);
	vector<string> GetGroupMembers(const string& group);
	vector<string> GetGroups();
	bool RemoveGroup(const string& group);
	bool RemoveGroupMember(const string& group, const string& member);

	// Appid / system commands
	bool AppAddID(const string& appid);
	vector<string> AppGetIDs();
	bool AppRemoveID(const string& appid);

	bool AppAddIdentifier(const string& appid, const map<string,string>& identifier);
	list<map<string,string>> AppGetIdentifiers(const string& appid);
	bool AppRemoveIdentifier(const string& appid, const map<string,string>& identifier);

	bool AppAddACL(const string& appid, const string& acl);
	vector<string> AppGetACL(const string& appid);
	bool AppRemoveACL(const string& appid, const string& acl);
	bool AppHasACL(const string& appid, const string& acl);


	virtual ~Secop();

protected:
	Json::Value DoCall(Json::Value& cmd);

	bool CheckReply( const Json::Value& val );

	int tid;
private:
	UnixStreamClientSocket secop;
	Json::FastWriter writer;
	Json::Reader reader;
};

typedef shared_ptr<Secop> SecopPtr;


#endif // SECOP_H
