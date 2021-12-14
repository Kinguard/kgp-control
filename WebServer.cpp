#include "WebServer.h"
#include "Config.h"
#include "mongoose.h"
#include <libopi/DnsServer.h>
#include <libopi/SysConfig.h>
#include <libopi/SysInfo.h>

#include <kinguard/IdentityManager.h>

#include <libutils/String.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>
#include <libutils/HttpStatusCodes.h>

#include <string>
#include <map>
#include <utility>

using namespace Utils;
using namespace Utils::HTTP;
using namespace std;

std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *, struct http_message *)> > WebServer::routes;
std::function<json(json)> WebServer::callback;
struct mg_serve_http_opts WebServer::s_http_server_opts;
string WebServer::documentroot;


WebServer::WebServer(std::function<json(json)> cb, const string &docroot, uint16_t port):
	Utils::Thread(false),
	doRun(true),
	port(port)
{
	WebServer::callback = std::move(cb);
	documentroot = docroot;
	this->portstring = to_string(this->port);
	routes[std::make_pair("/configure","POST")] = WebServer::handle_init;
	routes[std::make_pair("/init","POST")] = WebServer::handle_init;
	routes[std::make_pair("/reinit","POST")] = WebServer::handle_reinit;
	routes[std::make_pair("/restore","POST")] = WebServer::handle_restore;
	routes[std::make_pair("/unlock","POST")] = WebServer::handle_unlock;
	routes[std::make_pair("/status","GET")] = WebServer::handle_status;
	routes[std::make_pair("/user","POST")] = WebServer::handle_user;
	routes[std::make_pair("/checkname","POST")] = WebServer::handle_checkname;
	routes[std::make_pair("/opiname","POST")] = WebServer::handle_selectname;
	routes[std::make_pair("/portstatus","GET")] = WebServer::handle_portstatus;
	routes[std::make_pair("/terminate","POST")] = WebServer::handle_terminate;
	routes[std::make_pair("/shutdown","POST")] = WebServer::handle_shutdown;
	routes[std::make_pair("/gettype","GET")] = WebServer::handle_type;
	routes[std::make_pair("/getdomains","GET")] = WebServer::handle_domains;
	routes[std::make_pair("/activetheme","GET")] = WebServer::handle_theme;
	routes[std::make_pair("/storagedevices","GET")] = WebServer::handle_storagedevices;
	routes[std::make_pair("/devices","POST")] = WebServer::handle_devices;

}

void WebServer::Stop()
{
	this->doRun = false;
}

void WebServer::PreRun()
{
	OPI::SysConfig cfg;
	const string certpath = cfg.GetKeyAsString("webcertificate", "activecert");
	const string keypath = cfg.GetKeyAsString("webcertificate", "activekey");

	struct mg_bind_opts bind_opts = {};

	if( ! File::FileExists( certpath ) && ! File::LinkExists( certpath ) )
	{
		logg << Logger::Error << "Unable to locate certificate file: " << certpath << lend;
	}
	else
	{
		logg << Logger::Debug << "Using certificate file: " << certpath << lend;
	}

	if( ! File::FileExists( keypath ) && ! File::LinkExists( keypath ) )
	{
		logg << Logger::Error << "Unable to locate private key file: " << keypath << lend;
	}
	else
	{
		logg << Logger::Debug << "Using private key file: " << keypath << lend;
	}

	logg << Logger::Debug << "Starting up using port "<< this->portstring << " (" << this->port << ")"<<lend;

	mg_mgr_init( &this->mgr, nullptr);
	memset(&bind_opts, 0, sizeof(bind_opts));

	bind_opts.ssl_cert = certpath.c_str();
	bind_opts.ssl_key = keypath.c_str();
	const char *errmsg;
	bind_opts.error_string = &errmsg;
	this->conn = mg_bind_opt( &(this->mgr), this->portstring.c_str(), WebServer::ev_handler, bind_opts);

	if( ! this->conn )
	{
		logg << Logger::Crit << "Unable to create webserver connection [" << errmsg << "]" << lend;

	}

	mg_set_protocol_http_websocket(this->conn);
	WebServer::s_http_server_opts.document_root = WebServer::documentroot.c_str();
	// Redirect all 404 to our index page
	// This seems not supported any more. We patch mg_http_send_error to fix this for now.
	WebServer::s_http_server_opts.enable_directory_listing = "no";

	// Disable php as cgi since this result in a status 500 on faulty requests
	WebServer::s_http_server_opts.cgi_file_pattern ="**.cgi$";

	logg << Logger::Debug << "Using webroot " << WebServer::s_http_server_opts.document_root << lend;
}

void WebServer::Run()
{
	logg << Logger::Debug << "Starting webserver on port " << this->port <<lend;
	while ( this->doRun ) {
		mg_mgr_poll(&this->mgr, 1000);
	}
}

void WebServer::PostRun()
{
	// Cleanup, and free server instance
	logg << Logger::Debug << "Webserver shutting down!" << lend;
	mg_mgr_free(&this->mgr);
}

WebServer::~WebServer() = default;

static void send_json_reply(mg_connection *conn, const json& val )
{
	string reply = val.dump();
	stringstream headerstream;
	headerstream << "Cache-Control: no-cache\r\n"
			<< "Content-Length: " << reply.size()<<"\r\n"
			<< "Content-Type: application/json\r\n\r\n";

	string headers = headerstream.str();
	mg_send_response_line( conn, Status::Ok, "");
	mg_send( conn, headers.c_str(), static_cast<int>(headers.size()));
	mg_send( conn, reply.c_str(), static_cast<int>(reply.size()) );
}

static void send_simple_reply(mg_connection *conn, int status, const string& msg, const list<string>& headers={})
{
	stringstream hs;
	hs << "Cache-Control: no-cache\r\n";
	for(const auto &header: headers)
	{
		hs << header << "\r\n";
	}
	hs << "\r\n";
	mg_send_response_line(conn, status, "");
	mg_send(conn, hs.str().c_str(), static_cast<int>(hs.str().size()));
	mg_send( conn, msg.c_str(), static_cast<int>( msg.size()) );

	conn->flags |= MG_F_SEND_AND_CLOSE;
}

static bool validate_initdata(const json& v)
{
	if( ! v.contains("masterpassword") || !v["masterpassword"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["masterpassword"].get<string>(), "\t ") == "" )
	{
		return false;
	}

	if( OPI::SysInfo::isOP() ) {
		if (! v.contains("unit_id") || !v["unit_id"].is_string() )
		{
			return false;
		}

		if( String::Trimmed( v["unit_id"].get<string>(), "\t ") == "" )
		{
			return false;
		}
	}
	else
	{
		logg << Logger::Debug << "Skip requirement for unitid" << lend;
	}

	if( ! v.contains("save") || !v["save"].is_boolean() )
	{
		return false;
	}

	return true;
}

int WebServer::handle_init(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for init"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if(  validate_initdata( req ) )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "init";
			cmd["password"] = String::Trimmed( req["masterpassword"].get<string>(), "\t " );
			cmd["unit_id"] = String::Trimmed( req["unit_id"].get<string>(), "\t ");
			cmd["save"] = req["save"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply( conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}


static bool validate_reinitdata(const json& v)
{
	if( ! v.contains("masterpassword") || !v["masterpassword"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["masterpassword"].get<string>(), "\t ") == "" )
	{
		return false;
	}

	if( ! v.contains("save") || !v["save"].is_boolean() )
	{
		return false;
	}

	return true;
}


int WebServer::handle_reinit(mg_connection *conn, http_message *http)
{
	// Almost like init but from an initialized unit
	logg << Logger::Debug << "Got request for reinit"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if(   validate_reinitdata( req )  )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "reinit";
			cmd["password"] = String::Trimmed( req["masterpassword"].get<string>(), "\t ");
			cmd["save"] = req["save"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}


static bool validate_restoredata(const json& v)
{
	if( ! v.contains("path") || !v["path"].is_string() )
	{
		return false;
	}

	if( ! v.contains("restore") || !v["restore"].is_string() )
	{
		return false;
	}

	return true;
}


int WebServer::handle_restore(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for restore"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if(   validate_restoredata( req )  )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "restore";
			cmd["path"] = req["path"].get<string>();
			cmd["restore"] = req["restore"].get<string>() == "1";
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}

static bool validate_unlockdata(const json& v)
{
	if( ! v.contains("masterpassword") || !v["masterpassword"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["masterpassword"].get<string>(), "\t ") == "" )
	{
		return false;
	}

	if( ! v.contains("save") || !v["save"].is_boolean() )
	{
		return false;
	}

	return true;
}


int WebServer::handle_unlock(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for unlock"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( validate_unlockdata( req ) )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "unlock";
			cmd["password"] = String::Trimmed( req["masterpassword"].get<string>(), "\t " );
			cmd["save"] = req["save"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}

int WebServer::handle_status(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Handle status"<<lend;
	(void) http;
	json ret;
	if( WebServer::callback != nullptr )
	{
		json cmd;
		cmd["cmd"]="status";
		ret = WebServer::callback( cmd );
	}

	send_json_reply(conn, ret);

	return true;
}

static bool validate_user(const json& v)
{

	if( ! v.contains("username") || !v["username"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["username"].get<string>(), "\t " ) == "" )
	{
		return false;
	}

	if( ! v.contains("displayname") || !v["displayname"].is_string() )
	{
		return false;
	}

	if( ! v.contains("password") || !v["password"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["password"].get<string>(), "\t " ) == "" )
	{
		return false;
	}

	return true;
}

int WebServer::handle_user(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for adduser"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( validate_user(req) )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "adduser";
			cmd["username"] = String::Trimmed( req["username"].get<string>(), "\t " );
			cmd["displayname"] = String::Trimmed( req["displayname"].get<string>(), "\t " );
			cmd["password"] = String::Trimmed( req["password"].get<string>(), "\t " );
			ret = WebServer::callback( cmd );
		}
		send_json_reply( conn, ret );
	}
	else
	{
		logg << Logger::Debug << "Request for add user had invalid arguments"<<lend;
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}

int WebServer::handle_checkname(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for checkname"<<lend;

	json req;
	string fqdn;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( req.contains("opiname") && req["opiname"].is_string() && String::Trimmed( req["opiname"].get<string>(), "\t " ) != ""  &&
		req.contains("domain") && req["domain"].is_string() && String::Trimmed( req["domain"].get<string>(), "\t " ) != ""
	)
	{
		fqdn = String::Trimmed( req["opiname"].get<string>(), "\t " )+"."+String::Trimmed( req["domain"].get<string>(), "\t " );

		KGP::IdentityManager& imgr = KGP::IdentityManager::Instance();

		if( ! OPI::SysInfo::isOP() )
		{
			logg << Logger::Info << "Request for dns check name when not supported"<<lend;
			send_simple_reply( conn, Status::NotImplemented, "Operation not supported");
			return true;
		}

		bool available = imgr.DnsNameAvailable(
				String::Trimmed( req["opiname"].get<string>(), "\t " ),
				String::Trimmed( req["domain"].get<string>(), "\t " ));

		json ret;
		ret["available"]=available;
		send_json_reply(conn, ret);
	}
	else
	{
		logg << Logger::Debug << "Request for check opiname arguments"<<lend;
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}


static bool validate_selectname(const json& v)
{

	if( ! v.contains("opiname") || !v["opiname"].is_string() )
	{
		return false;
	}

	if( String::Trimmed( v["opiname"].get<string>(), "\t " ) == "" )
	{
		return false;
	}

	if( ! v.contains("domain") || !v["domain"].is_string() )
	{
		return false;
	}

	return true;
}


int WebServer::handle_selectname(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for update dnsname"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( ! validate_selectname(req) )
	{
		logg << Logger::Debug << "Request for select opiname had invalid arguments"<<lend;
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
		return true;
	}

	string hostname = String::Trimmed( req["opiname"].get<string>(), "\t " );
	string domainname = String::Trimmed( req["domain"].get<string>(), "\t " );

	logg << Logger::Debug << "Hostname " << hostname << " domain " << domainname << lend;

	json ret;
	string fqdn;

	if( WebServer::callback != nullptr ){
		json cmd;
		cmd["cmd"] = "opiname";
		cmd["hostname"] = hostname;
		cmd["domain"] = domainname;
		ret = WebServer::callback( cmd );
	}
	send_json_reply(conn, ret);

	return true;
}

int WebServer::handle_portstatus(mg_connection *conn, http_message *http)
{
	(void) http;

	logg << Logger::Debug << "Got request for portstatus"<<lend;

	json ret;
	if( WebServer::callback != nullptr )
	{
		json cmd;
		cmd["cmd"]="portstatus";
		ret = WebServer::callback( cmd );
	}
	send_json_reply(conn, ret);

	return true;
}

int WebServer::handle_terminate(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for terminate"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( req.contains("shutdown") && req["shutdown"].is_boolean() )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "terminate";
			cmd["shutdown"] = req["shutdown"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}

int WebServer::handle_shutdown(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request for shutdown"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	if( req.contains("action") && req["action"].is_string() )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "shutdown";
			cmd["action"] = req["action"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}

int WebServer::handle_type(mg_connection *conn, http_message *http)
{
	(void) http;
	logg << Logger::Debug << "Got request for type"<<lend;

	json ret;
	if( WebServer::callback != nullptr )
	{
		json cmd;

		cmd["cmd"]= "gettype";
		ret = WebServer::callback( cmd );
	}

	send_json_reply(conn, ret);

	return true;
}

int WebServer::handle_domains(mg_connection *conn, http_message *http)
{
	(void) http;
	logg << Logger::Debug << "Got request for domains"<<lend;


	json ret;
	if( WebServer::callback != nullptr )
	{
		json cmd;

		cmd["cmd"]= "getdomains";
		ret = WebServer::callback( cmd );
	}

	send_json_reply(conn, ret);

	return true;
}

int WebServer::handle_theme(mg_connection *conn, http_message *http)
{
	vector<string> uri;
	string struri(http->uri.p, http->uri.len);

	logg << Logger::Debug << "Got request for theme"<<lend;

	String::Split(struri,uri,"/",2);
	try
	{
		string theme,themefile;

		theme = OPI::SysConfig().GetKeyAsString("webapps","theme");
		if ( theme == "kgp" )
		{
			// default kgp files should always be loaded so do not load them again.
			logg << Logger::Debug << "Theme is 'kgp' do not load any additional files." <<lend;
		}
		else
		{
			themefile="/themes/" + theme + "/" + uri[1];
			if( File::FileExists(WebServer::documentroot + themefile))
			{
				send_simple_reply( conn, Status::TemporaryRedirect, "Redirect to theme file",
									{
									   "Content-Type: text/html",
									   string("Location: ")+themefile
									}
								   );
				return true;
			}
			else
			{
				logg << Logger::Debug << "File missing: " << uri[1] <<lend;
			}
		}
	}
	catch (std::runtime_error& e)
	{
		logg << Logger::Debug << "No theme set (" << e.what() << ")"<<lend;
	}

	send_simple_reply(conn, Status::NotFound, "<h1>Not Found</h1><br>The requested URL was not found on this server.", {"Content-Type: text/html"});
	return true;
}

int WebServer::handle_storagedevices(mg_connection *conn, http_message *http)
{
	(void) http;
	logg << Logger::Debug << "Got request for storage devices"<<lend;

	json ret;
	if( WebServer::callback != nullptr )
	{
		json cmd;

		cmd["cmd"]= "getstoragedevices";
		ret = WebServer::callback( cmd );
	}

	send_json_reply(conn, ret);

	return true;

}


static bool validate_devicedata(const json& v)
{
	if( ! v.contains("devices") || !v["devices"].is_array() )
	{
		return false;
	}

	if( ! v.contains("encryption") || !v["encryption"].is_string() )
	{
		return false;
	}

	if( ! v.contains("logical") || !v["logical"].is_string() )
	{
		return false;
	}

	if( ! v.contains("physical") || !v["physical"].is_string() )
	{
		return false;
	}


	return true;
}


int WebServer::handle_devices(mg_connection *conn, http_message *http)
{
	logg << Logger::Debug << "Got request select storage config"<<lend;

	json req;

	if( ! WebServer::parse_json(conn, http, req) )
	{
		// True in the sense that we handled the req.
		return true;
	}

	cout << req.dump(4)<< endl;

	if( validate_devicedata( req ) )
	{
		json ret;
		if( WebServer::callback != nullptr ){
			json cmd;
			cmd["cmd"] = "deviceconfig";
			cmd["devices"] = req["devices"];
			cmd["encryption"] = req["encryption"];
			cmd["logical"] = req["logical"];
			cmd["physical"] = req["physical"];
			ret = WebServer::callback( cmd );
		}
		send_json_reply(conn, ret);
	}
	else
	{
		send_simple_reply(conn, Status::BadRequest, "Missing argument!");
	}

	return true;
}



void WebServer::ev_handler(struct mg_connection *conn, int ev, void *p)
{
	if (ev == MG_EV_HTTP_REQUEST)
	{
#if 0
		if( conn->uri )
		{
			logg << Logger::Debug << "URI      ["<< conn->uri << "]"<<lend;
		}
		if( conn->query_string )
		{
			logg << Logger::Debug << "Querystr ["<< conn->query_string << "]"<<lend;
		}
		if( conn->request_method )
		{
			logg << Logger::Debug << "Method   ["<< conn->request_method << "]"<<lend;
		}
		if( conn->http_version )
		{
			logg << Logger::Debug << "Version  ["<< conn->http_version << "]"<<lend;
		}
#endif
#if 0
		mg_printf(conn, "URI      [%s]\n", conn->uri);
		mg_printf(conn, "Querystr [%s]\n", conn->query_string);
		mg_printf(conn, "Method   [%s]\n", conn->request_method);
		mg_printf(conn, "version  [%s]\n", conn->http_version);
#endif

		auto *hm = static_cast<struct http_message*>(p);
		string uri(hm->uri.p, hm->uri.len);
		string cmd;
		if ( uri.length() > 1 )
		{
			cmd = "/" + String::Split(uri,"/",2).front();
		}
		else
		{
			cmd = uri;
		}
		auto val = std::make_pair(cmd, string(hm->method.p, hm->method.len));

		if( WebServer::routes.find(val) != WebServer::routes.end() )
		{
			WebServer::routes[val](conn, hm);
		}
		else
		{
			// Try serve as static file request
			mg_serve_http( conn, hm, WebServer::s_http_server_opts);
		}

	}
}

bool WebServer::parse_json(mg_connection *conn, struct http_message *hm, json &val)
{
	string postdata(hm->body.p, hm->body.len);

	//cout << "Got data: [" << postdata << "]" << endl;

	try
	{
		val = json::parse(postdata);
	}
	catch(json::parse_error& err)
	{
		logg << Logger::Info << "Failed to parse input ("<< err.what()<<")"<<lend;
		send_simple_reply(conn, Status::BadRequest, "Unable to parse input");

		return false;
	}

	return true;
}
