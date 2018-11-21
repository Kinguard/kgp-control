#include "WebServer.h"
#include "Config.h"
#include "mongoose.h"
#include <libopi/DnsServer.h>
#include <libopi/SysConfig.h>

#include <kinguard/IdentityManager.h>

#include <libutils/String.h>
#include <libutils/Logger.h>
#include <libutils/FileUtils.h>

#include <string>
#include <map>

#ifdef OPI_BUILD_PACKAGE
#define DOCUMENT_ROOT	"/usr/share/opi-control/web"
#else
#define DOCUMENT_ROOT	"../opi-control/html"
#endif

#define LISTENING_PORT	"443"

using namespace Utils;
using namespace std;

std::map<std::pair<std::string,std::string>, std::function<int(mg_connection *)> > WebServer::routes;
std::function<Json::Value(Json::Value)> WebServer::callback;

WebServer::WebServer(std::function<Json::Value(Json::Value)> cb):
    Utils::Thread(false),
    doRun(true),
    server(nullptr)
{
    WebServer::callback = cb;
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

    this->server = mg_create_server(nullptr, WebServer::ev_handler);
    mg_set_option(this->server, "document_root", DOCUMENT_ROOT);

    if( ! File::FileExists( certpath ) && ! File::LinkExists( certpath ) )
    {
        logg << Logger::Error << "Unable to locate certificate file: " << certpath << lend;
    }
    else
    {
        logg << Logger::Debug << "Using certificate file: " << certpath << lend;
    }

    mg_set_option(this->server, "ssl_certificate",certpath.c_str());


    if( ! File::FileExists( keypath ) && ! File::LinkExists( keypath ) )
    {
        logg << Logger::Error << "Unable to locate private key file: " << keypath << lend;
    }
    else
    {
        logg << Logger::Debug << "Using private key file: " << keypath << lend;
    }

    mg_set_option(this->server, "ssl_private_key",keypath.c_str());

    mg_set_option(this->server, "listening_port",LISTENING_PORT);

    // Redirect all 404 to our index page
    mg_set_option(this->server, "url_rewrites","404=/");

#if 0
    mg_set_option( this->server, "access_log_file", "mg_logfile.txt");
#endif
}

void WebServer::Run()
{
    logg << Logger::Debug << "Starting webserver on port " << mg_get_option(server, "listening_port") <<lend;
    while ( this->doRun ) {
        mg_poll_server(this->server, 1000);
    }
}

void WebServer::PostRun()
{
    // Cleanup, and free server instance
    logg << Logger::Debug << "Webserver shutting down!" << lend;
    mg_destroy_server(&server);
}

WebServer::~WebServer()
{

}

static bool validate_initdata(const Json::Value& v)
{
    if( ! v.isMember("masterpassword") || !v["masterpassword"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["masterpassword"].asString(), "\t ") == "" )
    {
        return false;
    }

    if( ! v.isMember("unit_id") || !v["unit_id"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["unit_id"].asString(), "\t ") == "" )
    {
        return false;
    }

    if( ! v.isMember("save") || !v["save"].isBool() )
    {
        return false;
    }


    return true;
}

int WebServer::handle_init(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for init"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if(  validate_initdata( req ) )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "init";
            cmd["password"] = String::Trimmed( req["masterpassword"].asString(), "\t " );
            cmd["unit_id"] = String::Trimmed( req["unit_id"].asString(), "\t ");
            cmd["save"] = req["save"];
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str());
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }

    return MG_TRUE;
}


static bool validate_reinitdata(const Json::Value& v)
{
    if( ! v.isMember("masterpassword") || !v["masterpassword"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["masterpassword"].asString(), "\t ") == "" )
    {
        return false;
    }

    if( ! v.isMember("save") || !v["save"].isBool() )
    {
        return false;
    }

    return true;
}


int WebServer::handle_reinit(mg_connection *conn)
{
    // Almost like init but from an initialized unit
    logg << Logger::Debug << "Got request for reinit"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if(   validate_reinitdata( req )  )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "reinit";
            cmd["password"] = String::Trimmed( req["masterpassword"].asString(), "\t ");
            cmd["save"] = req["save"];
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str());
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }

    return MG_TRUE;
}


static bool validate_restoredata(const Json::Value& v)
{
    if( ! v.isMember("path") || !v["path"].isString() )
    {
        return false;
    }

    if( ! v.isMember("restore") || !v["restore"].isString() )
    {
        return false;
    }

    return true;
}


int WebServer::handle_restore(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for restore"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if(   validate_restoredata( req )  )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "restore";
            cmd["path"] = req["path"].asString();
            cmd["restore"] = req["restore"].asString() == "1";
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str());
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }



    return MG_TRUE;
}

static bool validate_unlockdata(const Json::Value& v)
{
    if( ! v.isMember("masterpassword") || !v["masterpassword"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["masterpassword"].asString(), "\t ") == "" )
    {
        return false;
    }

    if( ! v.isMember("save") || !v["save"].isBool() )
    {
        return false;
    }

    return true;
}


int WebServer::handle_unlock(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for unlock"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if( validate_unlockdata( req ) )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "unlock";
            cmd["password"] = String::Trimmed( req["masterpassword"].asString(), "\t " );
            cmd["save"] = req["save"];
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str() );
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_status(mg_connection *conn)
{


    Json::Value ret;
    if( WebServer::callback != nullptr )
    {
        Json::Value cmd;
        cmd["cmd"]="status";
        ret = WebServer::callback( cmd );
    }

    mg_send_header( conn, "Cache-Control", "no-cache");
    mg_send_header( conn, "Content-Type", "application/json");
    mg_printf_data( conn, ret.toStyledString().c_str() );

    return MG_TRUE;
}

static bool validate_user(const Json::Value& v)
{

    if( ! v.isMember("username") || !v["username"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["username"].asString(), "\t " ) == "" )
    {
        return false;
    }

    if( ! v.isMember("displayname") || !v["displayname"].isString() )
    {
        return false;
    }

    if( ! v.isMember("password") || !v["password"].isString() )
    {
        return false;
    }

    if( String::Trimmed( v["password"].asString(), "\t " ) == "" )
    {
        return false;
    }

    return true;
}

int WebServer::handle_user(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for adduser"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if( validate_user(req) )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "adduser";
            cmd["username"] = String::Trimmed( req["username"].asString(), "\t " );
            cmd["displayname"] = String::Trimmed( req["displayname"].asString(), "\t " );
            cmd["password"] = String::Trimmed( req["password"].asString(), "\t " );
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Content-Type", "application/json");
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, ret.toStyledString().c_str() );
    }
    else
    {
        logg << Logger::Debug << "Request for add user had invalid arguments"<<lend;
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Invalid argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_checkname(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for checkname"<<lend;

    Json::Value req;
    string fqdn;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if( req.isMember("opiname") && req["opiname"].isString() && String::Trimmed( req["opiname"].asString(), "\t " ) != ""  &&
        req.isMember("domain") && req["domain"].isString() && String::Trimmed( req["domain"].asString(), "\t " ) != ""
    )
    {
        fqdn = String::Trimmed( req["opiname"].asString(), "\t " )+"."+String::Trimmed( req["domain"].asString(), "\t " );

		KGP::IdentityManager& imgr = KGP::IdentityManager::Instance();

		if( ! imgr.HasDnsProvider() )
		{
			logg << Logger::Info << "Request for dns check name when not supported"<<lend;
			mg_send_status(conn, 501);
			mg_send_header( conn, "Cache-Control", "no-cache");
			mg_printf_data( conn, "Operation not supported");
			return MG_TRUE;
		}

		bool available = imgr.DnsNameAvailable(
				String::Trimmed( req["opiname"].asString(), "\t " ),
				String::Trimmed( req["domain"].asString(), "\t " ));

		mg_send_header( conn, "Content-Type", "application/json");
		mg_send_header( conn, "Cache-Control", "no-cache");
		mg_printf_data( conn, "{\"available\":%d}", available);

    }
    else
    {
        logg << Logger::Debug << "Request for check opiname arguments"<<lend;
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Invalid argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_selectname(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for update dnsname"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }
    if( req.isMember("opiname") && req["opiname"].isString() && String::Trimmed( req["opiname"].asString(), "\t " ) != ""  &&
        req.isMember("domain") && req["domain"].isString() && String::Trimmed( req["domain"].asString(), "\t " ) != ""
    )
    {
        Json::Value ret;
        string fqdn;

        fqdn = String::Trimmed( req["opiname"].asString(), "\t " )+"."+String::Trimmed( req["domain"].asString(), "\t " );

        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "opiname";
            cmd["opiname"] = fqdn;
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str() );
    }
    else
    {
        logg << Logger::Debug << "Request for select opiname had invalid arguments"<<lend;
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Invalid argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_portstatus(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for portstatus"<<lend;


    Json::Value ret;
    if( WebServer::callback != nullptr )
    {
        Json::Value cmd;
        cmd["cmd"]="portstatus";
        ret = WebServer::callback( cmd );
    }

    mg_send_header( conn, "Cache-Control", "no-cache");
    mg_send_header( conn, "Content-Type", "application/json");
    mg_printf_data( conn, ret.toStyledString().c_str() );

    return MG_TRUE;
}

int WebServer::handle_terminate(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for terminate"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if( req.isMember("shutdown") && req["shutdown"].isBool() )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "terminate";
            cmd["shutdown"] = req["shutdown"];
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str() );
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_shutdown(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for shutdown"<<lend;

    Json::Value req;

    if( ! WebServer::parse_json(conn, req) )
    {
        // True in the sense that we handled the req.
        return MG_TRUE;
    }

    if( req.isMember("action") && req["action"].isString() )
    {
        Json::Value ret;
        if( WebServer::callback != nullptr ){
            Json::Value cmd;
            cmd["cmd"] = "shutdown";
            cmd["action"] = req["action"];
            ret = WebServer::callback( cmd );
        }
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_send_header( conn, "Content-Type", "application/json");
        mg_printf_data( conn, ret.toStyledString().c_str() );
    }
    else
    {
        mg_send_status(conn, 400);
        mg_send_header( conn, "Cache-Control", "no-cache");
        mg_printf_data( conn, "Missing argument!");
    }

    return MG_TRUE;
}

int WebServer::handle_type(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for type"<<lend;


    Json::Value ret;
    if( WebServer::callback != nullptr )
    {
        Json::Value cmd;

        cmd["cmd"]= "gettype";
        ret = WebServer::callback( cmd );
    }

    mg_send_header( conn, "Cache-Control", "no-cache");
    mg_send_header( conn, "Content-Type", "application/json");
    mg_printf_data( conn, ret.toStyledString().c_str() );

    return MG_TRUE;
}

int WebServer::handle_domains(mg_connection *conn)
{
    logg << Logger::Debug << "Got request for domains"<<lend;


    Json::Value ret;
    if( WebServer::callback != nullptr )
    {
        Json::Value cmd;

        cmd["cmd"]= "getdomains";
        ret = WebServer::callback( cmd );
    }

    mg_send_header( conn, "Cache-Control", "no-cache");
    mg_send_header( conn, "Content-Type", "application/json");
    mg_printf_data( conn, ret.toStyledString().c_str() );

    return MG_TRUE;
}

int WebServer::handle_theme(mg_connection *conn)
{
    vector<string> uri;

    logg << Logger::Debug << "Got request for theme"<<lend;

    String::Split(conn->uri,uri,"/",2);
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
            if( File::FileExists(DOCUMENT_ROOT + themefile))
            {
                mg_send_status(conn,303);
                mg_send_header( conn, "Cache-Control", "no-cache");
                mg_send_header( conn, "Location", themefile.c_str());
                mg_send_header( conn, "Content-Type", "text/html");
                mg_printf_data( conn, "Redirect to theme file");
                return MG_TRUE;
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

    mg_send_status(conn,404);
    mg_send_header( conn, "Cache-Control", "no-cache");
    mg_send_header( conn, "Content-Type", "text/html");
    mg_printf_data( conn, "<h1>Not Found</h1><br>The requested URL was not found on this server.");
    return MG_TRUE;
}


int WebServer::ev_handler(mg_connection *conn, mg_event ev)
{
    int result = MG_FALSE;

    if (ev == MG_REQUEST)
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
        mg_printf_data(conn, "URI      [%s]\n", conn->uri);
        mg_printf_data(conn, "Querystr [%s]\n", conn->query_string);
        mg_printf_data(conn, "Method   [%s]\n", conn->request_method);
        mg_printf_data(conn, "version  [%s]\n", conn->http_version);
#endif

        string cmd;
        if ( string(conn->uri).length() > 1 )
        {
            cmd = "/" + String::Split(conn->uri,"/",2).front();
        }
        else
        {
            cmd = conn->uri;
        }
        auto val = std::make_pair(cmd, conn->request_method);

        if( WebServer::routes.find(val) != WebServer::routes.end() )
        {
            //mg_send_header( conn, "Cache-Control", "no-cache");
            result = WebServer::routes[val](conn);
        }

    }
    else if (ev == MG_AUTH)
    {
        result = MG_TRUE;
    }

    return result;
}

bool WebServer::parse_json(mg_connection *conn, Json::Value &val)
{
    string postdata(conn->content, conn->content_len);

    if( ! Json::Reader().parse(postdata, val) )
    {
        logg << Logger::Info << "Failed to parse input"<<lend;
        mg_printf_data( conn, "Unable to parse input");
        mg_send_status(conn, 400);

        return false;
    }

    return true;
}
