#ifndef IDENTITYMANAGER_H
#define IDENTITYMANAGER_H

#include "BaseManager.h"
#include <libutils/Thread.h>
#include <libutils/ClassTools.h>

#include <memory>
#include <string>

typedef shared_ptr<Utils::Thread> ThreadPtr;


using namespace std;

class IdentityManager: public BaseManager
{
private:
	IdentityManager();
public:

	static IdentityManager& Instance();


	/**
	 * @brief SetHostname Set system hostname
	 * @param name
	 * @return true upon success
	 */
	bool SetHostname(const string& name);

	/**
	 * @brief SetDomain Set domain name for system
	 * @param domain
	 * @return true upon success
	 */
	bool SetDomain(const string& domain);

	/**
	 * @brief DnsNameAvailable Check availability of dns-name
	 * @param hostname
	 * @param domain
	 * @return true if available
	 */
	bool DnsNameAvailable(const string& hostname, const string& domain);

	/**
	 * @brief AddDnsName Register a new DNS entry for this unit
	 * @param hostname
	 * @param domain
	 * @return true if succesfull
	 */
	bool AddDnsName(const string& hostname, const string& domain);

	/**
	 * @brief HasDNSProvider
	 * @return true if there is at least one provider
	 */
	bool HasDNSProvider();

	/**
	 * @brief CleanUp clean up environment if needed
	 *        should be called when Mgr not needed anymore
	 */
	void CleanUp();

	virtual ~IdentityManager();
private:

	bool GetCertificate(const string& fqdn, const string& provider);
	bool GetSignedCert(const string& fqdn);

	bool CheckUnitID();
	bool OPLogin();

	string unitid;
	string token;
	ThreadPtr signerthread; // Used by letsencrypt signer thread
};

#endif // IDENTITYMANAGER_H
