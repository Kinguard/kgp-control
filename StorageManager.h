#ifndef STORAGEMANAGER_H
#define STORAGEMANAGER_H

#include <string>

using namespace std;

class StorageManager
{
public:
	StorageManager(const string& password);

	bool Initialize();

	bool Open();

	static bool mountDevice(const string& destination);
	static void umountDevice();

	/**
	 * @brief UseLock tells if device needs some form of unlock
	 * @return true if unlock needed, false otherwise
	 */
	static bool UseLocking();

	/**
	 * @brief IsLocked tells us if device is locked
	 * @return true if locked
	 */
	static bool IsLocked();

	/**
	 * @brief DevicePath get path to top device, ie that what should be monted
	 * @return path to top device
	 */
	static string DevicePath();

	/**
	 * @brief StorageAreaExists check if storage area is existant
	 * @return true if area exists
	 */
	static bool StorageAreaExists();

	/**
	 * @brief DeviceExists check if underlaying block device exists
	 * @return true if exists
	 */
	static bool DeviceExists();

	/**
	 * @brief Size get size of raw device
	 * @return size of device
	 */
	// TODO: revise this since it is a bit ambigous
	static size_t Size();

	string Error();

	virtual ~StorageManager();
private:

	bool checkDevice(const string& path);

	bool setupLUKS(const string& path);
	bool unlockLUKS(const string& path);
	bool InitializeLUKS(const string& device);

	bool setupStorageArea(const string& device);

	void RemoveLUKS();
	void RemoveLVM();
	bool CreateLVM();
	bool InitializeLVM();

	bool device_new;
	string password;
	string global_error;
};

#endif // STORAGEMANAGER_H
