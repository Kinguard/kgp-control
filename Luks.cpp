#include "Luks.h"

#include <libutils/Exceptions.h>

#include <libudev.h>

#include <iostream>
using namespace std;
using namespace Utils;

Luks::Luks(const string &path): path(path), open(false)
{
	if( crypt_init( &this->cryptdevice, path.c_str() ) < 0 )
	{
		throw Utils::ErrnoException("Failed to init cryptsetup");
	}
}

bool Luks::isLuks(const string &device)
{
	struct udev *udev=udev_new();

	if ( !udev ) {
		return false;
	}

	struct udev_device *dev = udev_device_new_from_subsystem_sysname( udev, "block", device.c_str() );
	if( ! dev )
	{
		udev_unref(udev);
		return false;
	}

	const char* c_type = udev_device_get_property_value(dev, "ID_FS_TYPE");
	if( ! c_type )
	{
		udev_device_unref( dev );
		udev_unref(udev);
		return false;
	}

	string type(c_type);
	bool ret = type == "crypto_LUKS";

	udev_device_unref( dev );
	udev_unref(udev);

	return ret;
}

void Luks::Format(const string &password)
{
	struct crypt_params_luks1 params;

	params.hash = "sha1";
	params.data_alignment = 0;
	params.data_device = NULL;

	int r = crypt_format(
				this->cryptdevice,
				CRYPT_LUKS1,
				"aes",
				"xts-plain64",
				NULL,
				NULL,
				256/8,
				&params
				);

	if( r < 0 )
	{
		throw Utils::ErrnoException("Failed to LUKS format device");
	}

	r = crypt_keyslot_add_by_volume_key(
				this->cryptdevice,
				CRYPT_ANY_SLOT,
				NULL,
				0,
				password.c_str(),
				password.length()
				);
	if( r < 0 )
	{
		throw Utils::ErrnoException("Failed to add key to LUKS volume");
	}

}

bool Luks::Open(const string &name, const string &password, bool discard)
{

	int r = crypt_load(
				this->cryptdevice,
				CRYPT_LUKS1,
				NULL
				);

	if( r < 0 )
	{
		throw Utils::ErrnoException("Failed to load context");
	}

	r = crypt_activate_by_passphrase(
				this->cryptdevice,
				name.c_str(),
				CRYPT_ANY_SLOT,
				password.c_str(),
				password.length(),
				discard?CRYPT_ACTIVATE_ALLOW_DISCARDS:0
				);

	if( r < 0 )
	{
		return false;
	}
	this->name = name;
	this->open = true;

	return true;
}

bool Luks::Active(const string &name)
{
	return crypt_status( this->cryptdevice, name.c_str() ) == CRYPT_ACTIVE;
}

void Luks::Close(const string mname)
{
	string mappername;
	if( mname != "" )
	{
		mappername = mname;
	}
	else
	{
		mappername = this->name;
	}

	if( crypt_deactivate( this->cryptdevice, mappername.c_str() ) < 0 )
	{
		throw Utils::ErrnoException("Failed to deactivate device");
	}
	this->open = false;
}

Luks::~Luks()
{
	crypt_free( this->cryptdevice );
}
