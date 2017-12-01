#include "StorageManager.h"

#include "Config.h"

#include <libutils/FileUtils.h>
#include <libutils/Logger.h>

#include <libopi/LVM.h>
#include <libopi/Luks.h>
#include <libopi/SysInfo.h>
#include <libopi/DiskHelper.h>

using namespace Utils;
using namespace OPI;

StorageManager::StorageManager(const string &password): device_new(false), password(password)
{

}

/**
 * @brief checkDevice check if device is available, wait a while and retry if
 *        currently not available.
 * @param path Path to device to check
 * @return
 */
bool StorageManager::checkDevice(const string& path)
{
	logg << Logger::Debug << "Check device " << path << lend;
	int retries = 50;
	bool done=false;
	do
	{
		try
		{
			logg << Logger::Debug << "Checking device"<<lend;
			done = DiskHelper::DeviceExists( Utils::File::RealPath( path ) );
		}
		catch(std::runtime_error& err)
		{
			logg << Logger::Debug << "Unable to probe device: "<< err.what() << lend;
		}
		if( !done && retries > 0 )
		{
			logg << Logger::Debug << "Device not yet available, waiting" << lend;
			usleep(1000);
		}
	}while( !done && retries-- > 0);

	if ( ! done )
	{
		logg << Logger::Notice << "Unable to locate device, aborting" << lend;
		this->global_error = "Unable to locate storage device";
		return false;
	}

	logg << Logger::Debug << "Device " << path << " avaliable" << lend;
	return true;
}

bool StorageManager::mountDevice(const string &destination)
{
	// Work out what to mount
	string source = StorageManager::DevicePath();

	logg << Logger::Debug << "Mount "<< source << " device at " << destination << lend;

	try
	{
		// Make sure device is not mounted (Should not happen)
		if( DiskHelper::IsMounted( source ) != "" )
		{
			DiskHelper::Umount( source );
		}

		DiskHelper::Mount( source , destination );
	}
	catch( ErrnoException& err)
	{
		return false;
	}

	return true;
}

void StorageManager::umountDevice()
{
	DiskHelper::Umount( StorageManager::DevicePath() );
}

bool StorageManager::Initialize()
{
	logg << Logger::Debug << "Storagemanager initialize" << lend;


	if( ! this->checkDevice( sysinfo.StorageDevicePath() ) )
	{
		return false;
	}

	string curdevice = sysinfo.StorageDevicePath();
	if( SysInfo::useLVM() )
	{
		curdevice = LVMDEVICE;
		if( ! this->InitializeLVM() )
		{
			return false;
		}
	}

	if( SysInfo::useLUKS() )
	{
		if( ! this->InitializeLUKS( curdevice) )
		{
			return false;
		}
		curdevice = LUKSDEVICE;
	}

	return this->setupStorageArea( curdevice );
}

bool StorageManager::Open()
{

	if( SysInfo::useLUKS() )
	{
		string luksdevice = SysInfo::useLVM() ? LVMDEVICE : sysinfo.StorageDevicePath();

		Luks l( luksdevice );

		if( ! l.Active("opi") )
		{
			logg << Logger::Debug << "Activating LUKS volume"<<lend;
			if ( !l.Open("opi", this->password) )
			{
				logg << Logger::Debug << "Failed to openLUKS volume on "<<sysinfo.StorageDevicePath()<< lend;
				this->global_error = "Unable to unlock crypto storage. (Wrong password?)";
				return false;
			}
		}

	}

	return true;
}

bool StorageManager::UseLocking()
{
	return SysInfo::useLUKS();
}

bool StorageManager::IsLocked()
{
	Luks l( StorageManager::DevicePath() );

	return ! l.Active( StorageManager::DevicePath() );
}

string StorageManager::DevicePath()
{
	string source = sysinfo.StorageDevicePath();

	if( SysInfo::useLUKS() )
	{
		source = LUKSDEVICE;
	}
	else if( SysInfo::useLVM() )
	{
		source = LVMDEVICE;
	}

	return source;
}

bool StorageManager::StorageAreaExists()
{
	logg << Logger::Debug << "Check if storage area exists"<<lend;
	try
	{
		// With no underlaying device there can't be any upper layer either
		if( ! DiskHelper::DeviceExists( sysinfo.StorageDevice() ) )
		{
			return false;
		}

		// We need storage space on underlaying device. I.e. an sd-card is available in slot
		if( DiskHelper::DeviceSize( sysinfo.StorageDevice() ) == 0 )
		{
			return false;
		}

		if( SysInfo::useLVM() && ! DiskHelper::DeviceExists( LVMDEVICE ) )
		{
			return false;
		}

		// If we have a luks-volume on underlaying storage we assume we have a correct setup
		if( SysInfo::useLUKS() )
		{
			if( SysInfo::useLVM() && ! Luks::isLuks( LVMDEVICE ) )
			{
				return false;
			}

			if( ! SysInfo::useLVM() && ! Luks::isLuks( sysinfo.StorageDevicePath() ) )
			{
				return false;
			}
		}

	}
	catch( std::exception& e)
	{
		logg << Logger::Notice << "Failed to check" << StorageManager::DevicePath()<< ": " << e.what() <<lend;
		return false;
	}

	return true;
}

bool StorageManager::DeviceExists()
{
	try
	{
		string device = File::RealPath( sysinfo.StorageDevice() );

		logg << Logger::Debug << "Checking device " << device << lend;


		if( ! DiskHelper::DeviceExists( device ) )
		{
			return false;
		}

		if( DiskHelper::DeviceSize( device ) == 0 )
		{
			return false;
		}

	}catch( std::exception& e)
	{
		logg << Logger::Notice << "Failed to check device: " << e.what() <<lend;
		return false;
	}
	return true;
}

size_t StorageManager::Size()
{
	return DiskHelper::DeviceSize( sysinfo.StorageDevicePath() );
}

string StorageManager::Error()
{
	return this->global_error;
}

StorageManager::~StorageManager()
{

}

bool StorageManager::setupLUKS(const string &path)
{
	try
	{
		Luks l( Utils::File::RealPath( path ) );
		l.Format( this->password );

		if( ! l.Open("opi", this->password ) )
		{
			this->global_error = "Wrong password";
			return false;
		}

		DiskHelper::FormatPartition( LUKSDEVICE,"OPI");
	}
	catch( std::runtime_error& err)
	{
		logg << Logger::Notice << "Failed to format device: "<<err.what()<<lend;
		return false;
	}

	return true;
}

bool StorageManager::unlockLUKS(const string &path)
{
	Luks l( path );

	if( ! l.Active("opi") )
	{
		logg << Logger::Debug << "Activating LUKS volume"<<lend;
		if ( !l.Open("opi", this->password ) )
		{
			this->global_error = "Wrong password";
			return false;
		}
	}

	return true;
}

bool StorageManager::InitializeLUKS(const string &device)
{
	logg << Logger::Debug << "Initialize LUKS on device " << device <<lend;
	if( ! Luks::isLuks( device ) )
	{
		logg << Logger::Notice << "No luks volume on device " << device << " creating" << lend;

		if( ! this->setupLUKS( device ) )
		{
			return false;
		}

		this->device_new = true;
	}

	if( ! this->unlockLUKS( device ) )
	{
		return false;
	}

	return true;
}

bool StorageManager::setupStorageArea(const string &device)
{
	try
	{
		// Make sure device is not mounted (Should not happen)
		if( DiskHelper::IsMounted( device ) != "" )
		{
			DiskHelper::Umount( device );
		}

		if( this->device_new )
		{
			logg << Logger::Debug << "Sync mmc to storage device " << device <<lend;
			// Sync data from emmc to sd
			DiskHelper::Mount( device , TMP_MOUNT );

			DiskHelper::SyncPaths(MOUNTPOINT, TMP_MOUNT);

			DiskHelper::Umount(device);

			this->device_new = false;
		}

		// Mount in final place
		DiskHelper::Mount( device , MOUNTPOINT );
	}
	catch( ErrnoException& err)
	{
		logg << Logger::Error << "Finalize unlock failed: " << err.what() << lend;
		this->global_error = "Unable to access SD card";
		return false;
	}

	return true;
}

void StorageManager::RemoveLUKS()
{
	logg << Logger::Debug << "Remove any active LUKS volumes on storage area" << lend;
	try
	{
		if( SysInfo::useLVM() && Luks::isLuks( LVMDEVICE ) )
		{
			logg << Logger::Debug << "Try closing device" << lend;
			Luks l( LVMDEVICE );

			l.Close("opi" );
		}
	}
	catch( std::exception& e)
	{
		logg << Logger::Notice << "Failed to close LUKS" << e.what() << lend;
	}
	logg << Logger::Debug << "Remove LUKS done"<< lend;
}

void StorageManager::RemoveLVM()
{
	logg << Logger::Debug << "Remove any present LVM volumes"<<lend;
	try
	{
		LVM l;

		list<VolumeGroupPtr> vgs = l.ListVolumeGroups();
		for( auto& vg: vgs)
		{
			if( vg == nullptr )
			{
				logg << Logger::Error << "Got nullptr vg from listvgs"<< lend;
				continue;
			}
			list<LogicalVolumePtr> lvs = vg->GetLogicalVolumes();
			for( auto& lv: lvs)
			{
				if( lv == nullptr )
				{
					logg << Logger::Error << "Got nullptr lv from listlvs"<< lend;
					continue;
				}
				vg->RemoveLogicalVolume(lv);
			}

			l.RemoveVolumeGroup(vg);
		}

		//TODO: remove all PVs
	}
	catch( std::exception& e)
	{
		logg << Logger::Error << "Failed to remove lvms: " << e.what()<<lend;
	}
	logg << Logger::Debug << "Remove done"<<lend;
}

bool StorageManager::InitializeLVM()
{
	logg << Logger::Debug << "Initialize LVM on " << LVMDEVICE << lend;
	try
	{
		if( ! StorageManager::StorageAreaExists() )
		{
			logg << Logger::Notice << "No LVM on device "<< sysinfo.StorageDevicePath()<<", creating"<<lend;

			// Unfortunately we cant assume a clean slate, there could be a partial/full lvm here
			// try to remove
			if( SysInfo::useLUKS() )
			{
				this->RemoveLUKS();
			}
			this->RemoveLVM();

			DiskHelper::PartitionDevice( sysinfo.StorageDevice() );

			if( ! this->checkDevice( sysinfo.StorageDevicePath() ) )
			{
				logg << Logger::Error << "No such device avaliable (" << sysinfo.StorageDevicePath() << lend;
				return false;
			}

			// Setup device
			LVM lvm;
			PhysicalVolumePtr pv;
			try
			{
				pv = lvm.CreatePhysicalVolume( File::RealPath( sysinfo.StorageDevicePath() ) );
			}
			catch( ErrnoException& err )
			{
				logg << Logger::Debug << "Device not yet reappeared, wait and check" << lend;
				// Udev most likely not done yet, check device once more and retry.
				if( ! this->checkDevice( sysinfo.StorageDevicePath() ) )
				{
					logg << Logger::Error << "Device disappeared? (" << sysinfo.StorageDevicePath() << lend;
					return false;
				}

				pv = lvm.CreatePhysicalVolume( File::RealPath( sysinfo.StorageDevicePath() ) );
			}

			VolumeGroupPtr vg = lvm.CreateVolumeGroup( LVMVG, {pv} );

			LogicalVolumePtr lv = vg->CreateLogicalVolume( LVMLV );

			this->device_new = true;
		}

	}catch( std::exception& e)
	{
		logg << Logger::Error << "Unable to setup lvm: " << e.what() << lend;
		return false;
	}

	// We should now have a valid LVM device to work with
	return true;
}
