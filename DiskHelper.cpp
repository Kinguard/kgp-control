
#include <libutils/Exceptions.h>
#include <libutils/FileUtils.h>
#include <libutils/String.h>

#include <parted/parted.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iostream>
#include <map>
#include <string>

using namespace std;

namespace DiskHelper {


static bool do_stat(const std::string& path,mode_t mode )
{
	struct stat st;
	if(stat(path.c_str(),&st)){
		if( errno == ENOENT ){
				return false;
		}
		throw Utils::ErrnoException("Failed to check file");
	}
	return ((((st.st_mode)) & 0170000) & (mode));
}


void PartitionDevice(const string& device)
{
	PedDevice* dev = ped_device_get( device.c_str() );

	if( ! ped_device_open( dev ) )
	{
		throw runtime_error("Failed to open device");
	}

	PedDiskType* type = ped_disk_type_get( "msdos" );

	PedDisk* disk = ped_disk_new_fresh( dev, type );
	if( !disk )
	{
		throw runtime_error("Failed to create new partition table");
	}

	PedConstraint* constraint = ped_constraint_any( dev );
	PedGeometry* geom = ped_constraint_solve_max( constraint );

	PedPartition* part = ped_partition_new( disk, PED_PARTITION_NORMAL, NULL, geom->start, geom->end );

	ped_geometry_destroy( geom );

	if( !part )
	{
		throw runtime_error("Failed to create new partition");
	}

	ped_exception_fetch_all();

	if( !ped_disk_add_partition( disk, part, constraint ) )
	{
		ped_exception_leave_all();
		throw runtime_error("Failed to add the new partition to the partition table");
	}

	ped_constraint_destroy( constraint );

	ped_exception_leave_all();


	ped_exception_catch();

	if (ped_partition_is_flag_available( part, PED_PARTITION_LBA ) )
	{
		ped_partition_set_flag( part, PED_PARTITION_LBA, 1 );
	}

	if (!ped_disk_commit_to_dev( disk ) )
	{
		throw runtime_error("Failed writing partition table to disk");
	}

	if (!ped_disk_commit_to_os( disk ) )
	{
		throw runtime_error("Inform kernel about the changes failed");
	}

	ped_disk_destroy( disk );

	if( ! ped_device_close( dev ) )
	{
		throw runtime_error("Failed closing device");
	}

}

static int do_call(const string& cmd){
		int ret=system(cmd.c_str());
		if(ret<0){
				return ret;
		}
		return WEXITSTATUS(ret);
}

void FormatPartition(const string& device, const string& label )
{
	string cmd="/sbin/mkfs -text4 -q -L"+label + " " + device;

	if( do_call( cmd.c_str() ) != 0 )
	{
		throw Utils::ErrnoException("Failed to format device ("+device+")");
	}

}

void Mount(const string& device, const string& mountpoint)
{
	string cmd = "/bin/mount -text4 "+device+" "+mountpoint;

	if( do_call( cmd.c_str() ) != 0 )
	{
		throw Utils::ErrnoException("Failed to mount "+device+" on "+mountpoint );
	}
}

void Umount(const string& device)
{
	// TODO: Perhaps kill processes locking device using fuser
	string cmd = "/bin/umount "+device;

	if( do_call( cmd.c_str() ) != 0 )
	{
		throw Utils::ErrnoException("Failed to umount "+device );
	}
}

bool DeviceExists(const string &device)
{
	return do_stat(device, S_IFBLK );
}

size_t DeviceSize(const string &devicename)
{
	string size = Utils::File::GetContentAsString( "/sys/class/block/"+devicename+"/size");
	return strtoull(size.c_str(), NULL, 0);
}

string IsMounted(const string &device)
{
	list<string> lines = Utils::File::GetContent( "/etc/mtab");
	map<string,string> tab;
	for( auto line: lines)
	{
		list<string> words = Utils::String::Split(line);
		if( words.size() > 2 )
		{
			string device = words.front();
			words.pop_front();
			string mpoint = words.front();
			tab[device] = mpoint;
		}
	}

	return tab.find(device)==tab.end()?"":tab[device];
}

}
