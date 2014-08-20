#ifndef DISKHELPER_H
#define DISKHELPER_H

#include <string>

using namespace std;

namespace DiskHelper {

bool DeviceExists( const string& device);

/*
 * Note, devicename is block device name not path to device node
 * I.e, its sdg not /dev/sdg
 */
size_t DeviceSize( const string& devicename);

string IsMounted( const string& device);

void PartitionDevice(const string& device);

void FormatPartition(const string& device, const string& label );

void Mount(const string& device, const string& mountpoint, bool noatime=true, bool discard=true, const string& filesystem = "ext4");

void Umount(const string& device);

void SyncPaths(const string& src, const string& dst);

}

#endif // DISKHELPER_H
