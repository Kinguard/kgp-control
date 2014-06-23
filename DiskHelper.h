#ifndef DISKHELPER_H
#define DISKHELPER_H

#include <string>

using namespace std;

namespace DiskHelper {

void PartitionDevice(const string& device);

void FormatPartition(const string& device, const string& label );

void Mount(const string& device, const string& mountpoint);

void Umount(const string& device);

}

#endif // DISKHELPER_H
