#! /bin/bash


# Default config
DO_SETUP=0
DO_INIT=0
DO_REINIT=0
DO_REBOOT=0
DEVICE=keep
STDEV=/dev/disk/by-path/platform-f10a8000.sata-ata-2-part1

usageandexit()
{		# show help
		echo "Usage: cleankeep.sh [OPTION]"
		echo " -h|-?	This help"
		echo " -d [DEV] device to assume, default keep"
		echo "		vaild names include keep, rpi3"
		echo " -s	Setup system and install needed packages"
		echo " -i	Clean system for an initial setup or restore"
		echo " -r	Clean storage area and setup for a reinit"
		echo "		(Keep settings om rootfs)"
		echo " -b	Reboot system after operation"
		exit 0;
}

# Parse cmdline
OPTIND=1

while getopts "h?sirbd:" opt
do
	case "$opt" in
	h|\?)
		usageandexit
		;;
	s)
		DO_SETUP=1
		;;
	i)
		DO_INIT=1;
		;;
	r)
		DO_REINIT=1
		;;
	b)
		DO_REBOOT=1
		;;
	d)
		DEVICE=${OPTARG}
		;;
	*)
		echo "ERROR parsing commandline"
		exit 3
		;;
	esac
done


case $DEVICE in
	keep)
		;;
	rpi3)
		STDEV=/dev/disk/by-path/platform-3f980000.usb-usb-0:1.5:1.0-scsi-0:0:0:0-part1
		;;
	*)
		echo "Unknown device $DEVICE"
		exit 3
		;;
esac

if [ $DO_INIT -eq 0 ] && [ $DO_REINIT -eq 0 ]
then
	echo "You need to specify operation -i or -r"
	usageandexit
fi

if [ $DO_SETUP -eq 1 ]
then
	echo "Setup system"
	sed -i  "s/elli/vili/; s/debian-stable/debian-unstable/" /etc/apt/sources.list.d/keep.list
	apt update
	apt install cryptsetup-bin
fi

echo "Stoping services using storage"
service secop stop
service mysql stop
service opi-control stop
service nginx stop
service postfix stop
service dovecot stop

echo "Shutdown storage and backup"
/usr/share/opi-backup/umount_fs.sh
umount /dev/mapper/opi
cryptsetup luksClose opi
lvremove /dev/pool/data


if [ $DO_INIT -eq 1 ] || [ $DO_REINIT -eq 1 ]
then
	echo "Wiping storage area"
	vgremove pool
	pvremove /dev/sda1
	wipefs -a $STDEV
fi

if [ $DO_INIT -eq 1 ]
then
	echo "Restore initial settings and cleaning up"
	rm /var/opi/secop/secop.db
	if [ -e /etc/kinguard/sysconfig.json ]
	then
		sed -i 's/\"\(unitid\)/\"\#\1/' /etc/kinguard/sysconfig.json
		sed -i 's/\"\(domain\)/\"\#\1/' /etc/kinguard/sysconfig.json
		sed -i 's/\"\(hostname\)/\"\#\1/' /etc/kinguard/sysconfig.json
	fi

	rm -rf /usr/share/kinguard-certhandler/dehydrated/accounts/*
	rm /etc/opi/web*
	rm -rf /etc/opi/signed_certs
	echo "keep" > /etc/mailname
        rm -f /etc/opi/dns*.pem
        rm -f /etc/opi/opi.cert
	ln -s /usr/share/nginx-opi/opi-tmpcert.pem /etc/opi/opi.cert
	ln -s /usr/share/nginx-opi/opi-tmpkey.pem /etc/opi/dnspriv.pem
	openssl rsa -in /etc/opi/dnspriv.pem -pubout > /etc/opi/dnspub.pem
	ln -s /etc/opi/dnspriv.pem /etc/opi/web_key.pem
	ln -s /etc/opi/opi.cert /etc/opi/web_cert.pem
	touch /etc/opi/firstboot
fi

if [ -d /etc/kinguard/scripts/ccheck ]
then
	echo "Running ccheck scripts"
	run-parts /etc/kinguard/scripts/ccheck
fi

systemctl restart opi-backend

if [ -e ./opi-control ]
then
	./opi-control -D
fi

if [ $DO_REBOOT -eq 1 ]
then
	/sbin/reboot
fi


# för PC

#sudo lvremove /dev/pool/data

#sudo vgremove pool
#sudo pvremove /dev/sdd1
#sudo wipefs /dev/sdd1

