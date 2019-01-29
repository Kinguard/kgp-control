#! /bin/bash


# Default config
DO_SETUP=0
DO_INIT=0
DO_REINIT=0
DO_REBOOT=0

usageandexit()
{		# show help
		echo "Usage: cleankeep.sh [OPTION]"
		echo " -h|-?	This help"
		echo " -s	Setup system and install needed packages"
		echo " -i	Clean system for an initial setup or restore"
		echo " -r	Clean storage area and setup for a reinit"
		echo "		(Keep settings om rootfs)"
		echo " -b	Reboot system after operation"
		exit 0;
}

# Parse cmdline
OPTIND=1

while getopts "h?sirb" opt
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
	*)
		echo "ERROR parsing commandline"
		exit 3
		;;
	esac
done

if [ $DO_INIT -eq 0 ] && [ $DO_REINIT -eq 0 ]
then
	echo "You need to specify operation -i or -r"
	usageandexit
fi

if [ $DO_SETUP -eq 1 ]
then
	echo "Setup system"
	apt update
	apt install cryptsetup-bin
fi

echo "Stoping services using storage"
service secop stop
service opi-authproxy stop
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
	wipefs -a /dev/disk/by-path/platform-f10a8000.sata-ata-2-part1
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
	rm -f /etc/mailname
	ln -s /etc/opi/dnspriv.pem /etc/opi/web_key.pem
	ln -s /etc/opi/opi.cert /etc/opi/web_cert.pem
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

