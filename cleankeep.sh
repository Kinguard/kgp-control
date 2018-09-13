#!/bin/bash
if [ "$1" == "upgrade" ]
then
	apt update
	apt install cryptsetup-bin
fi

service secop stop
service opi-authproxy stop
service mysql stop
service opi-control stop
service nginx stop
service postfix stop
service dovecot stop

/usr/share/opi-backup/umount_fs.sh
umount /dev/mapper/opi
cryptsetup luksClose opi
lvremove /dev/pool/data


vgremove pool
pvremove /dev/sda1
wipefs -a /dev/disk/by-path/platform-f10a8000.sata-ata-2-part1
rm /var/opi/secop/secop.db
sed -i 's/\(unitid\)/\#\1/' /etc/kinguard/sysconfig.json
sed -i 's/\(domain\)/\#\1/' /etc/kinguard/sysconfig.json
sed -i 's/\(hostname\)/\#\1/' /etc/kinguard/sysconfig.json

rm -rf /usr/share/kinguard-certhandler/dehydrated/accounts/*
rm /etc/opi/web*
rm -rf /etc/opi/signed_certs
ln -s /etc/opi/dnspriv.pem /etc/opi/web_key.pem
ln -s /etc/opi/opi.cert /etc/opi/web_cert.pem

./opi-control -D





# för PC

#sudo lvremove /dev/pool/data

#sudo vgremove pool
#sudo pvremove /dev/sdd1
#sudo wipefs /dev/sdd1

