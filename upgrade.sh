#!/bin/bash
. /etc/ossec-init.conf 2> /dev/null || exit 1
OLD=`echo $VERSION | cut -f2 -d v`
echo "wazuh_command.remote_commands=1" >> $DIRECTORY/etc/local_internal_options.conf
if [ $OLD < "3.3"]; then
	echo "Version can not be installed. Your version is lower than 3.3" >> $DIRECTORY/logs/upgrade.log
	echo "1" >  $DIRECTORY/var/upgrade/upgrade_result
else
    (sleep 5 && chmod +x $DIRECTORY/var/upgrade/src/init/*.sh && $DIRECTORY/var/upgrade/src/init/pkg_installer.sh) >/dev/null 2>&1 &
fi