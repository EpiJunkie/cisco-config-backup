#!/bin/sh

# Copyright (c) 2016, Justin D Holcomb All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



# cisco-config-backup.sh version 0.1 by Justin D Holcomb



## Purpose
# The purpose of this script is to initiate a transfer of the running and
# startup configurations from a list of Cisco devices using SNMP. This does not
# require a configuration on the Cisco devices except for a writable SNMP group.
# Below are Cisco configuration examples to help you get started.
#



## Usage
# There are two modes as declared in variable "_mode".
#
#   "insecure" mode initiates the configuration of the transfer over SNMP
#     version 1 which is in cleartext and the transfer occurs over TFTP also in
#     cleartext. If using this mode, obviously you can not be bothered to use
#     any security precautions.
#
#   "secure" mode intiates the configuration of the transfer over SNMP version 3
#     over an authenticated and encrypted channel. Then the transfer occurs over
#     SCP which is also encrypted. The SSH user and password should be a
#     restricted user which only has access to these configuration files. At the
#     very least this script should be protected by using "chmod 600" and owned
#     by root to prevent access to the stored SSH password.
#
# Commands:
#   cisco-backup-configs.sh
#   cisco-backup-configs.sh insecure|secure
#   cisco-backup-configs.sh insecure|secure erase
#   cisco-backup-configs.sh -h|--help|help
#
# The first command uses the variable `_mode` to determine the mode to run in.
# The second command uses the user input to determine the mode to run in. The
# last command above erases the MIB created for that mode, this is normally done
# at the end of each run but may be required to run independently for debugging
# purposes. The last command displays the table above as well as which actions
# to take and the default mode to run in.
#
# To run a daily cron at 3am run:
#
#   root@unix-host:~ # crontab -e
#     0 3 * * * /root/cisco-backup-config.sh >> /var/logs/cisco-config-backup.log 2>&1
#



## Cisco Example Config:
# Below are example Cisco configurations for each mode which reflect the
# initial defaults.
#
# Insecure mode:
#   router01(config)# ! Create a v1,v2c community name "orgRW" with read and write access.
#   router01(config)# snmp-server community orgRW rw
#
# Secure mode:
#   router01(config)# ! Create a group "ITTEAM", with authPriv security access and write access as
#   router01(config)# !  described in group view "BACKUPMIBONLY" when connecting only under conditions set in ACL 45.
#   router01(config)# snmp-server group ITTEAM v3 priv write BACKUPMIBONLY access 45
#   router01(config)# !
#   router01(config)# ! Create a group view "BACKUPMIBONLY" that only has access to the MIB "1.3.6.1.4.1.9.9.96.1.1.1.1" for this task.
#   router01(config)# snmp-server view BACKUPMIBONLY enterprises.9.9.96.1.1.1.1 included
#   router01(config)# !
#   router01(config)# ! Create a version 3 user "BACKUPUSER" under the group "ITTEAM" that authenticates with SHA with
#   router01(config)# !  password "USERPASS" using  AES 128-bit encryption with the key "ENCKEY".
#   router01(config)# snmp-server user BACKUPUSER ITTEAM v3 auth sha USERPASS priv aes 128 ENCKEY
#   router01(config)# !
#   router01(config)# ! Create a standard ACL with access from one host and log all other attempts.
#   router01(config)# access-list 45 remark "SNMP: ITTEAM access"
#   router01(config)# access-list 45 permit host XXX.XXX.XXX.XXX
#   router01(config)# access-list 45 deny any log
#



## Dependancies
# This tool requires the Bourne shell and net-snmp on the system running this
# script. The system receiving the configuration must have a ssh or tftp server
# running.
#
# This was tested on FreeBSD, CentOS, and Debian. On Windows, tftpd32 was
# successfully tested to receive the configuration files.
#



## Cisco Device List File:
# The file described in variable "_devices_text_file" is the full path to a
# plain text file which contains the device name, a single space, and then an IP
# of the device. The next line follows the same format for the next device. An
# IP is required as snmpset requires it. If the device names are in DNS, then an
# attempt is made to resolve a IPv4 address using drill or dig, depending on the
# OS. Blank lines and lines starting with an octothrop "#" are ignored.
# Example:
#
#             # Site 0
#             router01 10.0.0.1
#             switch01 10.0.0.2
#             switch02 10.0.0.3
#
#             # Site 1
#             router11 10.0.1.1
#             switch11 10.0.1.2
#             switch12 10.0.1.3
#



## Variables
# Modify these values before use.

# Universal variables to modify
_devices_text_file='/usr/local/lib/network_devices.txt'
_organization="Your organization name"
_date=`date +%Y%m%d`
_mode="insecure"                        # Options: insecure|secure
_action_copy_startup="1"                # Options: 0|1
_action_copy_running_to_startup="1"     # Options: 0|1
_action_copy_running="1"                # Options: 0|1

# Insecure Settings - uses SNMP v1 and TFTP
_tftp_ip="10.0.0.250"							# This must be an IP address
_tftp_running_config_file_path="cisco-configs"	# Relative path without ending "/"
_tftp_startup_config_file_path="cisco-configs"	# Relative path without ending "/"
_snmp_rw_comm="orgRW"							# This must be a group with write access

# Secure Settings - uses SNMP v3 and SCP/SSH
# If storing a ssh password in this file, make sure to 'chmod u=x' the file, if
# not at least removing permissions for the group and others by 'chmod go-rwe'.
_scp_snmpv3_user="BACKUPUSER"
_scp_snmpv3_user_passphrase="USERPASS"			# Tested up to 16 characters
_scp_snmpv3_level="authPriv"					# Options: noAuthNoPriv|authNoPriv|authPriv
_scp_snmpv3_auth_protocol="sha"					# Options: sha|md5
_scp_snmpv3_privacy_protocol="aes"     			# Options: des|aes    AES only works at 128-bit
_scp_snmpv3_privacy_passphrase="ENCKEY"			# Tested up to 16 characters
_scp_ssh_ip_addr="10.0.0.250"					# This must be an IP address
_scp_ssh_user="restricted-user"
_scp_ssh_password="SSHUSERPASS"
_scp_running_config_file_path="/home/restricted-user/backup/cisco-configs"		# Absolute path without ending "/"
_scp_startup_config_file_path="/home/restricted-user/backup/cisco-configs"		# Absolute path without ending "/"

# Do not modify these variables
_uuid=`/bin/uuidgen`
_tmp_file=`grep -v -E '^#.*|^$' $_devices_text_file > /tmp/$_uuid`



# Check if snmpset is available and exit if not.
snmpset -V >/dev/null 2>&1
[ "$?" != 0 ] && echo "[ERROR] Unable to find 'snmpset' binary on system in \$PATH, exitting prematurely." && exit 1



# Functions
## Insecure functions
### Runs SNMP commands over version 1 to initiate a TFTP copy of the startup and running configuration.
__function_run_tftp() {

	echo "Running Cisco backup configuration for $_organization devices over TFTP and SNMP v1."

	while IFS= read -r _device_line ; do

		# Get IP from line
		_device_ip="$( echo $_device_line | awk '{ print $2 }' )"

		# Get hostname from line
		_device_hostname="$( echo $_device_line | awk '{ print $1 }' )"

		# File name
		_filename="${_date}--${_device_hostname}--${_device_ip}.cfg"

		__function_find_ip

		echo "Running SNMP write commands on $_device_hostname at ${_device_ip}... "

		# Check to see if host is up
		ping -c 1 ${_device_ip} >/dev/null 2>&1
		[ $? != 0 ] && echo "$_device_hostname was not pingable at $_device_ip, one attempt was made." && continue

	   # Copy startup config
		if [ "$_action_copy_startup" = 1 ]; then
			echo "   copying startup-config via TFTP."

			# The ConfigCopyProtocol is set to TFTP
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.2.128 i 1

			# Set the SourceFileType to startup-config
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.3.128 i 3

			# Set the DestinationFileType to networkfile
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.4.128 i 1

			# Sets the ServerAddress to the IP address of the TFTP server
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.5.128 a ${_tftp_ip}

			# Sets the CopyFilename to your desired file name.
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.6.128 s ${_tftp_startup_config_file_path}/${_filename}

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.128 i 1
		fi

	   # Copy running config
		if [ "$_action_copy_running" = 1 ]; then
			echo "   copying running-config via TFTP."

			# The ConfigCopyProtocol is set to TFTP
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.2.111 i 1

			# Set the SourceFileType to running-config
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.3.111 i 4

			# Set the DestinationFileType to networkfile
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.4.111 i 1

			# Sets the ServerAddress to the IP address of the TFTP server
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.5.111 a ${_tftp_ip}

			# Sets the CopyFilename to your desired file name.
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.6.111 s ${_tftp_running_config_file_path}/${_filename}

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.111 i 1
		fi

	   # Copy running-config to startup-config
		if [ "$_action_copy_running_to_startup" = 1 ]; then
			echo "   copying running-config to startup-confg."

			# Set the SourceFileType to running-config
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.3.115 i 4

			# Set the DestinationFileType to startup-config
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.4.115 i 3

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.115 i 1
		fi

		echo "done."
		echo ""
		echo ""
		_device_ip=""
		_device_hostname=""

	done </tmp/$_uuid

	__function_stage2_erase_mib_tftp
}

### Erases MIB setttings from device. This is required as kicking off another action is not possible.
__function_stage2_erase_mib_tftp() {

	echo "Erasing SNMP MIBs for Cisco backup configuration."

	while IFS= read -r _device_line ; do

		# Get IP from line
		_device_ip="$( echo $_device_line | awk '{ print $2 }' )"

		# Get hostname from line
		_device_hostname="$( echo $_device_line | awk '{ print $1 }' )"

		__function_find_ip

		echo -n "   on $_device_hostname at ${_device_ip}... "

		# Check to see if host is up
		ping -c 1 ${_device_ip} >/dev/null 2>&1
		[ $? != 0 ] && echo "$_device_hostname was not pingable at $_device_ip, one attempt were made." && continue

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 111
		snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.111 i 6 >/dev/null 2>&1

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 115
		snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.115 i 6 >/dev/null 2>&1

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 128
		snmpset -Cq -v 1 -c ${_snmp_rw_comm} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.14.128 i 6 >/dev/null 2>&1

		echo "done."

		_device_ip=""
		_device_hostname=""

	done </tmp/$_uuid
}



## Secure functions
### Runs SNMP over version 3 using authentication and encryption to initiate a SCP copy of the startup and running configuration.
__function_run_scp() {

	echo "Running Cisco backup configuration for $_organization devices over SCP and SNMP v3."

	while IFS= read -r _device_line ; do

		# Get IP from line
		_device_ip="$( echo $_device_line | awk '{ print $2 }' )"

		# Get hostname from line
		_device_hostname="$( echo $_device_line | awk '{ print $1 }' )"

		# File name
		_filename="${_date}--${_device_hostname}--${_device_ip}.cfg"

		__function_find_ip

		echo "Running SNMP write commands on $_device_hostname at ${_device_ip}... "

		# Check to see if host is up
		ping -c 1 ${_device_ip} >/dev/null 2>&1
		[ $? != 0 ] && echo "$_device_hostname was not pingable at $_device_ip, one attempt were made." && continue

	   # Copy startup config to SCP
		if [ "$_action_copy_startup" = 1 ]; then
			echo "   copying startup-config via SCP."

			# The ConfigCopyProtocol is set to SCP
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.2.129 i 4

			# Set the SourceFileType to startup-config
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.3.129 i 3

			# Set the DestinationFileType to networkfile
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.4.129 i 1

			# Sets the ServerAddress to the IP address of the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.5.129 a ${_scp_ssh_ip_addr}

			# Sets the Usernanme to use on the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.7.129 s ${_scp_ssh_user}

			# Sets the password to use on the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.8.129 s ${_scp_ssh_password}

			# Sets the CopyFilename to your desired file name.
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.6.129 s ${_scp_startup_config_file_path}/${_filename}

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.129 i 1
		fi

	   # Copy running config to SCP
		if [ "$_action_copy_running" = 1 ]; then
			echo "   copying running-config via SCP."

			# The ConfigCopyProtocol is set to SCP
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip} 1.3.6.1.4.1.9.9.96.1.1.1.1.2.112 i 4

			# Set the SourceFileType to running-config
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.3.112 i 4

			# Set the DestinationFileType to networkfile
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.4.112 i 1

			# Sets the ServerAddress to the IP address of the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.5.112 a ${_scp_ssh_ip_addr}

			# Sets the Usernanme to use on the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.7.112 s ${_scp_ssh_user}

			# Sets the password to use on the SCP server
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.8.112 s ${_scp_ssh_password}

			# Sets the CopyFilename to your desired file name.
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.6.112 s ${_scp_running_config_file_path}/${_filename}

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.112 i 1
		fi

	   # Copy running-config to startup-config
		if [ "$_action_copy_running_to_startup" = 1 ]; then
			echo "   copying running-config to startup-confg."

			# Set the SourceFileType to running-config
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.3.116 i 4

			# Set the DestinationFileType to startup-config
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.4.116 i 3

			# Sets the CopyStatus to active which starts the copy process.
			snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.116 i 1
		fi

		echo "done."
		echo ""
		echo ""
		_device_ip=""
		_device_hostname=""

	done </tmp/$_uuid

	__function_stage2_erase_mib_scp

	echo "Done erasing SNMP MIBs for Cisco backup configuration."
	echo "Done backing up Cisco configurations."
}

### Stage 2 to erase
__function_stage2_erase_mib_scp() {

	echo "Erasing SNMP MIBs for Cisco backup configuration."

	while IFS= read -r _device_line ; do

		# Get IP from line
		_device_ip="$( echo $_device_line | awk '{ print $2 }' )"

		# Get hostname from line
		_device_hostname="$( echo $_device_line | awk '{ print $1 }' )"

		echo -n "   on $_device_hostname at ${_device_ip}... "

		# Check to see if host is up
		ping -c 1 ${_device_ip} >/dev/null 2>&1
		[ $? != 0 ] && echo "$_device_hostname was not pingable at $_device_ip, one attempt was made." && continue

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 112
		snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.112 i 6 >/dev/null 2>&1

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 116
		snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.116 i 6 >/dev/null 2>&1

		# Sets the CopyStatus to delete which cleans all saved informations out of the MIB 129
		snmpset -Cq -v 3 -u ${_scp_snmpv3_user} -l ${_scp_snmpv3_level} -a ${_scp_snmpv3_auth_protocol} -A ${_scp_snmpv3_user_passphrase} -x ${_scp_snmpv3_privacy_protocol} -X ${_scp_snmpv3_privacy_passphrase} ${_device_ip}  1.3.6.1.4.1.9.9.96.1.1.1.1.14.129 i 6 >/dev/null 2>&1

		echo "done."

		_device_ip=""
		_device_hostname=""

	done </tmp/$_uuid
}

# If IP is not given, then hope DNS can resolve is working
__function_find_ip() {

	if [ -z "$_device_ip" ]; then
		echo "Missing IP field (2nd field, space separated.) in $_devices_text_file for $_device_hostname. Checking to see if it can be resolved..."

		# Check to see if dig is available on system.
		dig -v >/dev/null 2>&1
		if [ "$?" = 0 ]; then
			_device_ip="$( dig +short -t a $_device_hostname )"
		else
			echo "dig not installed on system, checking for drill..."
			drill -v >/dev/null 2>&1
			if [ "$?" = 0 ]; then
				_device_ip="$( drill $_device_hostname | grep -A1 ";; ANSWER SECTION:" | tail -n1 | awk '{ print $5 }' | grep -o -E '^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$' )"
			else
				echo "drill not installed on system."
			fi
		fi

		[ -z "$_device_ip" ] && echo "Skipping to next host due to unresolved hostname." && continue
	fi
}

# Parse user input.
__function_parse() {

	# Print date for log
	echo ""
	echo -n "Date: "
	date

	# Run help immediately.
	if [ "$1" = "help" ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
		__function_run_help
		exit

	# Runs using the variable "_mode" when no user input is given.
	elif [ -z "$1" ]; then
		if [ "$_mode" = "insecure" ]; then
			__function_run_tftp
		elif [ "$_mode" = "secure" ]; then
			__function_run_scp
		else
			echo "Unrecognized mode."
			exit 1
		fi

	# Runs using the input from the first parameter when the second parameter is not used.
	elif [ -z "$2" ]; then
		if [ "$1" = "insecure" ]; then
			__function_run_tftp
		elif [ "$1" = "secure" ]; then
			__function_run_scp
		else
			echo "Unrecognized parameter, 'insecure' or 'secure' are valid."
			exit 1
		fi

	# Runs the MIB erase function only for the selected mode.
	elif [ "$2" = "erase" ]; then
		if [ "$1" = "insecure" ]; then
			__function_stage2_erase_mib_tftp
		elif [ "$1" = "secure" ]; then
			__function_stage2_erase_mib_scp
		else
			echo "Unrecognized second parameter."
			exit 1
		fi

	# Catch-all
	else
		echo "Unrecognized command."
		exit 1
	fi

	# Delete temporary network list if it exists
	[ -e "/tmp/$_uuid" ] && rm -f /tmp/$_uuid
}

# Display help
__function_run_help() {
	echo "$_version"
	echo "Usage:"
	echo "  $0"
	echo "  $0 secure|insecure"
	echo "  $0 secure|insecure erase"
	echo "  $0 -h|--help|help"
	echo "This script copies the running and startup config on Cisco"
	echo "devices via SNMP over TFTP or SCP. Optionally the running"
	echo "configuration can be copied to the startup configuration as"
	echo "well."
	echo "The following variables are set:"
	echo "    \$_action_copy_startup is set to $_action_copy_startup"
	echo "    \$_action_copy_running_to_startup is set to: $_action_copy_running_to_startup"
	echo "    \$_action_copy_running is set to: $_action_copy_running"
	echo "Default security mode: $_mode"
	echo "More variables are set within the script, please edit to"
	echo "meet system configuration needs."
}

# Kicks off execution of code
__function_parse $@
