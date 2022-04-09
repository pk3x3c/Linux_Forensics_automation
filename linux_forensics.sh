#!/bin/bash

#INFO : For each type of forensics a file will be created

#Making a directory to save all files in that

	#statements
if [ "$3" = "-h" ] || [ "$1" = '-h' ]; then
	echo "Usage: $0 [-d] <direcoty_name> [-h]"
	echo ""
	echo "-d : directory name "
	echo "-h : help menu "
	echo "[] : Non mandatory argument "
	echo "<> : argument value for switch "
	echo ""
	echo "default directory = linux_forensics"
	echo ""
	echo "Example: $0 -d /tmp"
	exit 
fi

if [ "$1" = "-d" ]; then
	directory=$2
else
	directory="linux_forensics"
fi


echo "		 ___________________________.."
echo "		|;;|                     |;;||"
echo "		|[]|---------------------|[]||"
echo "		|;;|                     |;;||"
echo "		|;;|       Linux         |;;||"
echo "		|;;|     Forensics       |;;||"
echo "		|;;|                     |;;||"
echo "		|;;|    @SahilBasia      |;;||"
echo "		|;;;;;;;;;;;;;;;;;;;;;;;;;;;||"
echo "		|;;;;;;_______________ ;;;;;||"
echo "		|;;;;;|  ___          |;;;;;||"
echo "		|;;;;;| |;;;|         |;;;;;||"
echo "		|;;;;;| |;;;|         |;;;;;||"
echo "		|;;;;;| |___|         |;;;;;||"
echo "		\_____|_______________|_____||"
echo "		 ~~~~~^^^^^^^^^^^^^^^^^~~~~~~ "
echo""





#condition to check if directory exists already or not
if [ ! -d $directory ]; then												# later pls add command line arguemnts
	mkdir -p $directory;
	echo -e ">>> Directory $directory created\r\n"
else
	echo -e ">>> Directory creation failed. Check if directory creation permission is given or if there is directory with same name"
	exit 0
fi


## Phase 0 - Quick Risk Audit Process
#
# Hunting for passwords
#
#echo -e "[-] Hunting for passwords started"
#grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null > pass_hunt.txt
#echo -e "[-] Hunting for passwords is done"

# Hunting for SSH and authorized Keys
hunting_keys()
{
	echo -e "\e[1;31m[-] Hunting for authorized keys started"
	find / -name authorized_keys 2>/dev/null > $directory/authorized_keys.txt
	echo -e -e "\e[1;36m>>>\e[0m \e[1;35mauthorized_keys.txt file created"

	echo -e "\e[1;31m[-] Hunting for SSH keys started"
	find / -name id_rsa 2>/dev/null > $directory/ssh_keys.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mssh_keys.txt file created"
}


#LinuxStart enumeration
#echo -e "[-] LinSmart enumeration started"
#./lse.sh 2>/den/null > linsmart_enum.txt
#echo -e "[-] LinSmart enumeration is done"



## Phase 1 - Users and Groups
#
#Users
hunting_user_s()
{
	echo -e "\e[1;31m[-] Hunting users list started"
	cat /etc/passwd 2>/dev/null > $directory/all_users.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mall_users.txt file is created"
}


#UID-0 Users
hunting_uid_0()
{
	echo -e "\e[1;31m[-] Hunting users with uid-0 started"
	grep :0: /etc/passwd 2>/dev/null > $directory/uid-0_users.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35muid-0_users.txt file created"
}


#temporary users
hunting_tmp_users()
{
	echo -e "\e[1;31m[-] Hunting temporary users"
	find / -nouser -print 2>/dev/null > $directory/temp_users.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mtemp_users.txt file created"
}


#Groups

#Group list
hunting_grp_lst()
{
	echo -e "\e[1;31m[-] Hunting group list started"
	cat /etc/group 2>/dev/null > $directory/all_groups.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mall_groups.txt file created"
}


#sudoers list
hunting_sudo_lst()
{
	echo -e "\e[1;31m[-] Hunting sudoers group"
	cat /etc/sudoers 2>/dev/null > $directory/sudoers.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35msudoers.txt file created"
}


#capabilities
hunting_capability()
{
	echo -e "\e[1;31m[-] Hunting capabilities"
	getcap -r / 2>/dev/null > $directory/capabilities.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mcapability.txt file created"
}



## Phase 2 - system configuration
#
#Network configurations
hunting_net_config()
{
	echo -e "\e[1;31m[-] Hunting network configurations"


	#echo -e " File is /etc/network/interfaces" 2>/dev/null > $directory/net_config.txt
	echo -e "\e[1;33mNetwork Interfaces\e[0m" >> $directory/net_config.txt 
	cat /etc/network/interfaces 2>/dev/null >> $directory/net_config.txt
	#echo -e " File is resolve.conf" 2>/dev/null >> $directory/net_config.txt
	echo -e "\e[1;33mDNS Resolves\e[0m" >> $directory/net_config.txt
	cat /etc/resolv.conf 2>/dev/null >> $directory/net_config.txt
	#echo -e " File is dnsmasq.conf" 2>/dev/null >> $directory/net_config.txt
	#cat /etc/dnsmasq.conf 2>/dev/null >> $directory/net_config.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mnet_config.txt file created"
}



#OS information
hunting_os_info()
{
	echo -e "\e[1;31m[-] Hunting OS info"
	cat /etc/os-release 2>/dev/null > $directory/os_info.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mos_info.txt file fcreated"
}


#Hostname info
hunting_host_info()
{
	echo -e "\e[1;31m[-] Hunting hostname info"
	cat /etc/hostname 2>/dev/null > $directory/hostname_info.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mhostname_info.txt file created"	
}


#Time zone info
hunting_time_zone()
{
	echo -e "\e[1;31m[-] Hunting Time zone info"
	cat /etc/timezone 2>/dev/null > $directory/timezone_info.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mtimezone_info.txt file created"
}

#kernel modules
hunting_kernel_modules()
{
	echo -e "\e[1;31m[-] Hunting kernel modules"
	lsmod 2>/dev/null > $directory/kernel_modules.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mkernel_modules.txt file created"
}


## Phase 3 - User activities
#
#Bash history
hunting_bash_hist()
{
	echo -e "\e[1;31m[-] Hunting bash history"
	if [[  -r "/root/.zsh_history"  ||  -r "~/.zsh_history" ]]; then
		nl /root/.zsh_history > $directory/shell_history.txt
	elif [[ -r "~/.bash_history"  ||  -r "/root/bash_history" ]]; then
		nl /root/.bash_history > $directory/shell_history.txt
	else
		echo "Either file is not present or not readable" > c_history.txt
	fi
	echo -e "\e[1;36m>>>\e[0m \e[1;35mbash_history.txt file created"
}


#Mounted points
hunting_mnt_point()
{
	echo -e "\e[1;31m[-] Hunting mounting points"
	cat /proc/mounts 2>/dev/null > $directory/mounts.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mmounts.txt file created"
}

#findind open_files
hunting_open_files()
{
	echo -e "\e[1;31m[-] Hunting open_files"
	lsof 2>/dev/null > $directory/open_files.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mopen_files.txt file created"
}




## Phase 4 - Log Analysis
#
#Log entries
hunting_log_entry()
{
	echo -e "\e[1;31m[-] Hunting lastlog entries"
	lastlog 2>/dev/null > $directory/lastlogs.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mlastlogs.txt file created"
}


#auth.log (SSH/TELNET/sudo logs)
hunting_auth_log()
{
	echo -e "\e[1;31m[-] Hunting auth logs"
	cat /var/log/auth.log 2>/dev/null > $directory/auth_logs.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mauth_logs.txt file created"
}


#daemon logs
hunting_daemon()
{
	echo -e "\e[1;31m[-] Hunting deamon logs"
	cat /var/log/daemon.log 2>/dev/null > $directory/daemons_logs_1.txt
	cat /var/log/daemon.log.1 2>/dev/null > $directory/daemons_logs_2.txt

	echo -e "\e[1;36m>>>\e[0m \e[1;35mdaemons_logs.txt_1 file created"
	echo -e "\e[1;36m>>>\e[0m \e[1;35mdaemons_logs.txt_2 file created"
}


#syslogs
hunting_syslogs()
{
	echo -e "\e[1;31m[-] Hunting syslogs"
	cat /var/log/syslog 2>/dev/null > $directory/syslogs.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35msyslogs.txt.txt file created"
}


#wtmp logs
hunting_wtmp_log()
{
	echo -e "\e[1;31m[-] Hunting wtmp logs"
	last -f /var/log/wtmp 2>/dev/null > $directory/wtmp_logs.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mwtmp_logs.txt file created"
}


#btml logs
hunting_btml_log()
{
	echo -e "\e[1;31m[-] Hunting btmp logs"
	last -f /var/log/btmp 2>/dev/null > $directory/btmp_logs.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mbtmp_logs.txt file created"
}




## Phase 5 - Persistence Mechanisms
#
#Services 
hunting_services()
{
	echo -e "\e[1;31m[-] Hunting services"
	service --status-all 2>/dev/null | grep '+' > $directory/services.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mservices.txt file created"
}


#Processes
hunting_processes()
{
	echo -e "\e[1;31m[-] Hunting processes"
	ps aux 2>/dev/null > $directory/process.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mGatherprocess.txt file created"
}



#scheduled tasks and jobs
hunting_schedl_tsk()
{
	echo -e "\e[1;31m[-] Hunting scheduled tasks"
	cat /etc/crontab 2>/dev/null > $directory/cron_tasks.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mcron_tasks.txt file created"
}


#DNS resolves
hunting_ns_rslv()
{
	echo -e "\e[1;31m[-] Hunting dns resolves"
	cat /etc/resolv.conf 2>/dev/null > $directory/dns_resolves.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mdns_resolves.txt file created"
}


#Firewalls Rules
hunting_firew_rule()
{
	echo -e "\e[1;31m[-] Hunting firewall rules"
	iptables -L -n 2>/dev/null > $directory/firewalls_rules.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mfirewalls_rules.txt file created"
}


#Network connections
hunting_net_connect()
{
	echo -e "\e[1;31m[-] Hunting network connections"
	netstat -nap 2>/dev/null > $directory/network_connections.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mnetwork_connections.txt file created"
}

#routing_tables
hunting_routing_tables()
{
	echo -e "\e[1;31m[-] Hunting routing tables"
	ip route list 2>/dev/null > $directory/routing_tables.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mnrouting_tables.txt file created"
}

#open_ports
hunting_open_ports()
{
	echo -e "\e[1;31m[-] Hunting open TCP ports\e[0"
	nmap -T4 -sT -p- localhost > $directory/open_tcp_ports.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mopen_tcp_ports.txt file created"
	echo -e "\e[1;31m[-] Hunting open UDP ports\e[0"
	nmap -T4 -sU -p- localhost > $directory/open_udp_ports.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mopen_udp_ports.txt file created"
}



#Others

#collecting uptime data
hunting_up_time()
{
	echo -e "\e[1;31m[-] Hunting uptime data"
	uptime 2>/dev/null > $directory/uptime_data.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35muptime_data.txt file created"
}

#partitions_and_swap_area
hunting_paritions_and_swaps()
{
	echo -e "\e[1;31m[-] Hunting partitons and swaps"
	echo "Partitons present" > $directory/partitions_and_swaps.txt
	cat /proc/partitions 2>/dev/null >> $directory/partitions_and_swaps.txt
	echo -e "\r\n" >> $directory/partitions_and_swaps.txt 
	echo "Swaps partitions present"
	cat /proc/sawps 2>/dev/null >> $directory/partitions_and_swaps.txt
	echo -e "\e[1;36m>>>\e[0m \e[1;35mpartitions_and_swaps.txt file created"

}


# just created a main function to manage all functions
main()
{
	#Phase-0
	hunting_keys
	
	#Phase-1
	hunting_user_s
	hunting_uid_0
	hunting_tmp_users
	hunting_grp_lst
	hunting_sudo_lst
	hunting_capability

	#Phase-2
	hunting_net_config
	hunting_os_info
	hunting_host_info
	hunting_time_zone
	
	#Phase-3
	hunting_bash_hist
	hunting_mnt_point
	hunting_open_files

	#Phase-4
	hunting_log_entry
	hunting_auth_log
	hunting_daemon
	hunting_syslogs
	hunting_wtmp_log
	hunting_btml_log

	#Phase-5
	hunting_services
	hunting_processes
	hunting_schedl_tsk
	hunting_firew_rule
	hunting_net_connect
	hunting_routing_tables
	hunting_open_ports


	#Others
	hunting_up_time
	hunting_paritions_and_swaps


}

main
echo -e "\r\n\e[1;36m>>>\e[0m Check the $directory folder "


#####											#####
####   source : google.com, secuirty-hive.com    ####
#####											#####
