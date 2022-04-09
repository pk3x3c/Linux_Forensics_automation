# Linux_Forensics_Automation
-------------------

The following script fetches the important files that are necessary for linux forensics phase. The script stores the result in seperate files, which aids in easy management during the forensics phase. The script can be used along with linpeash.sh which will make the process more easier.

## Language used
-------------------
Bash

## How to use :-
-------------------
1. Clone the repository in your desired location.
2. Seek the linux_forensics.sh script.
3. chmod +x linux_forensics.sh
4. ./linux_forensics.sh -d /tmp/forensics

## Help Menu
Usage: ./linux_forensics.sh [-d] <directory_name> [-h]

-d : directory name
-h : help menu
[] : Non mandatory argument
<> : argument value for switch

default direcotory = linux_forensics

Example: ./linux_forensics -d /tmp/forensics

