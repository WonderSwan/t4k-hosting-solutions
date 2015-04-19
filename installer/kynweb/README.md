# KyneticWeb Seedbox Script
#### Current version = 2.05
#### Last stable version = 2.05

This script has been heavily modified from various other resources (most notably Notos). Working on Ubuntu 14.04 as well as Debian 7 OS installs. This script is enhanced to work on KyneticWeb Hosting Solutions server environments to match their specific needs. Running this script outside of KyneticWeb is done at the users own risk. Unless hosted on KyneticWeb - DO NOT contact in regards to support on this script. 

Furthermore, this script is used by KyneticWeb Hosting Solutions staff for installing and setting up Host Servers for KyneticWeb Shared Environments - DO NOT attempt to install this on a non KyneticWeb Hosted Server.

This script has the following features

* A multi-user enviroment, you'll have scripts to add and delete users.
* Linux Quota, to control how much space every user can use in your box.
* Individual User Login Info https://Server-IP/private/SBinfo.txt
* Individual User Https Downloads directory (https://Server-IP/private/Downloads)

## Default Options Enabled in this script (can be changed if needed)
* "Install Webmin?"      YES
* "Install Fail2ban?"    YES
* "Install OpenVPN?"     YES
* "Install SABnzbd?"     YES
* "Install Rapidleech?"  YES
* "Install Deluge?"      YES
* RTorrent version       0.9.4

## Installed software
* ruTorrent 3.4 + official plugins
* rTorrent 0.9.2 or 0.9.3 or 0.9.4(you can choose)
* Deluge 1.3.5 or 0.9.3 (you can choose, downgrade and upgrade at any time)
* libTorrrent 0.13.2 or 0.12.9
* mktorrent
* Fail2ban - to avoid apache and ssh exploits. Fail2ban bans IPs that show malicious signs -- too many password failures, seeking for exploits, etc.
* Apache (SSL)
* OpenVPN - Fixed
* PHP 5 and PHP-FPM (FastCGI to increase performance)
* Linux Quota
* SSH Server (for SSH terminal and sFTP connections)
* vsftpd (Very Secure FTP Deamon) <-- Working 
* IRSSI
* Webmin (use it to manage your users quota)
* sabnzbd: http://sabnzbd.org/
* Rapidleech (http://www.rapidleech.com)

## Main ruTorrent plugins
autotoolscpuload, diskspace, erasedata, extratio, extsearch, feeds, filedrop, filemanager, geoip, history, logoff, mediainfo, mediastream, ratiocolor, rss, scheduler, screenshots, theme, trafic and unpack

## Additional ruTorrent plugins
* Autodl-IRSSI (with an updated list of trackers)
* A modified version of Diskpace to support quota (by Notos)
* Filemanager (modified to handle rar, zip, unzip, tar and bzip)
* Fileupload
* Fileshare Plugin (http://forums.rutorrent.org/index.php?topic=705.0)
* MediaStream (to watch your videos right from your seedbox)
* Logoff
* Theme: Oblivion [BLUE] & Agent 46
* Colorful Ratios: Customized to match Oblivion [BLUE]

## Before installation
You need to have a Fresh "blank" server installation.
After that access your box using a SSH client, like PuTTY.

## Warnings

####If you don't know Linux ENOUGH:

DO NOT attempt to install NGINX as a frontend proxy if you plan to use Transdroid (http://www.transdroid.org/). Doing so will cause the app to either not connect or crash repeatedly

DO NOT use capital letters, all your usernames should be written in lowercase.

DO NOT upgrade anything in your box, ask in the proper support channels before even considering it.

DO NOT try to reconfigure packages using other tutorials - this script (AS IS) is designed to work with what's included. If you feel the script is lacking a particular feature(s), support your Feature Request at https://www.kyneticweb.com/community/feature-request

## How to install
*This script is valid only for the machine hosting shared slots. Do not attempt to install this on a Semi-Dedicated (VPS) or Dedicated slot.

```
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/kynweb/shared.sh

bash shared.sh
```

####You must be logged in as root to run this installation or use sudo on it.

## Commands
After installing you will have access to the following commands to be used directly in terminal
* createSeedboxUser
* deleteSeedboxUser
* changeUserPassword
* installRapidleech
* installOpenVPN
* installSABnzbd
* installWebmin
* installDeluge
* updategitRepository
* removeSendmail
* removeWebmin
* upgradeRTorrent
* installRTorrent
* restartSeedbox

* While executing them, if sudo is needed, they will ask for a password.

## Services
To access services installed on your new server point your browser to the following address:
```
https://<Server IP or Server Name>/private/SBinfo.txt
```
-- These details will also be easily accessed via your Member Dashboard at https://my.kyneticweb.com/

## Download Directory
To access Downloaded data directory on your new server; point your browser to the following address:
```
https://<Server IP or Server Name>/private/Downloads
```

####OpenVPN
To use your VPN you will need a VPN client compatible with [OpenVPN](http://openvpn.net/index.php?option=com_content&id=357), necessary files to configure your connection are in this link in your box:
```
https://<Server IP or Server Name>/rutorrent/CLIENT-NAME.zip` and use it in any OpenVPN client.
```
-- For ease of use, we automatically add this config file for download to your Member Dashboard at https://my.kyneticweb.com/

## Supported and tested servers
* Ubuntu Server 12.10.0 - 64bit (on VM environment)
* Ubuntu Server 12.04.x - 64bit (on VM environment)
* Ubuntu Server 14.04.x - 32bit (on Dedicated environment)
* Ubuntu Server 14.04.x - 64bit (on Dedicated environment)
* Debian 6.0.6 - 32 and 64bit (on Dedicated environment)
* Debian 6.0.6 - 32 and 64bit (on VM environment)
* Debian 7.0 - 32 and 64 bit (on VM & Dedicated environment)

## Quota
Quota is disabled by default in your box. To enable and use it, you'll have to open Webmin, using the address you can find in one of the tables box above this. After you sucessfully logged on Webmin, enable it by clicking

System => Disk and Network Filesystems => /home => Use Quotas? => Select "Only User" => Save

Now you'll have to configure quota for each user, doing

System => Disk Quotas => /home => <username> => Configure the "Soft kilobyte limit" => Update

As soon as you save it, your seedbox will also update the available space to all your users.

## Changelog
You don't worry about that. Any changes made, we'll announce.

## Support

We have support in the following locations:

*Forum  - https://www.kyneticweb.com/community/latest
*IRC    - irc://irc.p2p-network.net:6667 #t4k
*Ticket - https://my.kyneticweb.com/


## License
Copyright (c) 2015 KyneticWeb LLC (https://www.kyneticweb.com/) 

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions: 

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

--> Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
