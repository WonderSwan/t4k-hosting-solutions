#!/bin/bash

  SBFSCURRENTVERSION1=14.06
  OS1=$(lsb_release -si)
  OSV1=$(lsb_release -rs)

function getString
{
  local ISPASSWORD=$1
  local LABEL=$2
  local RETURN=$3
  local DEFAULT=$4
  local NEWVAR1=a
  local NEWVAR2=b
  local YESYES=YESyes
  local NONO=NOno
  local YESNO=$YESYES$NONO

  while [ ! $NEWVAR1 = $NEWVAR2 ] || [ -z "$NEWVAR1" ];
  do
    clear
    echo "#"
    echo "#"
    echo "# KyneticWeb Seedbox Script"
    echo "#"
    echo "#"
    echo

    if [ "$ISPASSWORD" == "YES" ]; then
      read -s -p "$DEFAULT" -p "$LABEL" NEWVAR1
    else
      read -e -i "$DEFAULT" -p "$LABEL" NEWVAR1
    fi
    if [ -z "$NEWVAR1" ]; then
      NEWVAR1=a
      continue
    fi

    if [ ! -z "$DEFAULT" ]; then
      if grep -q "$DEFAULT" <<< "$YESNO"; then
        if grep -q "$NEWVAR1" <<< "$YESNO"; then
          if grep -q "$NEWVAR1" <<< "$YESYES"; then
            NEWVAR1=YES
          else
            NEWVAR1=NO
          fi
        else
          NEWVAR1=a
        fi
      fi
    fi

    if [ "$NEWVAR1" == "$DEFAULT" ]; then
      NEWVAR2=$NEWVAR1
    else
      if [ "$ISPASSWORD" == "YES" ]; then
        echo
        read -s -p "Retype: " NEWVAR2
      else
        read -p "Retype: " NEWVAR2
      fi
      if [ -z "$NEWVAR2" ]; then
        NEWVAR2=b
        continue
      fi
    fi


    if [ ! -z "$DEFAULT" ]; then
      if grep -q "$DEFAULT" <<< "$YESNO"; then
        if grep -q "$NEWVAR2" <<< "$YESNO"; then
          if grep -q "$NEWVAR2" <<< "$YESYES"; then
            NEWVAR2=YES
          else
            NEWVAR2=NO
          fi
        else
          NEWVAR2=a
        fi
      fi
    fi
    echo "---> $NEWVAR2"

  done
  eval $RETURN=\$NEWVAR1
}
# 0.

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root" 1>&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

clear

# 1.

#localhost is ok this rtorrent/rutorrent installation
#HOSTNAME=`ifconfig | sed -n 's/.*inet addr:\([0-9.]\+\)\s.*/\1/p' | grep -v 127 | head -n 1`
HOSTNAME=$HOSTNAME
CHROOTJAIL1=NO

#those passwords will be changed in the next steps
PASSWORD1=a
PASSWORD2=b

getString NO  "You need to create an user for your seedbox: " NEWUSER1
getString YES "Password for user $NEWUSER1: " PASSWORD1
getString NO  "IP address or hostname of your box: " HOSTNAME $HOSTNAME.kyneticweb.com
getString NO  "SSH port: " NEWSSHPORT1 4747
getString NO  "vsftp port (usually 21): " NEWFTPPORT1 5757
getString NO  "OpenVPN port: " OPENVPNPORT1 31195
#getString NO  "Do you want to have some of your users in a chroot jail? " CHROOTJAIL1 YES
getString NO  "Install Webmin? " INSTALLWEBMIN1 YES
getString NO  "Install Fail2ban? " INSTALLFAIL2BAN1 YES
getString NO  "Install OpenVPN? " INSTALLOPENVPN1 YES
getString NO  "Install SABnzbd? " INSTALLSABNZBD1 YES
getString NO  "Install Rapidleech? " INSTALLRAPIDLEECH1 YES
getString NO  "Install Deluge? " INSTALLDELUGE1 YES
getString NO  "Wich RTorrent version would you like to install, '0.9.2' or '0.9.3' or '0.9.4'? " RTORRENT1 0.9.4

if [ "$RTORRENT1" != "0.9.3" ] && [ "$RTORRENT1" != "0.9.2" ] && [ "$RTORRENT1" != "0.9.4" ]; then
  echo "$RTORRENT1 typed is not 0.9.4 or 0.9.3 or 0.9.2!"
  exit 1
fi

if [ "$OSV1" = "14.04" ]; then
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 40976EAF437D05B5
  apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 3B4FE6ACC0B21F32
fi

apt-get --yes update
apt-get --yes install whois sudo makepasswd git nano 

apt-get install unzip

cd /tmp
wget http://www.rarlab.com/rar/rarlinux-x64-5.2.1.tar.gz
tar -zxvf rarlinux-x64-5.2.1.tar.gz
cd rar
./unrar
cp rar unrar /bin

mkdir /etc/kyneticweb-seedbox/

cd /etc/kyneticweb-seedbox/
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/kyneticweb-seedbox.zip
unzip /etc/kyneticweb-seedbox/kyneticweb-seedbox.zip
mkdir -p cd /etc/kyneticweb-seedbox/source
mkdir -p cd /etc/kyneticweb-seedbox/users

if [ ! -f /etc/kyneticweb-seedbox/kyneticweb-seedbox.sh ]; then
  clear
  echo Looks like something is wrong. Not able to gather needed files from the script.
  set -e
  exit 1
fi

# 2.

#show all commands
set -x verbose

# 3.
perl -pi -e "s/Port 22/Port $NEWSSHPORT1/g" /etc/ssh/sshd_config
perl -pi -e "s/PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
perl -pi -e "s/#Protocol 2/Protocol 2/g" /etc/ssh/sshd_config
perl -pi -e "s/X11Forwarding yes/X11Forwarding no/g" /etc/ssh/sshd_config

groupadd sshdusers
groupadd sftponly
echo "" | tee -a /etc/ssh/sshd_config > /dev/null
echo "UseDNS no" | tee -a /etc/ssh/sshd_config > /dev/null
echo "AllowGroups sshdusers root" >> /etc/ssh/sshd_config
mkdir -p /usr/share/terminfo/l/
cp /lib/terminfo/l/linux /usr/share/terminfo/l/
#echo '/usr/lib/openssh/sftp-server' >> /etc/shells
echo "Match Group sftponly" >> /etc/ssh/sshd_config
echo "ChrootDirectory %h" >> /etc/ssh/sshd_config
echo "ForceCommand internal-sftp" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
service ssh restart

# 4.
#remove cdrom from apt so it doesn't stop asking for it
perl -pi -e "s/deb cdrom/#deb cdrom/g" /etc/apt/sources.list
perl -pi.orig -e 's/^(deb .* universe)$/$1 multiverse/' /etc/apt/sources.list
#add non-free sources to Debian Squeeze# those two spaces below are on purpose
perl -pi -e "s/squeeze main/squeeze  main contrib non-free/g" /etc/apt/sources.list
perl -pi -e "s/squeeze-updates main/squeeze-updates  main contrib non-free/g" /etc/apt/sources.list

# 5.
# update and upgrade packages
apt-get --yes install python-software-properties software-properties-common
if [ "$OSV1" = "14.04" ]; then
  apt-add-repository --yes ppa:jon-severinsson/ffmpeg
fi
apt-get --yes update
apt-get --yes upgrade
# 6.
#install all needed packages
apt-get --yes build-dep znc
apt-get --yes install apache2 apache2-utils autoconf build-essential vsftpd vnstat ca-certificates comerr-dev curl cfv quota mktorrent dtach htop irssi libapache2-mod-php5 libcloog-ppl-dev libcppunit-dev libcurl3 libcurl4-openssl-dev libncurses5-dev libterm-readline-gnu-perl libsigc++-2.0-dev libperl-dev openvpn libssl-dev libtool libxml2-dev ncurses-base ncurses-term ntp openssl patch libc-ares-dev pkg-config php5 php5-cli php5-dev php5-curl php5-geoip php5-mcrypt php5-gd php5-xmlrpc pkg-config python-scgi screen ssl-cert subversion texinfo unzip zlib1g-dev expect automake1.9 flex bison debhelper binutils-gold ffmpeg libarchive-zip-perl libnet-ssleay-perl libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl libxml-libxml-perl libjson-rpc-perl libarchive-zip-perl znc tcpdump

if [ "$OSV1" = "14.04"]; then
  apt-get --yes install vsftpd
fi

if [ $? -gt 0 ]; then
  set +x verbose
  echo
  echo
  echo *** ERROR ***
  echo
  echo "Looks like something is wrong with apt-get install, aborting."
  echo
  echo
  echo
  set -e
  exit 1
fi
apt-get --yes install zip

apt-get --yes install rar
if [ $? -gt 0 ]; then
  apt-get --yes install rar-free
fi

apt-get --yes install unrar
if [ $? -gt 0 ]; then
  apt-get --yes install unrar-free
fi

apt-get --yes install dnsutils

if [ "$CHROOTJAIL1" = "YES" ]; then
  cd /etc/kyneticweb-seedbox
  tar xvfz jailkit-2.15.tar.gz -C /etc/kyneticweb-seedbox/source/
  cd source/jailkit-2.15
  ./debian/rules binary
  cd ..
  dpkg -i jailkit_2.15-1_*.deb
fi

# 7. additional packages for Ubuntu
# this is better to be apart from the others
apt-get --yes install php5-fpm
apt-get --yes install php5-xcache

if [ "$OSV1" = "13.10"]; then
  apt-get install php5-json
fi

#Check if its Debian and do a sysvinit by upstart replacement:

if [ "$OS1" = "Debian" ]; then
  echo 'Yes, do as I say!' | apt-get -y --force-yes install upstart
fi

# 8. Generate our lists of ports and RPC and create variables

#permanently adding scripts to PATH to all users and root
echo "PATH=$PATH:/etc/kyneticweb-seedbox:/sbin" | tee -a /etc/profile > /dev/null
echo "export PATH" | tee -a /etc/profile > /dev/null
echo "PATH=$PATH:/etc/kyneticweb-seedbox:/sbin" | tee -a /root/.bashrc > /dev/null
echo "export PATH" | tee -a /root/.bashrc > /dev/null

rm -f /etc/kyneticweb-seedbox/ports.txt
for i in $(seq 51101 51999)
do
  echo "$i" | tee -a /etc/kyneticweb-seedbox/ports.txt > /dev/null
done

rm -f /etc/kyneticweb-seedbox/rpc.txt
for i in $(seq 2 1000)
do
  echo "RPC$i"  | tee -a /etc/kyneticweb-seedbox/rpc.txt > /dev/null
done

# 9.

if [ "$INSTALLWEBMIN1" = "YES" ]; then
  #if webmin isup, download key
  WEBMINDOWN=YES
  ping -c1 -w2 www.webmin.com > /dev/null
  if [ $? = 0 ] ; then
    wget -t 5 http://www.webmin.com/jcameron-key.asc
    apt-key add jcameron-key.asc
    if [ $? = 0 ] ; then
      WEBMINDOWN=NO
    fi
  fi

  if [ "$WEBMINDOWN"="NO" ] ; then
    #add webmin source
    echo "" | tee -a /etc/apt/sources.list > /dev/null
    echo "deb http://download.webmin.com/download/repository sarge contrib" | tee -a /etc/apt/sources.list > /dev/null
    cd /tmp
  fi

  if [ "$WEBMINDOWN" = "NO" ]; then
    apt-get --yes update
    apt-get --yes install webmin
  fi
fi

if [ "$INSTALLFAIL2BAN1" = "YES" ]; then
  apt-get --yes install fail2ban
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.original
  cp /etc/kyneticweb-seedbox/etc.fail2ban.jail.conf.template /etc/fail2ban/jail.conf
  fail2ban-client reload
fi

# 10.
a2enmod ssl
a2enmod auth_digest
a2enmod reqtimeout
a2enmod rewrite
#a2enmod scgi ############### if we cant make python-scgi works
#cd /etc/apache2
#rm apache2.conf
#wget --no-check-certificate https://t4k.org/src-install/server/t4k/apache2.conf
cat /etc/kyneticweb-seedbox/add2apache2.conf >> /etc/apache2/apache2.conf

# 11.
#remove timeout if  there are any
perl -pi -e "s/^Timeout [0-9]*$//g" /etc/apache2/apache2.conf

echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "#seedbox values" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "ServerSignature Off" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "ServerTokens Prod" | tee -a /etc/apache2/apache2.conf > /dev/null
echo "Timeout 30" | tee -a /etc/apache2/apache2.conf > /dev/null
rm ports.conf
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/ports.conf
service apache2 restart
mkdir /etc/apache2/auth.users

echo "$HOSTNAME.kyneticweb.com" > /etc/kyneticweb-seedbox/hostname.info

# 12.
export TEMPHOSTNAME1=tsfsSeedBox
export CERTPASS1=@@$TEMPHOSTNAME1.$NEWUSER1.ServerP7s$
export NEWUSER1
export HOSTNAME

echo "$NEWUSER1" > /etc/kyneticweb-seedbox/mainuser.info
echo "$CERTPASS1" > /etc/kyneticweb-seedbox/certpass.info

bash /etc/kyneticweb-seedbox/createOpenSSLCACertificate

mkdir -p /etc/ssl/private/
openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem -config /etc/kyneticweb-seedbox/ssl/CA/caconfig.cnf

if [ "$OS1" = "Debian" ]; then
  apt-get purge -y --force-yes vsftpd
  echo "deb http://ftp.cyconet.org/debian wheezy-updates main non-free contrib" >> /etc/apt/sources.list.d/wheezy-updates.cyconet.list
  apt-get update
  apt-get install -y --force-yes -t wheezy-updates debian-cyconet-archive-keyring vsftpd
else
  apt-get --yes install libcap-dev libpam0g-dev libwrap0-dev
fi

if [ "$OSV1" = "12.04" ]; then
  dpkg -i /etc/kyneticweb-seedbox/vsftpd_2.3.2-3ubuntu5.1_`uname -m`.deb
fi

perl -pi -e "s/anonymous_enable\=YES/\#anonymous_enable\=YES/g" /etc/vsftpd.conf
perl -pi -e "s/connect_from_port_20\=YES/#connect_from_port_20\=YES/g" /etc/vsftpd.conf
perl -pi -e 's/rsa_private_key_file/#rsa_private_key_file/' /etc/vsftpd.conf
perl -pi -e 's/rsa_cert_file/#rsa_cert_file/' /etc/vsftpd.conf
#perl -pi -e "s/rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem/#rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem/g" /etc/vsftpd.conf
#perl -pi -e "s/rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key/#rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key/g" /etc/vsftpd.conf
echo "listen_port=$NEWFTPPORT1" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "allow_anon_ssl=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "force_local_data_ssl=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "force_local_logins_ssl=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_tlsv1=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_sslv2=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_sslv3=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "require_ssl_reuse=NO" | tee -a /etc/vsftpd.conf >> /dev/null
echo "ssl_ciphers=HIGH" | tee -a /etc/vsftpd.conf >> /dev/null
echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem" | tee -a /etc/vsftpd.conf >> /dev/null
echo "local_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "write_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "local_umask=022" | tee -a /etc/vsftpd.conf >> /dev/null
echo "chroot_local_user=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "chroot_list_file=/etc/vsftpd.chroot_list" | tee -a /etc/vsftpd.conf >> /dev/null
echo "passwd_chroot_enable=YES" | tee -a /etc/vsftpd.conf >> /dev/null
echo "allow_writeable_chroot=YES" | tee -a /etc/vsftpd.conf >> /dev/null
#sed -i '147 d' /etc/vsftpd.conf
#sed -i '149 d' /etc/vsftpd.conf


# 13.
if [ "$OSV1" = "14.04" ]; then
  cp /var/www/html/index.html /var/www/index.html 
  mv /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf.ORI
  rm -f /etc/apache2/sites-available/000-default.conf
  cp /etc/kyneticweb-seedbox/etc.apache2.default.template /etc/apache2/sites-available/000-default.conf
  perl -pi -e "s/http\:\/\/.*\/rutorrent/http\:\/\/$HOSTNAME.kyneticweb.com\/rutorrent/g" /etc/apache2/sites-available/000-default.conf
  perl -pi -e "s/<servername>/$HOSTNAME.kyneticweb.com/g" /etc/apache2/sites-available/000-default.conf
  perl -pi -e "s/<username>/$NEWUSER1/g" /etc/apache2/sites-available/000-default.conf
else
  mv /etc/apache2/sites-available/default /etc/apache2/sites-available/default.ORI
  rm -f /etc/apache2/sites-available/default
  cp /etc/kyneticweb-seedbox/etc.apache2.default.template /etc/apache2/sites-available/default
  perl -pi -e "s/http\:\/\/.*\/rutorrent/http\:\/\/$HOSTNAME.kyneticweb.com\/rutorrent/g" /etc/apache2/sites-available/default
  perl -pi -e "s/<servername>/$HOSTNAME.kyneticweb.com/g" /etc/apache2/sites-available/default
  perl -pi -e "s/<username>/$NEWUSER1/g" /etc/apache2/sites-available/default
fi
#mv /etc/apache2/sites-available/default /etc/apache2/sites-available/default.ORI
#rm -f /etc/apache2/sites-available/default
#cp /etc/kyneticweb-seedbox/etc.apache2.default.template /etc/apache2/sites-available/default
#perl -pi -e "s/http\:\/\/.*\/rutorrent/http\:\/\/$HOSTNAME.kyneticweb.com\/rutorrent/g" /etc/apache2/sites-available/default
#perl -pi -e "s/<servername>/$HOSTNAME/g" /etc/apache2/sites-available/default
#perl -pi -e "s/<username>/$NEWUSER1/g" /etc/apache2/sites-available/default

echo "ServerName $HOSTNAME.kyneticweb.com" | tee -a /etc/apache2/apache2.conf > /dev/null

# 14.
a2ensite default-ssl
#ln -s /etc/apache2/mods-available/scgi.load /etc/apache2/mods-enabled/scgi.load
#service apache2 restart
#apt-get --yes install libxmlrpc-core-c3-dev

#15. Download xmlrpc, rtorrent & libtorrent for 0.9.4
cd
svn co https://svn.code.sf.net/p/xmlrpc-c/code/stable /etc/kyneticweb-seedbox/source/xmlrpc
cd /etc/kyneticweb-seedbox/
wget -c http://libtorrent.rakshasa.no/downloads/rtorrent-0.9.4.tar.gz
wget -c http://libtorrent.rakshasa.no/downloads/libtorrent-0.13.4.tar.gz

#configure & make xmlrpc BASED ON RTORRENT VERSION
if [ "$RTORRENT1" = "0.9.4" ]; then
  cd /etc/kyneticweb-seedbox/source/xmlrpc
  ./configure --prefix=/usr --enable-libxml2-backend --disable-libwww-client --disable-wininet-client --disable-abyss-server --disable-cgi-server
  make -j$(grep -c ^processor /proc/cpuinfo)
  make install
else
  tar xvfz /etc/kyneticweb-seedbox/xmlrpc-c-1.16.42.tgz -C /etc/kyneticweb-seedbox/source/
  cd /etc/kyneticweb-seedbox/source/
  unzip ../xmlrpc-c-1.31.06.zip
  cd xmlrpc-c-1.31.06
  ./configure --prefix=/usr --enable-libxml2-backend --disable-libwww-client --disable-wininet-client --disable-abyss-server --disable-cgi-server
  make -j$(grep -c ^processor /proc/cpuinfo)
  make install
fi

# 16. Let's do a quick HOSTS file insert
cd /etc/
echo "127.0.0.1 10.rarbg.com" >> /etc/hosts
echo "127.0.0.1 11.rarbg.com" >> /etc/hosts
echo "127.0.0.1 2006.sxsw.com" >> /etc/hosts
echo "127.0.0.1 2007.sxsw.com" >> /etc/hosts
echo "127.0.0.1 209.50.48.13" >> /etc/hosts
echo "127.0.0.1 80.190.151.40" >> /etc/hosts
echo "127.0.0.1 9.rarbg.com" >> /etc/hosts
echo "127.0.0.1 94.75.205.147" >> /etc/hosts
echo "127.0.0.1 a.scarywater.net" >> /etc/hosts
echo "127.0.0.1 alanb.yi.org" >> /etc/hosts
echo "127.0.0.1 all4nothin.net" >> /etc/hosts
echo "127.0.0.1 anifans.ath.cx" >> /etc/hosts
echo "127.0.0.1 animex.com" >> /etc/hosts
echo "127.0.0.1 anstracker.no-ip.org" >> /etc/hosts
echo "127.0.0.1 anstracker2.no-ip.org" >> /etc/hosts
echo "127.0.0.1 anvilofsound.com" >> /etc/hosts
echo "127.0.0.1 baka-updates.com" >> /etc/hosts
echo "127.0.0.1 bakabt.com" >> /etc/hosts
echo "127.0.0.1 bangladeshrocks.com" >> /etc/hosts
echo "127.0.0.1 bittorrent.frozen-layer.net" >> /etc/hosts
echo "127.0.0.1 borft.student.utwente.nl" >> /etc/hosts
echo "127.0.0.1 bt-flux.com" >> /etc/hosts
echo "127.0.0.1 bt.base0.net" >> /etc/hosts
echo "127.0.0.1 bt.cartoonpalace.net" >> /etc/hosts
echo "127.0.0.1 bt.eastgame.net" >> /etc/hosts
echo "127.0.0.1 bt.edwardk.info" >> /etc/hosts
echo "127.0.0.1 bt.emuparadise.org" >> /etc/hosts
echo "127.0.0.1 bt.etree.org" >> /etc/hosts
echo "127.0.0.1 bt.fansub-irc.org" >> /etc/hosts
echo "127.0.0.1 bt.ktxp.com" >> /etc/hosts
echo "127.0.0.1 bt.peerseed.com" >> /etc/hosts
echo "127.0.0.1 bt.shinsen-subs.org" >> /etc/hosts
echo "127.0.0.1 bt.speedsubs.org" >> /etc/hosts
echo "127.0.0.1 bt.the9.com" >> /etc/hosts
echo "127.0.0.1 bt.tjgame.enorth.com" >> /etc/hosts
echo "127.0.0.1 bt.ydy.com" >> /etc/hosts
echo "127.0.0.1 btcomic.net" >> /etc/hosts
echo "127.0.0.1 btjunkie.org" >> /etc/hosts
echo "127.0.0.1 bttracker.acc.umu.se" >> /etc/hosts
echo "127.0.0.1 colombo-bt.org" >> /etc/hosts
echo "127.0.0.1 core-tracker.depthstrike.com" >> /etc/hosts
echo "127.0.0.1 cotapers.org" >> /etc/hosts
echo "127.0.0.1 crimsondays.com" >> /etc/hosts
echo "127.0.0.1 csclub.uwaterloo.ca" >> /etc/hosts
echo "127.0.0.1 dak180.dynalias.com" >> /etc/hosts
echo "127.0.0.1 dattebayobrasil.com" >> /etc/hosts
echo "127.0.0.1 deadacated.com" >> /etc/hosts
echo "127.0.0.1 denis.stalker.h3q.com" >> /etc/hosts
echo "127.0.0.1 dimeadozen.org" >> /etc/hosts
echo "127.0.0.1 doctortorrent.com" >> /etc/hosts
echo "127.0.0.1 egelteek.no-ip.org" >> /etc/hosts
echo "127.0.0.1 elsewhere.org" >> /etc/hosts
echo "127.0.0.1 ewheel.democracynow.org" >> /etc/hosts
echo "127.0.0.1 exe64.com" >> /etc/hosts
echo "127.0.0.1 exodus.1337x.org" >> /etc/hosts
echo "127.0.0.1 extratorrent.com" >> /etc/hosts
echo "127.0.0.1 extremebits.se" >> /etc/hosts
echo "127.0.0.1 extremenova.org" >> /etc/hosts
echo "127.0.0.1 eztv.tracker.prq.to" >> /etc/hosts
echo "127.0.0.1 f.scarywater.net" >> /etc/hosts
echo "127.0.0.1 fenopy.com" >> /etc/hosts
echo "127.0.0.1 gdbt.3322.org" >> /etc/hosts
echo "127.0.0.1 h33t.com" >> /etc/hosts
echo "127.0.0.1 handfilms.com" >> /etc/hosts
echo "127.0.0.1 harryy.us" >> /etc/hosts
echo "127.0.0.1 hewgill.com" >> /etc/hosts
echo "127.0.0.1 hexagon.cc" >> /etc/hosts
echo "127.0.0.1 hits4.us" >> /etc/hosts
echo "127.0.0.1 hypaculture.com" >> /etc/hosts
echo "127.0.0.1 indytorrents.org" >> /etc/hosts
echo "127.0.0.1 inferno.demonoid.com" >> /etc/hosts
echo "127.0.0.1 insanity.in" >> /etc/hosts
echo "127.0.0.1 irrenhaus.dyndns.dk" >> /etc/hosts
echo "127.0.0.1 islamictorrents.net" >> /etc/hosts
echo "127.0.0.1 isohunt.com" >> /etc/hosts
echo "127.0.0.1 itpb.tracker.prq.to" >> /etc/hosts
echo "127.0.0.1 jem.d-addicts.com" >> /etc/hosts
echo "127.0.0.1 jem.d-addicts.net" >> /etc/hosts
echo "127.0.0.1 kaa.animeconnection.net" >> /etc/hosts
echo "127.0.0.1 kaoz-subs.de" >> /etc/hosts
echo "127.0.0.1 livetorrents.com" >> /etc/hosts
echo "127.0.0.1 mass-torrent.com" >> /etc/hosts
echo "127.0.0.1 mightynova.com" >> /etc/hosts
echo "127.0.0.1 monova.org" >> /etc/hosts
echo "127.0.0.1 mozilla.isohunt.com" >> /etc/hosts
echo "127.0.0.1 mrtwig.net" >> /etc/hosts
echo "127.0.0.1 music-video-torrents.afz.biz" >> /etc/hosts
echo "127.0.0.1 mw.igg.com" >> /etc/hosts
echo "127.0.0.1 nanikano.no-ip.org" >> /etc/hosts
echo "127.0.0.1 nemesis.1337x.org" >> /etc/hosts
echo "127.0.0.1 newvoyages.us" >> /etc/hosts
echo "127.0.0.1 nova9.org" >> /etc/hosts
echo "127.0.0.1 nrkbeta.no" >> /etc/hosts
echo "127.0.0.1 nxtgn.org" >> /etc/hosts
echo "127.0.0.1 nyaatorrent.info" >> /etc/hosts
echo "127.0.0.1 nyaatorrent.org" >> /etc/hosts
echo "127.0.0.1 nyaatorrents.info" >> /etc/hosts
echo "127.0.0.1 nyaatorrents.org" >> /etc/hosts
echo "127.0.0.1 onebigtorrent.org" >> /etc/hosts
echo "127.0.0.1 os.us.to" >> /etc/hosts
echo "127.0.0.1 ostorr.org" >> /etc/hosts
echo "127.0.0.1 pleasuredome.org" >> /etc/hosts.uk
echo "127.0.0.1 publicbt.com" >> /etc/hosts
echo "127.0.0.1 publiclibrary.metamute.org" >> /etc/hosts
echo "127.0.0.1 quetooter-torrents.kicks-ass.net" >> /etc/hosts
echo "127.0.0.1 radioarchive.cc" >> /etc/hosts
echo "127.0.0.1 rebootedc.no-ip.org" >> /etc/hosts
echo "127.0.0.1 redsphereglobal.com" >> /etc/hosts
echo "127.0.0.1 revision3.com" >> /etc/hosts
echo "127.0.0.1 rocketredrockers.net" >> /etc/hosts
echo "127.0.0.1 saiei.edwardk.info" >> /etc/hosts
echo "127.0.0.1 seedler.org" >> /etc/hosts
echo "127.0.0.1 seedpeer.com" >> /etc/hosts
echo "127.0.0.1 server2.deadacated.com" >> /etc/hosts
echo "127.0.0.1 shadowshq.yi.org" >> /etc/hosts
echo "127.0.0.1 share.dmhy.org" >> /etc/hosts
echo "127.0.0.1 sharereactor.com" >> /etc/hosts
echo "127.0.0.1 sharetv.org" >> /etc/hosts
echo "127.0.0.1 suprnova.org" >> /etc/hosts
echo "127.0.0.1 team-mkv.homedns.org" >> /etc/hosts
echo "127.0.0.1 thepiratebay.org" >> /etc/hosts
echo "127.0.0.1 thewirdsdomain.com" >> /etc/hosts
echo "127.0.0.1 tk.btcomic.net" >> /etc/hosts
echo "127.0.0.1 tk.comican.com" >> /etc/hosts
echo "127.0.0.1 tlm-project.org" >> /etc/hosts
echo "127.0.0.1 tntvillage.org" >> /etc/hosts
echo "127.0.0.1 tog.net" >> /etc/hosts
echo "127.0.0.1 tokyotosho.com" >> /etc/hosts
echo "127.0.0.1 top.igg.com" >> /etc/hosts
echo "127.0.0.1 torrent-download.to" >> /etc/hosts
echo "127.0.0.1 torrent-downloads.to" >> /etc/hosts
echo "127.0.0.1 torrent.ibiblio.org" >> /etc/hosts
echo "127.0.0.1 torrent.ipnm.ru" >> /etc/hosts
echo "127.0.0.1 torrentat.org" >> /etc/hosts
echo "127.0.0.1 torrentchannel.com" >> /etc/hosts
echo "127.0.0.1 torrentraider.com" >> /etc/hosts
echo "127.0.0.1 torrentreactor.net" >> /etc/hosts
echo "127.0.0.1 torrentriot.net" >> /etc/hosts
echo "127.0.0.1 torrentspy.com" >> /etc/hosts
echo "127.0.0.1 torrentzilla.org" >> /etc/hosts
echo "127.0.0.1 torrentzone.net" >> /etc/hosts
echo "127.0.0.1 tracker.anirena.com" >> /etc/hosts
echo "127.0.0.1 tracker.bitreactor.to" >> /etc/hosts
echo "127.0.0.1 tracker.denness.net" >> /etc/hosts
echo "127.0.0.1 tracker.exdesi.com" >> /etc/hosts
echo "127.0.0.1 tracker.frozen-layer.net" >> /etc/hosts
echo "127.0.0.1 tracker.gotwoot.net" >> /etc/hosts
echo "127.0.0.1 tracker.ilibr.org" >> /etc/hosts
echo "127.0.0.1 tracker.ilovetorrents.com" >> /etc/hosts
echo "127.0.0.1 tracker.istole.it" >> /etc/hosts
echo "127.0.0.1 tracker.mariposahd.tv" >> /etc/hosts
echo "127.0.0.1 tracker.minglong.org" >> /etc/hosts
echo "127.0.0.1 tracker.openbittorrent.com" >> /etc/hosts
echo "127.0.0.1 tracker.se" >> /etc/hostseding.it
echo "127.0.0.1 tracker.tahise.info" >> /etc/hosts
echo "127.0.0.1 tracker.tlm-project.org" >> /etc/hosts
echo "127.0.0.1 tracker.to" >> /etc/hosts
echo "127.0.0.1 tracker.token.ro" >> /etc/hosts
echo "127.0.0.1 tracker.torrent.to" >> /etc/hosts
echo "127.0.0.1 tracker.torrent411.com" >> /etc/hosts
echo "127.0.0.1 tracker.torrentbay.to" >> /etc/hosts
echo "127.0.0.1 tracker.torrentbox.com" >> /etc/hosts
echo "127.0.0.1 tracker.torrenty.org" >> /etc/hosts
echo "127.0.0.1 tracker.zaerc.com" >> /etc/hosts
echo "127.0.0.1 tracker1.comicpirates.info" >> /etc/hosts
echo "127.0.0.1 tracker1.finalgear.com" >> /etc/hosts
echo "127.0.0.1 tracker1.torrentum.pl" >> /etc/hosts
echo "127.0.0.1 tracker1.transamrit.net" >> /etc/hosts
echo "127.0.0.1 tracker2.comicpirates.info" >> /etc/hosts
echo "127.0.0.1 tracker2.finalgear.com" >> /etc/hosts
echo "127.0.0.1 tracker2.torrentum.pl" >> /etc/hosts
echo "127.0.0.1 tracker3.comicpirates.info" >> /etc/hosts
echo "127.0.0.1 tracker3.finalgear.com" >> /etc/hosts
echo "127.0.0.1 tracker4.finalgear.com" >> /etc/hosts
echo "127.0.0.1 tracker5.zcultfm.com" >> /etc/hosts
echo "127.0.0.1 trackerb.zcultfm.com" >> /etc/hosts
echo "127.0.0.1 trackers.transamrit.net" >> /etc/hosts
echo "127.0.0.1 transamrit.net" >> /etc/hosts
echo "127.0.0.1 tvrss.net" >> /etc/hosts
echo "127.0.0.1 ushiai.no-ip.org" >> /etc/hosts
echo "127.0.0.1 usotsuki.info" >> /etc/hosts
echo "127.0.0.1 weebl00.nl" >> /etc/hosts
echo "127.0.0.1 weedy.1.vg" >> /etc/hosts
echo "127.0.0.1 wrentype.hoshinet.org" >> /etc/hosts
echo "127.0.0.1 www.ahashare.com" >> /etc/hosts
echo "127.0.0.1 www.allotracker.com" >> /etc/hosts
echo "127.0.0.1 www.bitenova.nl" >> /etc/hosts
echo "127.0.0.1 www.bittorrent.am" >> /etc/hosts
echo "127.0.0.1 www.bittorrentshare.com" >> /etc/hosts
echo "127.0.0.1 www.bt-chat.com" >> /etc/hosts
echo "127.0.0.1 www.btmon.com" >> /etc/hosts
echo "127.0.0.1 www.btscene.com" >> /etc/hosts
echo "127.0.0.1 www.btswarm.org" >> /etc/hosts
echo "127.0.0.1 www.chomskytorrents.org" >> /etc/hosts
echo "127.0.0.1 www.datorrents.com" >> /etc/hosts
echo "127.0.0.1 www.deadfrog.us" >> /etc/hosts
echo "127.0.0.1 www.demonoid.com" >> /etc/hosts
echo "127.0.0.1 inferno.demonoid.ph" >> /etc/hosts
echo "127.0.0.1 www.downloadanime.org" >> /etc/hosts
echo "127.0.0.1 www.elephantsdream.org" >> /etc/hosts
echo "127.0.0.1 www.eztv.it" >> /etc/hosts
echo "127.0.0.1 www.fulldls.com" >> /etc/hosts
echo "127.0.0.1 www.hightorrent.to" >> /etc/hosts
echo "127.0.0.1 www.idealtorrent.com" >> /etc/hosts
echo "127.0.0.1 www.ipodnova.tv" >> /etc/hosts
echo "127.0.0.1 www.livingtorrents.com" >> /etc/hosts
echo "127.0.0.1 www.mabula.net" >> /etc/hosts
echo "127.0.0.1 www.mac-torrents.com" >> /etc/hosts
echo "127.0.0.1 www.matrix8.com" >> /etc/hosts
echo "127.0.0.1 www.mininova.org" >> /etc/hosts
echo "127.0.0.1 www.mvtorrents.com" >> /etc/hosts
echo "127.0.0.1 www.mybittorrent.com" >> /etc/hosts
echo "127.0.0.1 www.mytorrent.pl" >> /etc/hosts
echo "127.0.0.1 www.new2me.net" >> /etc/hosts
echo "127.0.0.1 www.newtorrents.info" >> /etc/hosts
echo "127.0.0.1 www.nitcom.com.au" >> /etc/hosts
echo "127.0.0.1 www.okbt.com" >> /etc/hosts
echo "127.0.0.1 www.p2pbg.com" >> /etc/hosts
echo "127.0.0.1 www.peteteo.com" >> /etc/hosts
echo "127.0.0.1 www.pimptorrent.com" >> /etc/hosts
echo "127.0.0.1 www.point-blank.cc" >> /etc/hosts
echo "127.0.0.1 www.psppirates.com" >> /etc/hosts
echo "127.0.0.1 www.publicdomaintorrents.com" >> /etc/hosts
echo "127.0.0.1 www.raphustle.com" >> /etc/hosts
echo "127.0.0.1 www.seedleech.com" >> /etc/hosts
echo "127.0.0.1 www.sitasingstheblues.com" >> /etc/hosts
echo "127.0.0.1 www.slotorrent.net" >> /etc/hosts
echo "127.0.0.1 www.smaragdtorrent.to" >> /etc/hosts
echo "127.0.0.1 www.solidz.com" >> /etc/hosts
echo "127.0.0.1 www.speedtorrent.to" >> /etc/hosts
echo "127.0.0.1 www.sumotorrent.com" >> /etc/hosts
echo "127.0.0.1 www.thetorrentsite.com" >> /etc/hosts
echo "127.0.0.1 www.todotorrents.com" >> /etc/hosts
echo "127.0.0.1 www.torrent.to" >> /etc/hosts
echo "127.0.0.1 www.torrentbar.com" >> /etc/hosts
echo "127.0.0.1 www.torrentbox.com" >> /etc/hosts
echo "127.0.0.1 www.torrentdownloads.net" >> /etc/hosts
echo "127.0.0.1 www.torrentlocomotive.com" >> /etc/hosts
echo "127.0.0.1 www.torrentportal.com" >> /etc/hosts
echo "127.0.0.1 www.torrentreactor.to" >> /etc/hosts
echo "127.0.0.1 www.torrentum.pl" >> /etc/hosts
echo "127.0.0.1 www.tracker.big-torrent.to" >> /etc/hosts
echo "127.0.0.1 www.tribalmixes.com" >> /etc/hosts
echo "127.0.0.1 www.tvnihon.com" >> /etc/hosts
echo "127.0.0.1 www.web-torrent.com" >> /etc/hosts
echo "127.0.0.1 www.worldnova.org" >> /etc/hosts
echo "127.0.0.1 www.zeoez.com" >> /etc/hosts
echo "127.0.0.1 www.zoektorrents.com" >> /etc/hosts
echo "127.0.0.1 11.rarbg.com" >> /etc/hosts
echo "127.0.0.1 10.rarbg.com" >> /etc/hosts
echo "127.0.0.1 i.bandito.org" >> /etc/hosts
echo "127.0.0.1 tracker.prq.to" >> /etc/hosts
echo "127.0.0.1 tracker.tfile.me" >> /etc/hosts
echo "127.0.0.1 exodus.desync.com" >> /etc/hosts
echo "127.0.0.1 open.demonii.com" >> /etc/hosts
echo "127.0.0.1 tracker.coppersurfer.tk" >> /etc/hosts
echo "127.0.0.1 tracker.leechers-paradise.org" >> /etc/hosts

# 17.
#cd xmlrpc-c-1.16.42 ### old, but stable, version, needs a missing old types.h file
#ln -s /usr/include/curl/curl.h /usr/include/curl/types.h


# 18.
bash /etc/kyneticweb-seedbox/installRTorrent $RTORRENT1

######### Below this /var/www/rutorrent/ has been replaced with /var/www/rutorrent for Ubuntu 14.04

# 19.
cd /var/www/
rm -f -r rutorrent
svn checkout http://rutorrent.googlecode.com/svn/trunk/rutorrent
svn checkout http://rutorrent.googlecode.com/svn/trunk/plugins
rm -r -f rutorrent/plugins
mv plugins rutorrent/

cp /etc/kyneticweb-seedbox/action.php.template /var/www/rutorrent/plugins/diskspace/action.php

groupadd admin

echo "www-data ALL=(root) NOPASSWD: /usr/sbin/repquota" | tee -a /etc/sudoers > /dev/null

cp /etc/kyneticweb-seedbox/favicon.ico /var/www/

# 20. Installing Mediainfo from source
cd /tmp
wget http://downloads.sourceforge.net/mediainfo/MediaInfo_CLI_0.7.56_GNU_FromSource.tar.bz2
tar jxvf MediaInfo_CLI_0.7.56_GNU_FromSource.tar.bz2
cd MediaInfo_CLI_GNU_FromSource/
sh CLI_Compile.sh
cd MediaInfo/Project/GNU/CLI
make install

cd /var/www/rutorrent/js/
git clone https://github.com/gabceb/jquery-browser-plugin.git
mv jquery-browser-plugin/dist/jquery.browser.js .
rm -r -f jquery-browser-plugin
sed -i '31i\<script type=\"text/javascript\" src=\"./js/jquery.browser.js\"></script> ' /var/www/rutorrent/index.html

cd /var/www/rutorrent/plugins
git clone https://github.com/autodl-community/autodl-rutorrent.git autodl-irssi
#cp autodl-irssi/_conf.php autodl-irssi/conf.php
#svn co https://svn.code.sf.net/p/autodl-irssi/code/trunk/rutorrent/autodl-irssi/
cd autodl-irssi


# 21. 
cp /etc/jailkit/jk_init.ini /etc/jailkit/jk_init.ini.original
echo "" | tee -a /etc/jailkit/jk_init.ini >> /dev/null
bash /etc/kyneticweb-seedbox/updatejkinit

# 22. ZNC
#echo "ZNC Configuration"
#echo ""
#znc --makeconf
#/home/antoniocarlos/.znc/configs/znc.conf

# 23. 
# Installing poweroff button on ruTorrent
cd /var/www/rutorrent/plugins/
wget http://rutorrent-logoff.googlecode.com/files/logoff-1.0.tar.gz
tar -zxf logoff-1.0.tar.gz
rm -f logoff-1.0.tar.gz

# 24.
# Installing Filemanager and MediaStream
rm -f -R /var/www/rutorrent/plugins/filemanager
rm -f -R /var/www/rutorrent/plugins/fileupload
rm -f -R /var/www/rutorrent/plugins/mediastream
rm -f -R /var/www/stream

cd /var/www/rutorrent/plugins/
svn co http://svn.rutorrent.org/svn/filemanager/trunk/mediastream

cd /var/www/rutorrent/plugins/
svn co http://svn.rutorrent.org/svn/filemanager/trunk/filemanager

cp /etc/kyneticweb-seedbox/rutorrent.plugins.filemanager.conf.php.template /var/www/rutorrent/plugins/filemanager/conf.php

mkdir -p /var/www/stream/
ln -s /var/www/rutorrent/plugins/mediastream/view.php /var/www/stream/view.php
chown www-data: /var/www/stream
chown www-data: /var/www/stream/view.php

echo "<?php \$streampath = 'http://$HOSTNAME.kyneticweb.com/stream/view.php'; ?>" | tee /var/www/rutorrent/plugins/mediastream/conf.php > /dev/null

# 25. 
# FILEUPLOAD
cd /var/www/rutorrent/plugins/
svn co http://svn.rutorrent.org/svn/filemanager/trunk/fileupload
chmod 775 /var/www/rutorrent/plugins/fileupload/scripts/upload
apt-get --yes -f install

# 25.1
chown -R www-data:www-data /var/www/rutorrent
chmod -R 755 /var/www/rutorrent

#26.
perl -pi -e "s/\\\$topDirectory\, \\\$fm/\\\$homeDirectory\, \\\$topDirectory\, \\\$fm/g" /var/www/rutorrent/plugins/filemanager/flm.class.php
perl -pi -e "s/\\\$this\-\>userdir \= addslash\(\\\$topDirectory\)\;/\\\$this\-\>userdir \= \\\$homeDirectory \? addslash\(\\\$homeDirectory\) \: addslash\(\\\$topDirectory\)\;/g" /var/www/rutorrent/plugins/filemanager/flm.class.php
perl -pi -e "s/\\\$topDirectory/\\\$homeDirectory/g" /var/www/rutorrent/plugins/filemanager/settings.js.php

#27.
unzip /etc/kyneticweb-seedbox/rutorrent-oblivion.zip -d /var/www/rutorrent/plugins/
echo "" | tee -a /var/www/rutorrent/css/style.css > /dev/null
echo "/* for Oblivion */" | tee -a /var/www/rutorrent/css/style.css > /dev/null
echo ".meter-value-start-color { background-color: #E05400 }" | tee -a /var/www/rutorrent/css/style.css > /dev/null
echo ".meter-value-end-color { background-color: #8FBC00 }" | tee -a /var/www/rutorrent/css/style.css > /dev/null
echo "::-webkit-scrollbar {width:12px;height:12px;padding:0px;margin:0px;}" | tee -a /var/www/rutorrent/css/style.css > /dev/null
perl -pi -e "s/\$defaultTheme \= \"\"\;/\$defaultTheme \= \"OblivionBlue\"\;/g" /var/www/rutorrent/plugins/theme/conf.php
git clone https://github.com/InAnimaTe/rutorrent-themes.git /var/www/rutorrent/plugins/theme/themes/Extra
cp -r /var/www/rutorrent/plugins/theme/themes/Extra/OblivionBlue /var/www/rutorrent/plugins/theme/themes/
cp -r /var/www/rutorrent/plugins/theme/themes/Extra/Agent46 /var/www/rutorrent/plugins/theme/themes/
rm -r /var/www/rutorrent/plugins/theme/themes/Extra
#ln -s /etc/kyneticweb-seedbox/seedboxInfo.php.template /var/www/seedboxInfo.php

# 28.
cd /var/www/rutorrent/plugins/
rm -r /var/www/rutorrent/plugins/fileshare
rm -r /var/www/share
svn co http://svn.rutorrent.org/svn/filemanager/trunk/fileshare
mkdir /var/www/share
ln -s /var/www/rutorrent/plugins/fileshare/share.php /var/www/share/share.php
ln -s /var/www/rutorrent/plugins/fileshare/share.php /var/www/share/index.php
chown -R www-data:www-data /var/www/share
cp /etc/kyneticweb-seedbox/rutorrent.plugins.fileshare.conf.php.template /var/www/rutorrent/plugins/fileshare/conf.php
perl -pi -e "s/<servername>/$HOSTNAME/g" /var/www/rutorrent/plugins/fileshare/conf.php

# 29.
bash /etc/kyneticweb-seedbox/updateExecutables

# 30.
echo $SBFSCURRENTVERSION1 > /etc/kyneticweb-seedbox/version.info
echo $NEWFTPPORT1 > /etc/kyneticweb-seedbox/ftp.info
echo $NEWSSHPORT1 > /etc/kyneticweb-seedbox/ssh.info
echo $OPENVPNPORT1 > /etc/kyneticweb-seedbox/openvpn.info

# 31.
wget -P /usr/share/ca-certificates/ --no-check-certificate https://certs.godaddy.com/repository/gd_intermediate.crt https://certs.godaddy.com/repository/gd_cross_intermediate.crt
update-ca-certificates
c_rehash

# 32. 
# Add some CrossTransfer to VSFTP
cd /etc
echo "pasv_promiscuous=YES" >> /etc/vsftpd.conf
echo "port_promiscuous=YES" >> /etc/vsftpd.conf

# 33.
if [ "$INSTALLOPENVPN1" = "YES" ]; then
  bash /etc/kyneticweb-seedbox/installOpenVPN
fi

if [ "$INSTALLSABNZBD1" = "YES" ]; then
  bash /etc/kyneticweb-seedbox/installSABnzbd
fi

if [ "$INSTALLRAPIDLEECH1" = "YES" ]; then
  bash /etc/kyneticweb-seedbox/installRapidleech
fi

if [ "$INSTALLDELUGE1" = "YES" ]; then
  bash /etc/kyneticweb-seedbox/installDeluge
fi

# 34. First user will not be jailed
# createSeedboxUser <username> <password> <user jailed?> <ssh access?> <Chroot User>
bash /etc/kyneticweb-seedbox/createSeedboxUser $NEWUSER1 $PASSWORD1 YES YES YES NO

# 35. Cosmetic corrections & installing plowshare
cd /var/www/rutorrent/plugins/autodl-irssi
rm AutodlFilesDownloader.js
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/AutodlFilesDownloader.js
cd /var/www/rutorrent/js
rm webui.js
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/webui.js
cd ..
chown -R www-data:www-data /var/www/rutorrent
chmod -R 755 /var/www/rutorrent
cd 
git clone https://github.com/mcrapet/plowshare.git
cd ~/plowshare
make install
cd
rm -r plowshare

if [ "$OS1" = "Debian" ]; then
  apt-get install -y --force-yes -t wheezy-updates debian-cyconet-archive-keyring vsftpd
fi

# 36. Add those colorful ratios
cd /var/www/rutorrent/plugins/
mkdir /var/www/rutorrent/plugins/ratiocolor/
cd /var/www/rutorrent/plugins/ratiocolor/
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/ratiocolor.zip
unzip /var/www/rutorrent/plugins/ratiocolor/ratiocolor.zip
rm ratiocolor.zip
cd

# 37. ruTorrent Streaming capabilities
cd /var/www/rutorrent/plugins/
mkdir /var/www/rutorrent/plugins/stream/
cd /var/www/rutorrent/plugins/stream/
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/stream.zip
unzip /var/www/rutorrent/plugins/stream/stream.zip
rm stream.zip
cd

# 38. For shared we remove cpuload plugin, it's not needed and totally T4K :P
cd /var/www/rutorrent/plugins
rm -frv cpuload
wget https://bintray.com/artifact/download/hectortheone/base/pool/main/b/base/hectortheone.rar
unrar x hectortheone.rar
rm hectortheone.rar
cd quotaspace
chmod 755 run.sh
cd ..
chown -R www-data:www-data /var/www/rutorrent
set +x verbose
clear

# 39. Add an updated Mediainfo plugin
cd /var/www/rutorrent/plugins/mediainfo/
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/shared/mediainfo.zip
unzip /var/www/rutorrent/plugins/mediainfo/mediainfo.zip
rm mediainfo.zip

# 40. Quick PHP adjustments
cd /etc/php5/apache2/
sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 8M/g' php.ini

# 41. Remove Sendmail - it's a resource hog
apt-get purge sendmail*

echo ""
echo "<<< T4K Seedbox Script >>>"
echo "Script Modified by b0ts37en ---> https://t4k.org/"
echo ""
echo "Looks like everything is set."
echo ""
echo "Remember that your SSH port is now ======> $NEWSSHPORT1"
echo ""
echo "Your Login info can also be found at https://$HOSTNAME.kyneticweb.com/private/SBinfo.txt"
echo "Download Data Directory is located at https://$HOSTNAME.kyneticweb.com/private "
echo ""
echo "System will reboot now. Do not close the window or reconnect until all of the info has been noted for adding to the users dashboard. Remember not to forget especially the new port number: $NEWSSHPORT1"
echo ""
echo ""
#cat /etc/kyneticweb-seedbox/users/$NEWUSER1.info
# END.

 reboot

##################### LAST LINE ###########