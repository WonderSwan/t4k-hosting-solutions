#localhost is ok this rtorrent/rutorrent installation
IPADDRESS1=`ifconfig | sed -n 's/.*inet addr:\([0-9.]\+\)\s.*/\1/p' | grep -v 127 | head -n 1`
HOSTNAME=`hostname`

getString NO  "IP address of your box: " IPADDRESS1 $IPADDRESS1
getString NO  "Hostname of your box: " HOSTNAME $HOSTNAME.kyneticweb.com

echo "$IPADDRESS1	$HOSTNAME.kyneticweb.com $HOSTNAME" > /etc/hosts