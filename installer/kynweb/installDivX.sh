#!/bin/bash

cd /tmp
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/kynweb/divx.zip
unzip divx.zip
cd divx
bash install.sh
echo | q
echo | yes
apt-get install vlc