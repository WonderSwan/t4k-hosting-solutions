#!/bin/bash

cd /tmp/
wget --no-check-certificate https://raw.githubusercontent.com/b0ts37en/t4k-hosting-solutions/master/installer/kynweb/divx611-20060201-gcc4.0.1.zip
unzip divx611-20060201-gcc4.0.1.zip.zip
cd divx611-20060201-gcc4.0.1.zip/
bash install.sh
echo | q
echo | yes
apt-get install vlc