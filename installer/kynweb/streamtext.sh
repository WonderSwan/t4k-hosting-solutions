#!/bin/bash

# 42. Stream Auto-Login
perl -pi -e "s/\\\$auth \= \'\';/\\\$auth \= \'\\\$NEWUSER1\:\\\$PASSWORD1\';/g" /var/www/rutorrent/plugins/config.php