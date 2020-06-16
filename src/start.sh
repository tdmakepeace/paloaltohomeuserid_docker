#!/bin/bash
#Created by Toby Makepeace - tmakepeace@paloaltonetworks.com
#

DIR=/app/PaloAltoHomeUserID 
FILE=/app/PaloAltoHomeUserID/variables.py
if [ -d "$DIR" ] 
    then
    if [ ! -f "$FILE" ]
        then
        service mysql start ; mysql < /app/src/db/PaloAltoHomeUserId.sql 
        sleep 5s
        service mysql stop 
        cp /app/src/mastervariables.py /app/PaloAltoHomeUserID/variables.py
        mv /var/lib/mysql/PaloAltoHomeUserID /app/PaloAltoHomeUserID
        ln -s /app/PaloAltoHomeUserID/PaloAltoHomeUserID /var/lib/mysql/PaloAltoHomeUserID
        chmod 777 /app/PaloAltoHomeUserID
        mkdir /app/PaloAltoHomeUserID/backups
        echo '[mysqld]' >> /etc/mysql/my.cnf
        echo 'bind-address = 0.0.0.0' >> /etc/mysql/my.cnf
        echo 'socket = /var/lib/mysql/mysql.sock' >> /etc/mysql/my.cnf
        sleep 5s
        service mysql start
    else
        service mysql start ; mysql < /app/src/db/PaloAltoHomeUserId.sql 
        sleep 5s
        service mysql stop 
        rm -R /var/lib/mysql/PaloAltoHomeUserID
        ln -s /app/PaloAltoHomeUserID/PaloAltoHomeUserID /var/lib/mysql/PaloAltoHomeUserID
        chmod 777 /app/PaloAltoHomeUserID
        echo '[mysqld]' >> /etc/mysql/my.cnf
        echo 'bind-address = 0.0.0.0' >> /etc/mysql/my.cnf
        echo 'socket = /var/lib/mysql/mysql.sock' >> /etc/mysql/my.cnf
        sleep 5s
        service mysql start
    fi
    python3 /app/src/PaloHomeUserID.py > /app/PaloAltoHomeUserID/debug.txt  2>&1
    # python3 /app/src/PaloHomeUserID.py > /dev/null  2>&1
fi





