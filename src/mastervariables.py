## The master variable file 
# file can be edited directly after initial cretion 
#

# the host the webservice is hosted on, FQDN or IP is required.
#webhost = '192.168.102.6' 
# 0.0.0.0 for all interfaces.
webhost = '0.0.0.0' 

# the port the webservice is hosted on, default flask is 5000.
#webport = '5000' 
webport = '5000' 

# the host the MYSQL database is hosted on, FQDN or IP is required.
#host = '192.168.102.6' 
# 127.0.0.1 for local or docker config.
host = '127.0.0.1'
 
# the default port that the MySQL database is running on. 
#port = 3306 
port = 3306 
 
# The user to connect to the MySQL database. 
#user = 'PANuser' 
user = 'PANuser' 
 
# The Password of the user connecting to the MySQL database. 
 #passwd = 'password' 
passwd = 'password' 
 
# The Name of the database the data is to be store in. 
#db = 'PaloAltoHomeUserID'
db = 'PaloAltoHomeUserID' 
 
#   Enter the full name of the interface you want the DHCP data imported from e.g. ethernet1/2, ethernet1/2.2, all 
 #interface = 'ethernet1/2' 
interface = 'all' 
 
# The maintaince clean up on the database, uses 2 variables to deciede what data to clean out of the database. 

# dbCleanDhcpNoDisplay value is the time in months that will be removed from the database is no static display name it set. 
#dbCleanDhcpNoDisplay = 1 
dbCleanDhcpNoDisplay = 1 
 
# dbCleanDhcpDisplay value is the time in months that will be removed from the database where a static display name it set.
#dbCleanDhcpDisplay = 6 
dbCleanDhcpDisplay = 6 
 
# The length of the time to sleep between doing maintance on the database. 
# currently set to every day 86400. 
#dbMainDelay = 86400 
dbMainDelay = 86400 
 
# The lenght of the time to sleep between doing a firewall query and update. 
# default value is 300 seconds every 5 minutes 
#dbUserDelay = 300 
dbUserDelay = 300

# So as to only pull in the most upto date data, set the period of time you want to use to update the latest data. 
# with a leaselife set to 1, it will only pull in data that has made a DHCP request in the last week.  
# LeaseLife = 1
LeaseLife = 1 
 
