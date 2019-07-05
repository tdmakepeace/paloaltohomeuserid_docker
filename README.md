# PaloAltoHomeUserID_Docker
Palo Alto Networks - Tool for managing DHCP User ID and EDL.

# To deploy
The following line will deploy the container. <br> <br>
sudo docker run -d -p \<Listining Port\>:5000 -v \<local folder\>:/app/PaloAltoHomeUserID tdmakepeace/paloaltohomeuserid<br><br>

The options to edit are the \<Listining Port\> example would beport 5000 and the \<local folder\> <br>
The local folder is used to maintain all the files from the container that you want to be persistent. 
Things like the database folder, and the variables file.<br><br>

Example: <br>
sudo docker run -d -p 5000:5000 -v /home/pan:/app/PaloAltoHomeUserID tdmakepeace/paloaltohomeuserid

<br><br>
**docker volume** <br>
sudo docker volume create panhuid_data  <br>
sudo docker run -d -p 5000:5000 -v panhuid_data:/app/PaloAltoHomeUserID tdmakepeace/paloaltohomeuserid <br>
<br>

# Useful docker commands.

**get contianer id's**  - sudo docker ps<br>
**stop the container** - sudo docker stop \<container id\><br>
**start the container** - sudo docker start \<container id\><br>
**set container to survice a reboot** - sudo docker update --restart=always \<container id\><br>


# Disclaimer
This software is provided without support, warranty, or guarantee. Use at your own risk.
