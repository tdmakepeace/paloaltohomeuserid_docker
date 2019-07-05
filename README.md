# PaloAltoHomeUserID_Docker
Palo Alto Networks - Tool for managing DHCP User ID and EDL.

# To deploy
The following line will deploye the container. <br> <br>
sudo docker run -d -p \<Listining Port\>:5000 -v \<local folder\>:/app/PaloAltoHomeUserID tdmakepeace/paloaltohomeuserid

The options to edit are the \<Listining Port\> example would beport 5000 and the \<local folder\> <br>
The local folder is used to maintain all the files from the container that you want to be persistent. 
Things like the database folder, and the variables file.

Example: <br>
sudo docker run -d -p 5000:5000 -v /home/pan:/app/PaloAltoHomeUserID tdmakepeace/paloaltohomeuserid



# Disclaimer
This software is provided without support, warranty, or guarantee. Use at your own risk.
