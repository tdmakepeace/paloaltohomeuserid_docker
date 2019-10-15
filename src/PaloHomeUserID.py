## TODO :
## need to clean up some of the display 
## force and reset are not currently needed.
## 


#    if 'loggedin' in session:
#    return redirect(url_for('login'))
#
#>>> password1 = generate_password_hash('paloalto')
#>>> print password1


import threading
import time
import urllib
import urllib.request
import urllib.parse
import sys
import ssl
import xml.etree.ElementTree as ET
import pymysql
import os
from datetime import datetime ,timedelta
from flask import Flask, render_template , flash, redirect, url_for, session, request , logging ,send_from_directory
from flask import send_file
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, IntegerField,PasswordField, BooleanField,  validators 
# from wtforms.validators import InputRequired
from wtforms.fields.html5 import EmailField
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import MySQLdb.cursors
import re

sys.path.append("/app/PaloAltoHomeUserID") 

try:
    from variables import *
except ImportError:
    from mastervariables import *
    sys.exit(0)

try:
    from device import *
except ImportError:
    from newdevice import *
    
    

app = Flask(__name__)
# config mysql #
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SECRET_KEY'] = 'PaloAltoNetworksUserIDRegister'
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=5)


app.config['MYSQL_HOST'] = host
app.config['MYSQL_USER'] = user
app.config['MYSQL_PASSWORD'] = passwd
app.config['MYSQL_DB'] = db
app.config['MYSQL_PORT'] = port
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql =MySQL(app)


#####---------------------------------------------
def dbmain():
# TODO:    A new section to act as a DB maintainence.
# still to be worked on.
# but will currently delete any records that have not updated in the last month.
# or 6 months if they have a display name. 
# All Static assigned Leases on the firewall will never be deleted by the script
# even if removed from the firewall.
    while True:
        time.sleep(dbMainDelay)

        conn = pymysql.connect(host=host, port=port, user=user, passwd=passwd, db=db)
        state = ("delete from Group_User_Map where DHCP_UID in (select UID from DHCP where  LeaseTime <> '1970-01-01 00:00:01'  and  LeaseTime < (NOW() - INTERVAL %s month)  and DisplayName is null);") %(dbCleanDhcpNoDisplay)

        cur = conn.cursor()
        cur.execute(state)
        cur.close()

        state1 = ("Delete from DHCP where LeaseTime <> '1970-01-01 00:00:01'  and  LeaseTime < (NOW() - INTERVAL %s month)  and DisplayName is null;") %(dbCleanDhcpNoDisplay)

        cur1 = conn.cursor()
        cur1.execute(state1)
        cur1.close()

        state2 = ("delete from Group_User_Map where DHCP_UID in (select UID from DHCP where  LeaseTime <> '1970-01-01 00:00:01'  and  LeaseTime < (NOW() - INTERVAL %s month)  and DisplayName is not null);")  %(dbCleanDhcpDisplay)


        cur2 = conn.cursor()
        cur2.execute(state2)
        cur2.close()

        state3 = ("Delete from DHCP where LeaseTime <> '1970-01-01 00:00:01'  and  LeaseTime < (NOW() - INTERVAL %s month)  and DisplayName is not null;")  %(dbCleanDhcpDisplay)


        cur3 = conn.cursor()
        cur3.execute(state)
        cur3.close()

        conn.commit() 
        conn.close()  

    
def collectdhcp(): 
# This is the section of code that goes to the firewall and retrieves the DHCP
# data sessions based on variables in the variables.py file.
# the data it collects from the firewall is write into the SQL database.

    myssl = ssl.create_default_context();
    myssl.check_hostname=False
    myssl.verify_mode=ssl.CERT_NONE
    conn = pymysql.connect(host=host, port=port, user=user, passwd=passwd, db=db)
    
    typeop = "op"
# the XML path to retireve the data from the DHCP server on the firewall.
    cmd = "<show><dhcp><server><lease><interface>%s</interface></lease></server></dhcp></show>" %(interface)
    cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
    req = urllib.request.Request(cmd1, data=None )
    try:
        resp_str = urllib.request.urlopen(req ,context=myssl)
    except urllib.error.URLError as e:
        now = datetime.now()
        logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
        f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
        f.write(str(logdate))
        f.write(' collectdhcp ')
#        f.write(e.reason + '\n')
    else:
        result = resp_str.read()

    try :
        result
    except NameError:
        result = None

# The following lines extract the IP, MAC-Address and Hostname from the firewall
# result and convert it to variable to be used as part of the SQL insert.

    tree = ET.fromstring(result)
    for child in tree.iter('entry'):
        ip = child.find('ip').text
        
        mac =  child.find('mac')
        if mac is None:
            mac = 'blank'
        else:
            mac =  child.find('mac').text
             
        hostname =  child.find('hostname')
        if hostname is None:
            hostname = 'blank'
        else:
            hostname =  child.find('hostname').text

        
#        name = child.get('name')
        leasetime = child.find('leasetime')
        if leasetime is None:
#            leasetime = 'Jan 1 00:00:01 1970'
#            leasetime = datetime.strptime(leasetime, '%b %d %H:%M:%S %Y').
            leasetime = datetime.now()
            
        else:
            leasetime =  child.find('leasetime').text
            leaselen = len(leasetime)
            leasetime = leasetime[:leaselen-1]
            leasetime = datetime.strptime(leasetime, '%a %b %d %H:%M:%S %Y')
        
# the insert statement for the data, the update on duplicate key is used 
# to make sure we maintain the MAC address link relationship when the IP address
# changes for a device.
# the check has been added to deal wiht the same mac address on mulit VLAN
# and the XML not being orderable.
        state = ("Select 'Y' from Dual where 'Y' = (Select  'Y'  from DHCP where (MacAddr = '%s' and Leasetime <  '%s' )) or 'Y' = (select 'Y' from dual where '%s' not in (select MacAddr  from DHCP)); ") %(mac,  leasetime, mac)

        cur = conn.cursor()
        check = cur.execute(state)
        if check > 0:
            state1 = ("insert into DHCP (IPaddr, MacAddr, Hostname, Leasetime , Source) values (INET_ATON('%s'),'%s','%s','%s' , 'FW' ) ON DUPLICATE KEY UPDATE IPaddr=INET_ATON('%s'), Hostname='%s' , Leasetime='%s' ;") %(ip, mac,  hostname, leasetime, ip,  hostname, leasetime)
            cur1 = conn.cursor()
            cur1.execute(state1)
            cur1.close()
        else:
            state1 = ("")

        cur.close()     
        conn.commit()    

# to be able to add the mac-vendor, we retrieve all records from the database 
# that do not have a vendor linked to them, and have been populated from the 
# FW. 
# We then take each entry and query the api.macvendors.com database, and write 
# it back to the table.
# this is a one of process.

    state2 = ("SELECT MacAddr FROM DHCP where `source`= 'FW' and Vendor is null;")

    cur2 = conn.cursor()
    cur2.execute(state2)
    results2 = cur2.fetchall()

    for row in results2: 
        mac = row[0]
#            print (mac)

        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE
        url = "https://api.macvendors.com/%s" %(mac)
        req = urllib.request.Request(url, data=None )
        try :

# due to a issue with the certain characters returned from the api.macvendor.com
# we use a replace to remove the special character
# if the update fails, run the collect process manually, and look at the python
# error, normally it will show you the character that is the issue. and you can 
# use a replace option to convert it to a space or blank.
# as per line :  result3 = result3.replace('\uff0c', '')

            now = datetime.now()
            logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
            try:
                resp_str = urllib.request.urlopen(req ,context=myssl)
            except urllib.error.URLError as e:
                f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
                f.write(str(logdate))
                f.write(' MacLookup ')
                f.write(e.reason + '\n')
            else:
                result3 = resp_str.read().decode('utf-8')
                result3 = result3.replace('\uff0c', '')

# Test: to display the info back to the screen before the update, uncomment the 
# following line. with the double ##
##            print(mac ,' = ' , result3 )            
        except urllib.error.HTTPError as error:
            f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
            f.write(str(logdate))
            f.write(' MacLookup ')
            f.write(error.code + '\n')
            result3 = 'Unknown'
        cur3 = conn.cursor()

# the update statement to right the result back to the DHCP table.
# using double quotes rather than single quotes as single quote are part of some
# of the string returns, hence the difference in structure of the statemnet line

        state3 = ("UPDATE DHCP set vendor = \"%s\" where MacAddr = \"%s\";") %(result3, mac)
        cur3.execute(state3)
        cur3.close()
        conn.commit()    
# due to a limitation, on the macvendor api, we are only allowed to query the DB
# once a second, hence the sleep statement.
# also limited to 5000 queries a day. 
# if you are hitting that, then we need to consider what you are doing with this
# tool. We can address with either a commercial licnece for the macvendor.com db
# or do some local cache structure. I can not see this being needed.
        time.sleep(1)

        cur2.close()
# import, all the statements run above is this section are no commited until the
# following line, if you want to do a lot of testing without updateing the 
# database, you can temporay comment out the commit. (not recommended)
        conn.commit()         
        
#  
## the folllowing section just retrieves the latest status information of the 
## firewall, the Model, SN, and the software revisions. 
## writing this to the DB, but could easily be to a temp file if needed. 
#
#    typeop = "op"
#    cmd = "<show><system><info></info></system></show>" 
#    cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
#    req = urllib.request.Request(cmd1, data=None )
#    resp_str = urllib.request.urlopen(req ,context=myssl)
#    result4 = resp_str.read()
##    print (result4)
#    tree = ET.fromstring(result4)
#    for child in tree.iter('system'):
#        hostname = child.find('hostname').text
#        uptime =  child.find('uptime').text
#        model =  child.find('model').text
#        serial =  child.find('serial').text
#        swversion =  child.find('sw-version').text
#        appversion =  child.find('app-version').text
#        avversion =  child.find('av-version').text
#        appversion =  child.find('app-version').text
#        threatversion =  child.find('threat-version').text
#        wildfireversion =  child.find('wildfire-version').text
#        appdate =  child.find('app-release-date').text
#        avdate =  child.find('av-release-date').text
#        threatdate =  child.find('threat-release-date').text
#        wildfiredate =  child.find('wildfire-release-date').text
#
#
## writes the data to the FWdata table as a update, so we only maintain a single
## record, would be easy to add a history, but changing this to a insert. 
## if we changed this to a insert, so as to maintain history, we would add a 
## foreign key on the combination of the  (swversion,appversion,avversion,
## appversion,wildfireversion)
#
##  TODO: add insert statement as a example and the SQL to add Foreign Key.
#
#        state4 = ("UPDATE FWdata SET `hostname` = \"%s\",  `uptime` = \"%s\", `model` = \"%s\", `serial` = \"%s\", `swversion` = \"%s\", `appversion` = \"%s\", `avversion` =\"%s\", `threatversion` = \"%s\", `wildfireversion` = \"%s\", `appdate` = \"%s\",    `avdate` = \"%s\",    `threatdate` = \"%s\",    `wildfiredate` = \"%s\"   ORDER BY UID DESC LIMIT 1;" ) %(hostname,  uptime, model, serial, swversion,  appversion, avversion, threatversion, wildfireversion, appdate, avdate ,threatdate, wildfiredate)
#
#        cur4 = conn.cursor()
#        cur4.execute(state4)
#        cur4.close()
#        conn.commit()  
        
    conn.close() 
    
    
def createxmlfile(): 
# This is the section of code created the xml file that is used to populate 
# the user-id database.
# the file XML structure is created as per Palo Alto Networks API documentation.
# the file structure adds both user and group entires.
# the default life of the user-id entries is controlled under the firewall.
# Device/User Identification/user-Mapping/Palo Alto Networks User-ID Agent setup
# change the user Identification Timeout to a value you determine to be acceptable
# it should be set to at least double the script time interval.
# Default timeout on user-ID is 45 Minutes.
## CLI command to set it to one hour.
## set user-id-collector setting ip-user-mapping-timeout 60


#<uid-message>
#	<type>update</type>
#	<payload>
#		<login>
#			<entry ip="192.168.1.1" name="test" />
#		</login>
#		<groups>
#			<entry name="admin">
#				<members>
#					<entry name="test" />
#				</members>
#			</entry>
#		</groups>
#	</payload>
#</uid-message>



    root = ET.Element("uid-message")
    ET.SubElement(root, "type").text = "update"
    payload = ET.SubElement(root, "payload")

    login = ET.SubElement(payload, "login")    
 
    conn = pymysql.connect(host=host, port=port, user=user, passwd=passwd, db=db)

# Query is made to only pull back a single entry for each IP-address based upon 
# the most recent allocation. 
# it is possible that the DB contains multiple entries for the same IP, as DHCP 
# will reuse the IP-addresses. but the MAC addresses as hostnames are unique.

    state = ("SELECT IFNULL(DisplayName, Hostname) AS name, INET_NTOA(IPaddr) AS ip FROM DHCP WHERE ((Hostname <> 'blank' OR DisplayName IS NOT NULL)   AND LeaseTime IN (SELECT MAX(LeaseTime) FROM DHCP GROUP BY IPaddr DESC) AND ( LeaseTime > (NOW() - INTERVAL %s WEEK) and Source = 'fw')  ) or Source = 'form' ORDER BY IPaddr;")  %(LeaseLife)
    cur = conn.cursor()
    cur.execute(state)
    results = cur.fetchall()
    for row in results: 
        Name = row[0]
        IP = row[1]
        ET.SubElement(login, "entry", name=Name , ip=IP )
#        print(Name , IP)
       
    cur.close()
    groups = ET.SubElement(payload, "groups")  

# query the groups that need to be imported.     
    state1 = ("select GName from GROUPS;")
    cur1 = conn.cursor()
    cur1.execute(state1)
    results1 = cur1.fetchall()
    for row in results1: 
        Group = row[0]
# query the users IDs linked to the group and then add them to the XML structure
# as members of the group
# 
        group = ET.SubElement(groups, "entry", name=Group )
        state2 = ("SELECT distinct(ifnull(DHCP.DisplayName,DHCP.Hostname)) FROM DHCP where UID in (select Group_User_Map.DHCP_UID from Group_User_Map where Group_User_Map.Group_UID = (select UID from GROUPS where GName= '%s'))") %(Group)
        cur2 = conn.cursor()
        cur2.execute(state2)
        results2 = cur2.fetchall()
        members = ET.SubElement(group , "members") 
        for row in results2: 
            Member = row[0]
            ET.SubElement(members, "entry", name=Member )
        cur2.close()
    cur1.close()
    conn.close() 
    
    
    tree = ET.ElementTree(root)
    tree.write("userID.xml")

    
def sendapi(): 
    # Section of the code, that takes the XML file already created, and sends it 
# to the firewall to be imported as the userID.
# by default the import life on any record is 45 minutes.
# see above section for how to edit the value.
# we do not delete user-id entries, we either let them expire
# or we over write them with a new entry.
    
    myssl = ssl.create_default_context();
    myssl.check_hostname=False
    myssl.verify_mode=ssl.CERT_NONE
    


    fileN = open('userID.xml', 'r')
    # xml convert the file to a single URL #
    xml = urllib.parse.quote_plus(fileN.read())
    typeop = "user-id"
    cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,xml)

    req = urllib.request.Request(cmd1, data=None )
    now = datetime.now()
    logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
    try:
        resp_str = urllib.request.urlopen(req ,context=myssl)
    except urllib.error.URLError as e:
        f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
        f.write(str(logdate))
        f.write(' sendapi ')
        f.write(e.reason + '\n')
    else:
        result = resp_str.read()


#    resp_str = urllib.request.urlopen(req ,context=myssl)
#    result = resp_str.read()

## DEBUG: uncomment so as to be able    
##    print (result)

def dbuser():
    while True:
        if 'base' in globals():
            collectdhcp()
            createxmlfile()
            sendapi()
            time.sleep(dbUserDelay)
        else :
            time.sleep(dbUserDelay)
        
        
def initBackgroundProcs():
    thread1 = threading.Thread(target=dbuser)
    thread2 = threading.Thread(target=dbmain)
    thread1.start()
    thread2.start()

    




###
# The web structure is defined from this point onwards.
#
###

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico')
                               
                               
                               
                               
### All the pages that require an account login to manage ###
@app.route('/login/', methods=['GET', 'POST'])
def login():
    # Output message if something goes wrong...
    msg = ''
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        # Create variables for easy access
        username = request.form['username']
        upassword = request.form['password']
        # Check if account exists using MySQL
        cur = mysql.connection.cursor()
#        cur.execute('SELECT * FROM AdminAccounts WHERE username = %s AND password = %s', (username, upassword))
        cur.execute("SELECT * FROM AdminAccounts WHERE username = %s;", [username])
        # Fetch one record and return result
        account = cur.fetchone()
        # If account exists in accounts table in out database
#        if account:
        if check_password_hash( account['password'], upassword) == True:
            # Create session data, we can access this data in other routes
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session.permanent = True
            # Redirect to home page
            return redirect(url_for('register'))
        else:
            # Account doesnt exist or username/password incorrect
            msg = 'Incorrect username/password!'
    # Show the login form with message (if any)
    
    
    return render_template('loginindex.html', msg='')
    
@app.route('/login/logout')
def logout():
    # Remove session data, this will log the user out
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    # Redirect to login page
    return redirect(url_for('login'))

@app.route('/changepwd', methods=['GET', 'POST'])
def changepwd():
    if 'loggedin' in session:
        form = ChangePwd(request.form)
        if request.method == 'POST' and form.validate():
            currentpwd = form.currentpwd.data
            newpwd = form.newpwd.data
            checkpwd = form.checkpwd.data
            if newpwd == checkpwd :
                cur = mysql.connection.cursor()
                cur.execute("SELECT password FROM AdminAccounts WHERE id = %s;", [session['id']])
                account = cur.fetchone()
                if check_password_hash( account['password'], currentpwd) == True:
                    updatepwd = generate_password_hash(newpwd)
                    cur2 = mysql.connection.cursor()
                    cur2.execute(" update AdminAccounts set password = %s where id =%s;", (updatepwd ,[session['id']]))
                    ## commit and close ##
                    mysql.connection.commit()
                    cur2.close()
                    session.pop('loggedin', None)
                    session.pop('id', None)
                    session.pop('username', None)
                    return render_template('changepwd.html', form=form )

                else:
                    msg = 'Existing Passwords do not match'
                    flash (msg, 'warning')
                    return redirect(url_for('changepwd'))
                cur.close()
            else:
                msg = 'New Passwords do not match'
                flash (msg, 'warning')
                return redirect(url_for('changepwd'))
                
        return render_template('changepwd.html', form=form )

    return redirect(url_for('login'))




    
@app.route("/")
def index():
    # Check if user is loggedin
    if 'loggedin' in session:
        if 'first' in globals():
            if first == 'yes':
                 return redirect(url_for('setup'))
            else:
                 return render_template('index.html')
        else :
            return render_template('index.html')
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
    



@app.route("/register")
def register():
    # Check if user is loggedin
    if 'loggedin' in session:
        return render_template('register.html')
        
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))
    
@app.route("/backup")
def backup():
    if 'loggedin' in session:
        BASE_DIR = '/app/PaloAltoHomeUserID/backups/'

    # Return 404 if path doesn't exist
        if not os.path.exists(BASE_DIR):
            return abort(404)

    # Check if path is a file and serve
        if os.path.isfile(BASE_DIR):
            return send_file(BASE_DIR)
        
    # Show directory contents
        files = os.listdir(BASE_DIR)
        return render_template('backup.html', files=files)
    return redirect(url_for('login'))


@app.route("/backupdownload/<filename>" , methods=['GET', 'POST'])
def backupdownload(filename):
    if 'loggedin' in session:
        filedownload = "/app/PaloAltoHomeUserID/backups/%s" %(filename)
        
        return send_file(filedownload,  as_attachment=True)
    return redirect(url_for('login'))

@app.route("/backupdelete/<filename>" , methods=['GET', 'POST'])
def backupdelete(filename):
    if 'loggedin' in session:
        filedelete = "/app/PaloAltoHomeUserID/backups/%s" %(filename)
        os.system('rm %s' %(filedelete))
        
        return redirect(url_for('backup'))
    return redirect(url_for('login'))




@app.route("/backuplocal")
def backuplocal():
#    job = int(request.args.get('job', None))
##    complete = int(request.args.get('complete', None))
#
#    if job == 0:
    myssl = ssl.create_default_context();
    myssl.check_hostname=False
    myssl.verify_mode=ssl.CERT_NONE	
    
    typeop = "export"
    cmd = "configuration"
    cmd1 = "%s?key=%s&type=%s&category=%s" %(base,key,typeop,cmd)
    req = urllib.request.Request(cmd1, data=None )
    try:
        resp_str = urllib.request.urlopen(req ,context=myssl)
    except urllib.error.URLError as e:
        f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
        now = datetime.now()
        logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
        f.write(str(logdate))
        f.write(' backup failed ')
        #f.write(e.reason + '\n')
        flash ('backup Failed', 'error')
        return redirect(url_for('backup'))
    else:
        result = resp_str.read()
        
        if result:
            now = datetime.now()
            datebackup = ('backup'+(str(now.year))+(str(now.month))+(str(now.day))+(str(now.hour))+(str(now.minute))+(str(now.second)))
#            f = open('/app/PaloAltoHomeUserID/%s.xml' %(str(datebackup)), 'w')
#            f.write(result+ '\n')
#            f.close()
            tree = ET.XML(result)
            with open('/app/PaloAltoHomeUserID/backups/%s.xml' %(str(datebackup)), 'wb') as f:
                f.write(ET.tostring(tree))
            flash ('Configuration downloaded', 'success')
            
        else:
            msg = 'failed registation'
            return render_template('backup.html', msg=msg, form=form )
        resp_str.close
        
    typeop = "export"
    cmd = "device-state"
    cmd1 = "%s?key=%s&type=%s&category=%s" %(base,key,typeop,cmd)
    req = urllib.request.Request(cmd1, data=None )
    try:
        resp_str = urllib.request.urlopen(req ,context=myssl)
    except urllib.error.URLError as e:
        f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
        now = datetime.now()
        logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
        f.write(str(logdate))
        f.write(' State failed ')
        #f.write(e.reason + '\n')
        flash ('State Failed', 'error')
        return redirect(url_for('backup'))
    else:
        result = resp_str.read()
        
        if result:
            now = datetime.now()
            datebackup = ('state'+(str(now.year))+(str(now.month))+(str(now.day))+(str(now.hour))+(str(now.minute))+(str(now.second)))
            with open('/app/PaloAltoHomeUserID/backups/%s.tgz' %(str(datebackup)), 'wb') as f:
                f.write(result)
            flash ('State downloaded', 'success')
            
        else:
            msg = 'State registation'
            return render_template('backup.html', msg=msg, form=form )
        resp_str.close
        
        
        

        
        
    return redirect(url_for('backup'))



#        return redirect(url_for('backuprun' , job =(job) ))
#
#	  complete = 0
#	  if job is not None:
#	    while complete != 1:
#	    	myssl = ssl.create_default_context();
#	    	myssl.check_hostname=False
#	    	myssl.verify_mode=ssl.CERT_NONE
#	    	typeop = "op"
#	    	job = str(job)
#	    	cmd = "<show><jobs><id>" + job + "</id></jobs></show>"
#	    	cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
#	    	req = urllib.request.Request(cmd1, data=None )
#	    	resp_str = urllib.request.urlopen(req ,context=myssl)
#	    	response = resp_str.read()
#	    	if response:
#   				tree = ET.fromstring(response)
#   				if tree.find('./result/job/status').text == "ACT":
#   					status = tree.find('./result/job/progress').text + "% complete"
#   					print ('{0}\r'.format(status)),
#   					return render_template('upgradedownload.html',  status=status ,version = version , job = job)
#
#   				elif tree.find('./result/job/status').text == "FIN":
#   					complete = 1
#   					job = 0
#
#	    return redirect(url_for('upgradeinstall' ,  version=(version), job =(job) ))


                
@app.route("/upgrade")
def upgrade():
    if 'loggedin' in session:
        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE
    
        typeop = "op"
        cmd = "<show><system><info></info></system></show>" 
        cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
        req = urllib.request.Request(cmd1, data=None )
        try:
            resp_str = urllib.request.urlopen(req ,context=myssl)
        except urllib.error.URLError as e:
            f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
            now = datetime.now()
            logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
            f.write(logdate)
            f.write(' upgrade ')
            f.write(e.reason + '\n')
        else:
            result4 = resp_str.read()
    #    print (result4)
            tree = ET.fromstring(result4)
            for child in tree.iter('system'):
                swversion =  child.find('sw-version').text
    
        
        cmd = "<request><system><software><check></check></software></system></request>"
        cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
        req = urllib.request.Request(cmd1, data=None )
        try:
            resp_str = urllib.request.urlopen(req ,context=myssl)
        except urllib.error.URLError as e:
            f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
            now = datetime.now()
            logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
            f.write(logdate)
            f.write(' upgrade ')
            f.write(e.reason + '\n')
        else:
            result5 = resp_str.read()
    #    print (result5)
            tree = ET.fromstring(result5)
            for child in tree.iter('result'):
                latestversion = child.find('./sw-updates/versions/entry/version').text
        
        if 'latestversion':
            return render_template('upgrade.html',  swversion=swversion , latestversion=latestversion )
        else:
            return redirect(url_for('system'))
    return redirect(url_for('login'))
        
@app.route("/upgradestart/")
def upgradestart():
    if 'loggedin' in session:
        version = (request.args.get('version', None))
        job = int(request.args.get('job', None))

        if job == 0:
            myssl = ssl.create_default_context();
            myssl.check_hostname=False
            myssl.verify_mode=ssl.CERT_NONE	

            typeop = "op"
            cmd = "<request><system><software><download><version>" + version + "</version></download></software></system></request>"
            cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
            req = urllib.request.Request(cmd1, data=None )
            resp_str = urllib.request.urlopen(req ,context=myssl)
            response = resp_str.read()
            print (response)
            if response:
                tree = ET.fromstring(response)
                job = tree.find('./result/job').text
                print ("Downloading version " + version + " in job " + job)	
                flash ('Downloading version', 'success')
                return redirect(url_for('upgradestart' ,  version=(version), job =(job) ))

        complete = 0
        if job is not None:
            while complete != 1:
                myssl = ssl.create_default_context();
                myssl.check_hostname=False
                myssl.verify_mode=ssl.CERT_NONE
                typeop = "op"
                job = str(job)
                cmd = "<show><jobs><id>" + job + "</id></jobs></show>"
                cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
                req = urllib.request.Request(cmd1, data=None )
                resp_str = urllib.request.urlopen(req ,context=myssl)
                response = resp_str.read()
            if response:
                tree = ET.fromstring(response)
                if tree.find('./result/job/status').text == "ACT":
                    status = tree.find('./result/job/progress').text + "% complete"
                    print ('{0}\r'.format(status)),
                    return render_template('upgradedownload.html',  status=status ,version = version , job = job)
    
                elif tree.find('./result/job/status').text == "FIN":
                    complete = 1
                    job = 0
    
        return redirect(url_for('upgradeinstall' ,  version=(version), job =(job) ))    
    return redirect(url_for('login'))


@app.route("/upgradeinstall/")
def upgradeinstall():
    if 'loggedin' in session:        
#    return redirect(url_for('login'))
        version = (request.args.get('version', None))
        job = int(request.args.get('job', None))
#	  complete = int(request.args.get('complete', None))

        if job == 0:
            myssl = ssl.create_default_context();
            myssl.check_hostname=False
            myssl.verify_mode=ssl.CERT_NONE	

            typeop = "op"
            cmd = "<request><system><software><install><version>" + version + "</version></install></software></system></request>"
            cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
            req = urllib.request.Request(cmd1, data=None )
            resp_str = urllib.request.urlopen(req ,context=myssl)
            response = resp_str.read()
            print (response)
            if response:
                tree = ET.fromstring(response)
                job = tree.find('./result/job').text
                print ("Downloading version " + version + " in job " + job)	
                flash ('Installing version', 'success')
                return redirect(url_for('upgradeinstall' ,  version=(version), job =(job) ))
      
        complete = 0
        if job is not None:
            while complete != 1:
                myssl = ssl.create_default_context();
                myssl.check_hostname=False
                myssl.verify_mode=ssl.CERT_NONE
                typeop = "op"
                job = str(job)
                cmd = "<show><jobs><id>" + job + "</id></jobs></show>"
                cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
                req = urllib.request.Request(cmd1, data=None )
                resp_str = urllib.request.urlopen(req ,context=myssl)
                response = resp_str.read()
                if response:
                    tree = ET.fromstring(response)
                    if tree.find('./result/job/status').text == "ACT":
                        status = tree.find('./result/job/progress').text + "% complete"
                        print ('{0}\r'.format(status)),
                        return render_template('upgradeinstall.html',  status=status ,version = version , job = job)

        elif tree.find('./result/job/status').text == "FIN":
            complete = 1
            job = 0

        return redirect(url_for('upgradeconfirm', reboot=0))

    return redirect(url_for('login'))

@app.route("/upgradeconfirm/")
def upgradeconfirm():
    if 'loggedin' in session:
        reboot = int(request.args.get('reboot', None))
        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE
          
        if reboot == 0:
            return render_template('upgradeconfirm.html')
        else:
      
          typeop = "op"
          cmd = "<request><restart><system></system></restart></request>"
          cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
          req = urllib.request.Request(cmd1, data=None )
          resp_str = urllib.request.urlopen(req ,context=myssl)
          response = resp_str.read()
          if response:
              tree = ET.fromstring(response)
              if tree.get('status') == "success":
                  print ("Rebooting the firewall")
                  flash ('Rebooting the firewall', 'success')
                  return redirect(url_for('system'))
      
        return redirect(url_for('system'))
    return redirect(url_for('login'))

@app.route("/reboot/")
def reboot():
    if 'loggedin' in session:
        reboot = int(request.args.get('reboot', None))
        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE

        if reboot == 0:
            return render_template('reboot.html')
        else:

            typeop = "op"
            cmd = "<request><restart><system></system></restart></request>"
            cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
            req = urllib.request.Request(cmd1, data=None )
            resp_str = urllib.request.urlopen(req ,context=myssl)
            response = resp_str.read()
            if response:
                tree = ET.fromstring(response)
                if tree.get('status') == "success":
                    print ("Rebooting the firewall")
                    flash ('Rebooting the firewall', 'success')
                    return redirect(url_for('system'))

        return redirect(url_for('system'))
    return redirect(url_for('login'))


@app.route("/setup", methods=['GET', 'POST'])
def setup():
    if 'loggedin' in session:
        form = SetUp(request.form)
        if request.method == 'POST' and form.validate():
            ipman = form.ipman.data
            adminuser = form.adminuser.data
            adminpwd = form.adminpwd.data
            return redirect(url_for('setupfw' ,  ipman=(ipman), adminuser=(adminuser), adminpwd=(adminpwd)))


        return render_template('setup.html', form=form )
    return redirect(url_for('login'))


@app.route("/setupfw", methods=['GET', 'POST'])
def setupfw():
    if 'loggedin' in session:
        ipman = (request.args.get('ipman', None))
        adminuser = (request.args.get('adminuser', None))
        adminpwd = (request.args.get('adminpwd', None))
    
        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE
    
    
        url = "https://%s/api/?type=keygen&user=%s&password=%s" %(ipman,adminuser,adminpwd)
    #    print (url)
        req = urllib.request.Request(url, data=None )
        try:
            resp_str = urllib.request.urlopen(req ,context=myssl)
        except urllib.error.URLError as e:
            f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
            now = datetime.now()
            logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
            f.write(str(logdate))
            f.write(' register failed ')
            #f.write(e.reason + '\n')
            flash ('Registration Failed', 'error')
            return redirect(url_for('setup'))
        else:
            result = resp_str.read()
            print (result)
            if result:
                tree = ET.fromstring(result)
                for child in tree.iter('key'):
                    apikey = child.text
                    key1 = "# The API key to be used to connect to the firewall. \n# key = 'LUFRPT10VGJKTEV6a0R4L1JXd0ZmbmNvdUEwa25wMlU9d0N5d292d2FXNXBBeEFBUW5pV2xoZz09' \nkey = '%s' \n\n" %(apikey)
                    base1 = "# the Base url the script connects to. it is the https://<fw ip address/api/ \n#base ='https://192.168.55.10/api/' \nbase ='https://%s/api/'\n\n" %(ipman)
                    resp_str.close
                    f = open('/app/PaloAltoHomeUserID/device.py', 'w')
                    f.write(key1)
                    f.write(base1)
                    f.close()
                    global key
                    global base
                    global first
                    first = 'no'
                    key = '%s' %(apikey)
                    base = 'https://%s/api/' %(ipman)
                    return redirect(url_for('register'))
                    flash ('keygen', 'success')
            else:
                msg = 'failed registation'
                return render_template('setup.html', msg=msg, form=form )
            
        return redirect(url_for('setup'))
    return redirect(url_for('login'))

@app.route("/system")
def system():
    if 'loggedin' in session:
        myssl = ssl.create_default_context();
        myssl.check_hostname=False
        myssl.verify_mode=ssl.CERT_NONE

        typeop = "op"
        cmd = "<show><system><info></info></system></show>" 
        cmd1 = "%s?key=%s&type=%s&cmd=%s" %(base,key,typeop,cmd)
        req = urllib.request.Request(cmd1, data=None )
        try:
            resp_str = urllib.request.urlopen(req ,context=myssl)
        except urllib.error.URLError as e:
            f = open("/app/PaloAltoHomeUserID/errorlog.txt", "a")
            now = datetime.now()
            logdate = (now.year, now.month, now.day, now.hour, now.minute, now.second)
            f.write(str(logdate))
            f.write(' system ')
            f.write(e.reason + '\n')
            return redirect(url_for('setup'))
        else:
            result4 = resp_str.read()
#    print (result4)
            tree = ET.fromstring(result4)
            for child in tree.iter('system'):
                hostname = child.find('hostname').text
                uptime =  child.find('uptime').text
                model =  child.find('model').text
                serial =  child.find('serial').text
                swversion =  child.find('sw-version').text
                appversion =  child.find('app-version').text
                avversion =  child.find('av-version').text
                appversion =  child.find('app-version').text
                threatversion =  child.find('threat-version').text
                wildfireversion =  child.find('wildfire-version').text
                appdate =  child.find('app-release-date').text
                avdate =  child.find('av-release-date').text
                threatdate =  child.find('threat-release-date').text
                wildfiredate =  child.find('wildfire-release-date').text
    

        return render_template('system.html',  hostname=hostname , uptime=uptime, model=model, serial=serial,
                swversion=swversion, appversion=appversion, avversion=avversion,
                threatversion =  threatversion,  wildfireversion =  wildfireversion, appdate =  appdate, avdate =  avdate,
                threatdate =  threatdate, wildfiredate=wildfiredate)
            
    return redirect(url_for('login'))



@app.route("/fwhostlist")
def fwhostlist():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        state = ("SELECT IFNULL(DisplayName, Hostname) AS name, INET_NTOA(IPaddr) AS ip FROM DHCP WHERE (Hostname <> 'blank' OR DisplayName IS NOT NULL)         AND LeaseTime IN (SELECT            MAX(LeaseTime)        FROM            DHCP        GROUP BY IPaddr DESC) AND ( LeaseTime > (NOW() - INTERVAL %s WEEK) and Source = 'fw')  or Source = 'form' or LeaseTime = '1970-01-01 00:00:01' ORDER BY IPaddr;")  %(LeaseLife)
        result = cur.execute(state)
        results = cur.fetchall()
        
        if result > 0:
            return render_template('fwhostlist.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('fwhostlist.html', msg=msg)

        cur.close()
        return render_template('fwhostlist.html')
    return redirect(url_for('login'))

@app.route("/fwgrouplist")
def fwgrouplist():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        state = ("SELECT DISTINCT GROUPS.GName as `group`, (ifnull(DHCP.DisplayName,DHCP.Hostname)) as `device` FROM GROUPS INNER JOIN Group_User_Map ON GROUPS.UID = Group_User_Map.Group_UID INNER JOIN DHCP ON Group_User_Map.DHCP_UID = DHCP.UID ORDER BY GROUPS.GName ASC;")
        result = cur.execute(state)
        results = cur.fetchall()
        
        if result > 0:
            return render_template('fwgrouplist.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('fwgrouplist.html', msg=msg)
    
    
        cur.close()
            
        return render_template('fwgrouplist.html')
    return redirect(url_for('login'))

@app.route("/forcehost")
def forcehost():
    if 'loggedin' in session:
        createxmlfile()
        sendapi()
    
        cur = mysql.connection.cursor()
        state = ("SELECT IFNULL(DisplayName, Hostname) AS name, INET_NTOA(IPaddr) AS ip FROM DHCP WHERE (Hostname <> 'blank' OR DisplayName IS NOT NULL)         AND LeaseTime IN (SELECT            MAX(LeaseTime)        FROM            DHCP        GROUP BY IPaddr DESC) AND ( LeaseTime > (NOW() - INTERVAL %s WEEK) and Source = 'fw')  or Source = 'form' or LeaseTime = '1970-01-01 00:00:01' ORDER BY IPaddr;")  %(LeaseLife)
        result = cur.execute(state)
        results = cur.fetchall()
        
        if result > 0:
            return render_template('fwhostlist.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('fwhostlist.html', msg=msg)
    
    
        cur.close()
            
        return render_template('fwhostlist.html')
    return redirect(url_for('login'))
    


@app.route("/forcegroup")
def forcegroup():
    if 'loggedin' in session:
        createxmlfile()
        sendapi()
    
        cur = mysql.connection.cursor()
        state = ("SELECT DISTINCT GROUPS.GName as `group`, (ifnull(DHCP.DisplayName,DHCP.Hostname)) as `device` FROM GROUPS INNER JOIN Group_User_Map ON GROUPS.UID = Group_User_Map.Group_UID INNER JOIN DHCP ON Group_User_Map.DHCP_UID = DHCP.UID ORDER BY GROUPS.GName ASC;")
        result = cur.execute(state)
        results = cur.fetchall()
        
        if result > 0:
            return render_template('fwgrouplist.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('fwgrouplist.html', msg=msg)
        cur.close()
        return render_template('fwgrouplist.html')
    return redirect(url_for('login'))


@app.route("/deviceid")
def deviceid():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, inet_ntoa(`IPaddr`) as IP ,`Hostname`,`DisplayName`,`LeaseTime`,`Source`FROM `DHCP` where Source = 'form' order by IPaddr asc;" )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('deviceid.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('deviceid.html', msg=msg)
    
        cur.close()
            
        return render_template('deviceid.html')
    return redirect(url_for('login'))



@app.route("/manageusers")
def manageusers():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute( "select id, username , email, updatedate from AdminAccounts order by id asc;" )
        results = cur.fetchall()
        if result > 0:
            return render_template('manageusers.html', results=results)
        else:
            msg = 'No Users registered'
            return render_template('manageusers.html', msg=msg)
        cur.close()
        
        return render_template('deviceid.html')
    
    return redirect(url_for('login'))


@app.route("/group")
def group():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, GName,  `Desc` FROM GROUPS  where UID >=1 order by UID asc;" )
        results = cur.fetchall()
        if result > 0:
            return render_template('group.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('group.html', msg=msg)
        cur.close()
        return render_template('group.html')
    return redirect(url_for('login'))


@app.route("/edl")
def edl():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("select `UID`, `EDLName`, `Desc` from EDL order by UID asc;" )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('edl.html', results=results)
        else:
            msg = 'No EDL lists created'
            return render_template('edl.html', msg=msg)
    
    
        cur.close()
            
        return render_template('group.html')
    return redirect(url_for('login'))

@app.route("/edltest")
def edltest():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("select `UID`, `EDLName`, `Desc` from EDL order by UID asc;" )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('edltest.html', results=results)
        else:
            msg = 'No EDL lists created'
            return render_template('edltest.html', msg=msg)
    
    
        cur.close()
            
        return render_template('group.html')
    return redirect(url_for('login'))

@app.route("/addedl", methods=['GET', 'POST'])
def addedl():
    if 'loggedin' in session:
        form = AddEDL(request.form)
        if request.method == 'POST' and form.validate():
            displayname = form.displayname.data
            descript = form.descript.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" INSERT INTO EDL (EDLName, `Desc` )VALUES ( %s, %s) ", (displayname , descript ) )
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            flash ('EDL Added', 'success')
            return redirect(url_for('edl'))
        return render_template('addedl.html', form=form)
    return redirect(url_for('login'))
    
@app.route("/dhcpid")
def dhcpid():
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, inet_ntoa(`IPaddr`) as IP,`Hostname`,`DisplayName`,`LeaseTime`,`Source`FROM `DHCP` where Source = 'FW' order by IPaddr asc;" )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('dhcpid.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('dhcpid.html', msg=msg)
    
    
        cur.close()
            
        return render_template('dhcpid.html')
    return redirect(url_for('login'))


@app.route("/adddevice", methods=['GET', 'POST'])
def adddevice():
    if 'loggedin' in session:
        form = AddDeviceForm(request.form)
        if request.method == 'POST' and form.validate():
            hostname = form.hostname.data
            ipaddr = form.ipaddr.data
            mac = "st%s" %(hostname)
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" INSERT INTO `DHCP` (`MacAddr`, `IPaddr`,`DisplayName`,`LeaseTime`,`Source`)VALUES ( %s,INET_ATON(%s),%s,sysdate(),'form') ", (mac , ipaddr, hostname) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device Added', 'success')
            return redirect(url_for('deviceid'))
            
    #        return render_template('adduser.html')
        return render_template('adddevice.html', form=form)
    return redirect(url_for('login'))

@app.route("/addadmin", methods=['GET', 'POST'])
def addadmin():
    if 'loggedin' in session:
        form = AddAdminForm(request.form)
        if request.method == 'POST' and form.validate():
            username = form.username.data
            useremail = form.useremail.data
            userpassword = form.userpassword.data
            passworduser = generate_password_hash(userpassword)
            
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" INSERT INTO `AdminAccounts` (`username`, `email`,`password`,`updatedate`)VALUES ( %s,%s,%s, now()) ", (username , useremail, passworduser) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('User Added', 'success')
            return redirect(url_for('manageusers'))
            
    #        return render_template('adduser.html')
        return render_template('addadmin.html', form=form)
    return redirect(url_for('login'))
    

@app.route("/addedlobject/<string:id>/", methods=['GET','POST'])
def addedlobject(id):
    if 'loggedin' in session:
        form = AddEDLobject(request.form)
        if request.method == 'POST' and form.validate():
            edlobj = form.edlobj.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" INSERT INTO `EDLData` (`EDL_UID`, `EDL_Data`) VALUES ( %s, %s) ;", (id , edlobj) )
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            flash ('Device Added', 'success')
            return redirect(url_for('edl'))
    #        return render_template('adduser.html')
        return render_template('addedlobject.html', form=form)
    return redirect(url_for('login'))

@app.route("/addgroup", methods=['GET', 'POST'])
def addgroup():
    if 'loggedin' in session:
        form = AddGroup(request.form)
        if request.method == 'POST' and form.validate():
            displayname = form.displayname.data
            descript = form.descript.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" INSERT INTO GROUPS (GName, `Desc` )VALUES ( %s, %s) ", (displayname , descript ) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Group Added', 'success')
            return redirect(url_for('group'))
        return render_template('addgroup.html', form=form)
    return redirect(url_for('login'))


@app.route("/members/<string:id>/", methods=['GET','POST'])
def members(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT Group_User_Map.Group_UID as GUID, Group_User_Map.UID as UID, IFNULL(DHCP.DisplayName, DHCP.Hostname) as Hostname, INET_NTOA(DHCP.IPaddr) as IPaddr from DHCP INNER JOIN Group_User_Map ON DHCP.UID=Group_User_Map.DHCP_UID where Group_User_Map.Group_UID = %s order by Group_User_Map.UID asc ;" , [id] )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('members.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('members.html', msg=msg)
    
        cur.close()
            
        return render_template('members.html')
    return redirect(url_for('login'))


@app.route("/edlobjects/<string:id>/", methods=['GET','POST'])
def edlobjects(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT UID , EDL_Data FROM EDLData WHERE EDL_UID = %s order by UID asc;" , [id] )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('edlobjects.html', results=results)
        else:
            msg = 'No devices registered'
            return render_template('edlobjects.html', msg=msg)
    
        cur.close()
            
        return render_template('edlobjects.html')
    return redirect(url_for('login'))

@app.route("/addmembers/<string:id>/", methods=['GET','POST'])
def addmembers(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("Select %s as GUID , UID, IFNULL(DisplayName, Hostname) as name, INET_NTOA(IPaddr) as ip from DHCP where (Hostname <> 'blank' or DisplayName is not null) and UID not in (Select DHCP_UID from Group_User_Map where Group_UID = %s)order by IPaddr asc ;" , (id, id) )
        results = cur.fetchall()
        
        if result > 0:
            return render_template('addmembers.html', results=results )
        else:
            msg = 'No devices registered'
            return render_template('addmembers.html', msg=msg)
    
        cur.close()
            
        return render_template('addmembers.html')
    return redirect(url_for('login'))


@app.route("/addmember/", methods=['GET','POST'])
def addmember():
    if 'loggedin' in session:
        GUID = int(request.args.get('GUID', None))
        DHCPUID = int(request.args.get('DHCPUID', None))
        cur = mysql.connection.cursor()
        result = cur.execute(" Select '%s' as GUID , UID ,IFNULL(DisplayName, Hostname) as DisplayName, INET_NTOA(IPaddr) as ip FROM `DHCP` where  UID = '%s';" , ( GUID , DHCPUID ) )
        results = cur.fetchone()
    
      
        form = addmemberForm(request.form)
        form.displayname.data = results['DisplayName']
        form.ip.data = results['ip']
        form.GUID.data = results['GUID']
        form.DUID.data = results['UID']
        
           
        if request.method == 'POST' and form.validate():
            GUID = form.GUID.data 
            DHCPIP = form.DUID.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" Insert into Group_User_Map (Group_UID, DHCP_UID) Values (%s,%s)"  , (GUID , DHCPIP))
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device Added', 'success')
            return redirect(url_for('addmembers', id=int(GUID)))
        cur.close()
        return render_template('addmember.html', form=form )
    return redirect(url_for('login'))

@app.route("/editdevice/<string:id>/", methods=['GET','POST'])
def editdevice(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, inet_ntoa(`IPaddr`) as IP,`Hostname`,`DisplayName` ,`LeaseTime`,`Source`FROM `DHCP` where  UID = %s;" , [id] )
        results = cur.fetchone()
        
        form = EditDeviceForm(request.form)
        form.hostname.data = results['DisplayName']
        form.ipaddr.data = results['IP']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            hostname = request.form['hostname']
            ipaddr = request.form['ipaddr']
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" update `DHCP` set `DisplayName` = %s , `IPaddr` = INET_ATON(%s), LeaseTime = sysdate() where UID = %s;", (hostname , ipaddr,  uid) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device edited', 'success')
            return redirect(url_for('deviceid'))
        cur.close()
        return render_template('editdevice.html', form=form )
    return redirect(url_for('login'))


@app.route("/deletedevice/<string:id>/", methods=['GET','POST'])
def deletedevice(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, inet_ntoa(`IPaddr`) as IP,`Hostname`,`DisplayName` ,`LeaseTime`,`Source`FROM `DHCP` where  UID = %s;" , [id] )
        results = cur.fetchone()

        form = DeleteDeviceForm(request.form)
        form.hostname.data = results['DisplayName']
        form.ipaddr.data = results['IP']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            hostname = request.form['hostname']
            ipaddr = request.form['ipaddr']
            uid = form.uid.data
            uid = int(uid)
            ## cursor ##
            cur2 = mysql.connection.cursor()
            cur2.execute(" Delete from `DHCP` where UID = %s" ,  [id] )
            cur2.execute("delete from Group_User_Map where DHCP_UID = %s " ,  [id])
            ## commit and close ##
            mysql.connection.commit()
            cur2.close()
            
            flash ('Device Deleted', 'success')
            return redirect(url_for('deviceid'))
        cur.close()
        return render_template('deletedevice.html', form=form )
    return redirect(url_for('login'))

@app.route("/deleteadmin/<string:id>/", methods=['GET','POST'])
def deleteadmin(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT id, `username`,`email` FROM `AdminAccounts` where id = %s;" , [id] )
        results = cur.fetchone()
        result1 = cur.execute(" SELECT count(id) as count FROM `AdminAccounts` ;" )
        results1 = cur.fetchone()
        

        form = DeleteAdminForm(request.form)
        form.username.data = results['username']
        form.useremail.data = results['email']
        countid = results1['count']
        
        if request.method == 'POST' and form.validate():
#            username = request.form['username']
#            useremail = request.form['email']
            countid = int(countid)
            ## cursor ##
            if countid == 1 :
                flash ('Master admin can not be deleted', 'info')
                return redirect(url_for('manageusers'))
            else:
                cur2 = mysql.connection.cursor()
                cur2.execute(" Delete from `AdminAccounts` where id = %s" ,  [id] )
                ## commit and close ##
                mysql.connection.commit()
                cur2.close()

                flash ('Admin deleted', 'success')
                return redirect(url_for('manageusers'))
        cur.close()
        return render_template('deleteadmin.html', form=form )
    return redirect(url_for('login'))
    

@app.route("/deleteedlobj/<string:id>/", methods=['GET','POST'])
def deleteedlobj(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `EDL_Data` as edlobject FROM `EDLData` where  UID = %s;" , [id] )
        results = cur.fetchone()

        form = DeleteEDLObj(request.form)
        form.edlobject.data = results['edlobject']
        
        if request.method == 'POST' and form.validate():
            edlobject = form.edlobject.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" Delete from `EDLData` where UID = %s and EDL_Data = %s "  , ( id , edlobject ))
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Object Deleted', 'success')
            return redirect(url_for('edl'))
        cur.close()
        return render_template('deleteedlobj.html', form=form )
    return redirect(url_for('login'))



 
@app.route("/deletemember/<string:id>/", methods=['GET','POST'])
def deletemember(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT Group_User_Map.UID as UID, IFNULL(DHCP.DisplayName, DHCP.Hostname) as Hostname, INET_NTOA(DHCP.IPaddr) as IP from DHCP INNER JOIN Group_User_Map ON DHCP.UID=Group_User_Map.DHCP_UID where Group_User_Map.UID = %s order by Group_User_Map.UID asc ;" , [id] )
        results = cur.fetchone()

        form = DeleteMemForm(request.form)
        form.hostname.data = results['Hostname']
        form.ipaddr.data = results['IP']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            hostname = request.form['hostname']
            ipaddr = request.form['ipaddr']
            uid = form.uid.data
            blank = 0
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" Delete from Group_User_Map where UID = %s and DHCP_UID <> %s; "  , ( uid , blank ))
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device Deleted', 'success')
            return redirect(url_for('group'))
    
        cur.close()
        
        return render_template('deletemember.html', form=form )
    return redirect(url_for('login'))


@app.route("/editdhcp/<string:id>/", methods=['GET','POST'])
def editdhcp(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, Vendor,  inet_ntoa(`IPaddr`) as IP,`Hostname`,`DisplayName` ,`LeaseTime`,`Source`FROM `DHCP` where  UID = %s;" , [id] )
        results = cur.fetchone()
        
        form = EditDhcp(request.form)
        form.displayname.data = results['DisplayName']
        form.vendor.data = results['Vendor']
        form.hostname.data = results['Hostname']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            displayname = request.form['displayname']
            hostname = form.hostname.data
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" update `DHCP` set `DisplayName` = %s  where UID = %s;", (displayname,   uid) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device edited', 'success')
            return redirect(url_for('dhcpid'))
    
    
        cur.close()
            
        
        return render_template('editdhcp.html', form=form )
    return redirect(url_for('login'))


@app.route("/deletedhcp/<string:id>/", methods=['GET','POST'])
def deletedhcp(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute(" SELECT `UID`, `MacAddr`, inet_ntoa(`IPaddr`) as IPaddr,`Hostname`,`DisplayName` ,`LeaseTime`,`Source`FROM `DHCP` where  UID = %s;" , [id] )
        results = cur.fetchone()
    
      
        form = DeleteDhcp(request.form)
        form.displayname.data = results['DisplayName']
        form.hostname.data = results['Hostname']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            hostname = request.form['hostname']
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" Delete from `DHCP` where UID = %s and Hostname = %s"  , (uid ,hostname))
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            blank = 0 
            cur = mysql.connection.cursor()
            cur.execute(" Delete from Group_User_Map where  DHCP_UID = %s and Group_UID <> %s ; "  , ( uid , blank ))
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Device Deleted', 'success')
            return redirect(url_for('dhcpid'))
        cur.close()
            
        
        return render_template('deletedhcp.html', form=form )
    return redirect(url_for('login'))

@app.route("/editgroup/<string:id>/", methods=['GET','POST'])
def editgroup(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT `UID`, GName,  `Desc` as descript FROM GROUPS  where  UID = %s;" , [id] )
        results = cur.fetchone()
        
        form = EditGroup(request.form)
        form.displayname.data = results['GName']
        form.descript.data = results['descript']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            descript = request.form['descript']
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" update GROUPS set `Desc` = %s  where UID = %s;", (descript,   uid) )
            
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            
            flash ('Group edited', 'success')
            return redirect(url_for('group'))
        cur.close()
        return render_template('editgroup.html', form=form )
    return redirect(url_for('login'))

@app.route("/deletegroup/<string:id>/", methods=['GET','POST'])
def deletegroup(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT `UID`, GName,  `Desc` as descript FROM GROUPS  where  UID = %s;" , [id] )
        results = cur.fetchone()
    
      
        form = DeleteGroup(request.form)
        form.displayname.data = results['GName']
        form.descript.data = results['descript']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            displayname = request.form['displayname']
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            cur.execute(" Delete from GROUPS where UID = %s and GName = %s ;" , (uid , displayname))
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
            blank = 0 
            cur = mysql.connection.cursor()
            cur.execute(" Delete from Group_User_Map where Group_UID = %s and DHCP_UID <> %s; "  , ( uid , blank ))
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
               
               
            flash ('Group Deleted', 'success')
            return redirect(url_for('group'))
        cur.close()
        return render_template('deletegroup.html', form=form )
    return redirect(url_for('login'))

@app.route("/deleteedl/<string:id>/", methods=['GET','POST'])
def deleteedl(id):
    if 'loggedin' in session:
        cur = mysql.connection.cursor()
        result = cur.execute("SELECT `UID`, EDLName,  `Desc` as descript FROM EDL  where  UID = %s;" , [id] )
        results = cur.fetchone()
    
      
        form = DeleteEDL(request.form)
        form.displayname.data = results['EDLName']
        form.descript.data = results['descript']
        form.uid.data = results['UID']
        
        if request.method == 'POST' and form.validate():
            displayname = request.form['displayname']
            uid = form.uid.data
            ## cursor ##
            cur = mysql.connection.cursor()
            #print([id])
            cur.execute("Delete from EDLData where EDL_UID = %s;" , [id] )
            mysql.connection.commit()
            cur.close()
            cur = mysql.connection.cursor()
            cur.execute(" Delete from EDL where UID = %s and EDLName = %s ;" , (uid , displayname))
            ## commit and close ##
            mysql.connection.commit()
            cur.close()
               
               
            flash ('EDL Deleted', 'success')
            return redirect(url_for('edl'))
        cur.close()
        return render_template('deleteedl.html', form=form )
    return redirect(url_for('login'))



### does not require login as is being used by FW as a EDL ###
@app.route('/download/<filename>', methods=['GET', 'POST'])
def download(filename):
    fileedl = "%s" %(filename)
    nameedl = fileedl[:-4]
    folderedl = "edldownloads/%s" %(fileedl)

    conn = pymysql.connect(host=host, port=port, user=user, passwd=passwd, db=db)
    cur = conn.cursor()

#collect all the IP EDLS
    state = ("select `UID` from EDL where `EDLName` = '%s';") %(nameedl)
    try:
        cur.execute(state)
        results = cur.fetchall()
        for row in results: 
            ID = row[0]
            f = open('edldownloads/%s.txt' %(nameedl), 'w') 
#open file for writing
            state1 = ("SELECT `EDL_Data` FROM `EDLData` where `EDL_UID` = %s ;") %(ID)
            cur.execute(state1)
            results1 = cur.fetchall()
            for row in results1:
                ip = row[0]
                f.write(ip+ '\n')
            f.close()
#Return File 
        return send_file(folderedl,  as_attachment=True)
        
    except :
        f = open('edldownloads/%s.txt' %(nameedl), 'w')
        f.write('\n')
        f.close()
#Return empty File 
        return send_file(folderedl,  as_attachment=True)
        

#@app.route("/reset")
#def reset():
#    return render_template('reset.html')

class SetUp(Form):
    ipman = StringField('Management IP', [validators.IPAddress(ipv4=True , message="Enter a valid IP Address")])
    adminuser = StringField('Admin UserName', [validators.Length(min=1, max=50)])
    adminpwd = PasswordField('Admin Password', [validators.Length(min=1, max=50)])

class AddDeviceForm(Form):
    hostname = StringField('Display Name', [validators.Length(min=1, max=50)])
    ipaddr = StringField('IP Address', [validators.IPAddress(ipv4=True , message="Enter a valid IP Address")])

class AddAdminForm(Form):
    username = StringField('Login', [validators.Length(min=1, max=50)])
    useremail = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    userpassword = PasswordField('New Password', [validators.DataRequired(), validators.EqualTo('checkpwd', message='Passwords must match')])
    checkpwd = PasswordField('Repeat New Password')

class AddEDLobject(Form):
    edlobj = StringField('Object String', [validators.Length(min=1, max=50 , message="Enter required")])
    
class DeleteEDLObj(Form):
    edlobject = StringField('Object String', render_kw={'readonly': True})

class EditDeviceForm(Form):
    uid = IntegerField('UID', render_kw={'readonly': True})
    hostname = StringField('Display Name', [validators.Length(min=1, max=50)])
    ipaddr = StringField('IP Address', [validators.IPAddress(ipv4=True , message="Enter a valid IP Address")])

class DeleteDeviceForm(Form):
    uid = IntegerField('UID', render_kw={'readonly': True})
    hostname = StringField('Display Name', render_kw={'readonly': True})
    ipaddr = StringField('IP Address', render_kw={'readonly': True})

class DeleteAdminForm(Form):
    id = IntegerField('id', render_kw={'readonly': True})
    username = StringField('Login', render_kw={'readonly': True})
    useremail = EmailField('Email address',render_kw={'readonly': True})


class DeleteMemForm(Form):
    uid = IntegerField('UID', render_kw={'readonly': True})
    hostname = StringField('Display Name', render_kw={'readonly': True})
    ipaddr = StringField('IP Address', render_kw={'readonly': True}) 

class EditDhcp(Form):
    uid = IntegerField('UID', render_kw={'readonly': True})
    hostname = StringField('Host Name', render_kw={'readonly': True} )
    vendor = StringField('Mac Vendor', render_kw={'readonly': True} )
    displayname = StringField('Display Name')

class DeleteDhcp(Form):
    uid = IntegerField('UID', render_kw={'readonly': True} )
    hostname = StringField('Host Name', render_kw={'readonly': True} )
    displayname = StringField('Display Name', render_kw={'readonly': True})   
    
class AddEDL(Form):
    descript = StringField('Description')
    displayname = StringField('EDL Name', [validators.Length(min=1, max=50)])
    
class AddGroup(Form):
    descript = StringField('Description')
    displayname = StringField('Group Name', [validators.Length(min=1, max=50)])
    
class EditGroup(Form):
    uid = IntegerField('UID', render_kw={'readonly': True})
    descript = StringField('Description')
    displayname = StringField('Group Name', render_kw={'readonly': True})
    
class DeleteGroup(Form):
    uid = IntegerField('UID', render_kw={'readonly': True} )
    descript = StringField('Description', render_kw={'readonly': True} )
    displayname = StringField('Group Name', render_kw={'readonly': True})   
    
    
class DeleteEDL(Form):
    uid = IntegerField('UID', render_kw={'readonly': True} )
    descript = StringField('Description', render_kw={'readonly': True} )
    displayname = StringField('EDL Name', render_kw={'readonly': True})   

class addmemberForm(Form):
    displayname = StringField('Display Name', render_kw={'readonly': True})
    ip = StringField('IP Address', render_kw={'readonly': True})    
    DUID = IntegerField('DUID', render_kw={'readonly': True} )
    GUID = IntegerField('GUID', render_kw={'readonly': True} )   

class ChangePwd(Form):
    currentpwd = PasswordField('Current Password', [validators.Length(min=1, max=50)])
    newpwd = PasswordField('New Password', [validators.DataRequired(), validators.EqualTo('checkpwd', message='Passwords must match')])
    checkpwd = PasswordField('Repeat New Password')
    

class Force(Form):
     checkbox = BooleanField('Agree?', validators=[validators.DataRequired(), ])
    
if __name__ == '__main__':
    initBackgroundProcs()
    app.secret_key='PaloAltoNetworksUserIDRegister'
    app.run(debug=False , host=webhost , port=webport)

    