<h1>SOC Analyst Home Lab</h1>


 

<h2>Description</h2>
Setting up 2 VM machine to mimic a SOC environment. One Kali Linux VM to emulate and attacker. Installing Sysmon on Windows VM for telemetry on our Windows endpoint. Installing LimaCharlie EDR on our Windows VM using as a cross-platform EDR agent, that also handles all of the log shipping/ingestion and a plus having a threat detection engine. Using our Kali Linux VM we are going to make some noise, generating C2 payload and and then proceeding to our command and control session. We will also craft our own detection rules and proceeding to block any attacks. Lastly we are going to use some YARA scanning, the goal is to take advantage of a more advanced capability. To automatically scan files or processes for the presence of malware based on a YARA signature. 

<br />


<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 
- <b>Linux</b>
- <b>Sysmon</b>
- <b>LimaCharlie</b>
- <b>YARA</b>
- <b>C2 session payload</b>

<h2>Environments Used </h2>

- <b>Windows 10</b> (21H2)
- <b>Ubuntu Server 22.04</b>
- <b>Kali Linux (attack machine)</b>

<h2>Program walk-through:</h2>

<h3>Part Two (Generating C2 Payload):</h3>
<h3>Part Three (Emulating an adversary):</h3>
<h3>Part Four (Blocking an attack):</h3>
<h3>Part Five (False Positive tuning in LimaCharlie):</h3>
<h3>Part Six (Detection rule & YARA scans):</h3>
<br/>
<br/>
<br/>
<br/>

<p align="center">
<h3>Part One (Install & setting up VMs:</h3>
Installing Ubuntu: <br/>
We need to take a few steps to set our static IP address for this VM.<br/>
<br />
<img src="https://i.imgur.com/nl6DEQ6.png"/>
<br />
<br />
Finding out the gateway IP of your VMware workstation NAT network:  <br/>
VMware workstation > click Edit menu on top > Click "Virtual Network Editor" > Select Type : "NAT" network > and click "NAT Settings" > make sure to take down the Gateway address IP and Subnet mask <br/>
<br />
<img src="https://i.imgur.com/BwFP3Er.png"/>
<br />
<br />
Now back to Ubuntu Installer we are going to change the interface from DHCPv4 to Manual or static: <br/>
Now got back to Network Connections > drop down to "ens33 eth" and select "edit IPv4" > after that select "Manual" > now a window has appeared and just plug in the required IP from our previous steps <br/>
<br />
<img src="https://i.imgur.com/9JN0v2l.png"/>
<br />
<br />
Continue to Install Ubuntu:  <br/>
Once Static IP has been set > continue to next installer > Make sure to set memorable username/password > Next step "Install OpenSSH server" > then continue isntalling OS until "Install Complete" and hit "reboot now" <br/>
<br />
<img src="https://i.imgur.com/EtZPCjM.png"/>
<br />
<br />
Installation and Reboot complete:  <br/>
After reboot now we make sure DNS and outbound pings are working > make sure to login in with the your credentials > type in "ping -c 2 google.com" > looks like we pinged right now we are all set for our ubuntu server <br/>
<br />
<img src="https://i.imgur.com/0pTReUk.png"/>
<br />
<br />
Windows 10 ent VM configurations:  <br/>
Disabling the Windows defender so it doesn't interfere with the shady stuff we are planning to do. Here are the few steps I did: <br/>
Disabling Tamper Protection > click "Start" > "Settings" > "Privacy & Security" > " Windows Security" > "Virus & threat protection" > Under this tab click " Manage settings" > Toggle off the "Tamper Protection"<br/>
<br /> 
<img src="https://i.imgur.com/9R3wDfE.png"/>
<br />
<br />
Permanently Disable defender via group policy editor:  <br/>
click "start" menu > type "cmd" into the search bar > Right click "command promt" and click " Run as administrator" and then run the following Command "gpedit.msc" <br/>
<img src="https://i.imgur.com/wIcheNb.png"/>
<br />
Also we can disable defendiar via Group Policy Editor : <br/>
Click computer configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Double-click "Turn off Microsoft Defender Antivirus"> select "Enabled" > click apply and ok <br/>
<br />
Permanently Disable Defender via Registry: <br/>
Open cmd promt with administrative privileges and type the following command: "REG ADD "hklm\software\policies\microsoft\windows defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f"
<img src="https://i.imgur.com/CBejFpA.png"/>
<br />
Installing Sysmon in Windows VM: <br/>
Now launch Administrative Powershell > Download Syszmon with the following command > "Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile C:\Windows\Temp\Sysmon.zip" <br/>
We unzip Sysmon.zip using this command: "Expand-Archive -LiteralPath C:\Windows\Temp\Sysmon.zip -DestinationPath C:\Windows\Temp\Sysmon" <br/>
After that we Download SwiftOnSecurity's Sysmon config with these set of commands > "Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile C:\Windows\Temp\Sysmon\sysmonconfig.xml" <br/>
Installing sysmon with Swift's config: "C:\Windows\Temp\Sysmon\Sysmon64.exe -accepteula -i C:\Windows\Temp\Sysmon\sysmonconfig.xml"<br/>
Lastly we check for the presence of sysmon Event Logs : Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10<br/>
<br />
<img src="https://i.imgur.com/RTFCNpJ.png"/>
<img src="https://i.imgur.com/qCbiNb9.png"/>
<img src="https://i.imgur.com/JxcYpnq.png"/>
<br />
Installing LimaCharlie EDR on our Windows VM: <br/>
Creating a free LimaCharlie Account <br/>
Once Logged into LimaCharlie, create an organization: Name: anything but must be unique > Data residency: USA > Template: Extended Detection & Response Standard <br/>
<img src="https://i.imgur.com/vnoK5x9.png"/>
<br/>
Once you've created the organization we proceed to adding a sensor > Click "Add Sensor" > Now we are going to create an installation key: Select an installation key "Windows" > click create > select the installation key we just created > specify the x86-64 (.exe) > after that don't do anything or download the selected installer. <br/>
<img src="https://i.imgur.com/bmss0H7.png"/>
<img src="https://i.imgur.com/bf1l4NW.png"/>
<br />
WE go bac kto the Windows VM, open an administrative Powershell prompt and enter the following commands: "cd C:\Users\Win10 Ent\Downloads" > next we type these commands "Invoke-WebRequest -Uri https://downloads.limacharlie.io/sensor/windows/64 -Outfile C:\Users\User\Downloads\lc_sensor.exe" > now we shift to a standard command by running "cmd.exe" > next we go back to Limacharlie go to the number 4 bullet and copy the command then paste it and enter. <br/> 
<br />
<img src="https://i.imgur.com/LDrYtaz.png"/>
<img src="https://i.imgur.com/bf1l4NW.png"/>
<img src="https://i.imgur.com/RNXJqPG.png"/> 
<br />
Once we've done everything and worked correctly, once we go back to the LimaCharlie web UI we should be able to see a sensor reporting in like so:<br/>
<img src="https://i.imgur.com/0quhJNQ.png"/> 
<br />
# In this step we are going to configure Limacharlie to also ship the Sysmon event logs alongside its own EDR telemetry   <br/>
a. in the left side menu click "Artifact Collection" <br/>
b. click "Add Rule" > enter "windows-sysmon-logs as the name > for platforms type "Windows" > path pattern will be: wel://Microsoft-Windows-Sysmon/Operational:* > retention period will be "10" > after this click "save" <br/>
by doing this we are now going to start shipping sysmon logs which provide a wealth of EDR-like telemetry, some of which is redundant to LC's own telemetry \. <br/>
<br />
Now ths will be our last step for our Part one: <br/>
<br />
# For this step I just used my host system and used SSH to access our Ubuntu VM. <br/>
# Using the static IP address of our Ubuntu we can SSH to it using this command: "ssh user@[ubuntu IP] <br/>
# Once we SSH successfully we can "sudo su" to make our life easier and have root privilege <br/>
# We proceed to download Sliver, a C2 framework by Bishopfox. We are going to use these set of commands in order to download. <br/>
# Download Sliver Linux Server binary : "wget https://github.com/BishopFox/sliver/releases/download/v1.5.34/sliver-server_linux -O /usr/local/bin/sliver-server" <br/>
# We make it executable by changing the permissions using these command: "chmod +x /usr/local/bin/sliver-server" <br/>
# I recommend installing mingw-w64 for additional capabiities: enter this command in our SSH console "apt install -y mingw-w64" <br/>
# Now lastly we create a working directory that we will use in future steps : enter this command : "mkdir -p /opt/sliver" <br/>
<br />

</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
