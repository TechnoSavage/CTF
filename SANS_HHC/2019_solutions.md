# IOTBraces

## Proper Firewall configuration:

The firewall used for this system is `iptables`. The following is an example of how to set a default policy with using `iptables`:

```
sudo iptables -P FORWARD DROP
```

The following is an example of allowing traffic from a specific IP and to a specific port:

```
sudo iptables -A INPUT -p tcp --dport 25 -s 172.18.5.4 -j ACCEPT
```

A proper configuration for the Smart Braces should be exactly:

1. Set the default policies to DROP for the INPUT, FORWARD, and OUTPUT chains.
2. Create a rule to ACCEPT all connections that are ESTABLISHED,RELATED on the INPUT and the OUTPUT chains.
3. Create a rule to ACCEPT only remote source IP address **172.19.0.225** to access the local 
SSH server (on port 22).
4. Create a rule to ACCEPT any source IP to the local TCP services on ports 21 and 80.
5. Create a rule to ACCEPT all OUTPUT traffic with a destination TCP port of 80.
6. Create a rule applied to the INPUT chain to ACCEPT all traffic from the lo interface.

```
sudo iptables -P FORWARD DROP
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp -s 172.19.0.225 --dport 22 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 21 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

# Laser

```
(Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent
(Invoke-WebRequest http://127.0.0.1:1225/api/refraction?val=1.867).RawContent
(Invoke-WebRequest http://127.0.0.1:1225/api/temperature?val=-33.5).RawContent

$gases = "O=6&H=7&He=3&N=4&Ne=22&Ar=11&Xe=10&F=20&Kr=8&Rn=9"
(Invoke-WebRequest -Uri http://localhost:1225/api/gas -Method POST -Body $gases).
RawContent

Get-History | Format-List CommandLine

CommandLine : (Invoke-WebRequest http://127.0.0.1:1225/api/angle?val=65.5).RawContent

CommandLine : I have many name=value variables that I share to applications system wide. 
              At a command I will reveal my secrets once you Get my Child Items.

cd env:
Get-ChildItem | Format-List name,value

Name  : riddle
Value : Squeezed and compressed I am hidden away. Expand me from my prison and I will 
        show you the way. Recurse through all /etc and Sort on my LastWriteTime to 
        reveal im the newest of all.

Get-ChildItem -Recurse /etc/ | sort LastWriteTime

/etc/apt/archive

Copy-Item /etc/apt/archive ~

Expand-Archive ./archive stuff

cd /stuff/refraction
chmod +x runme.elf
./runme.elf

refraction?val=1.867

Get-Content ./riddle
Very shallow am I in the depths of your elf home. You can find my entity by using my md5 identity:
25520151A320B5B0D21561F92C8F6224

cd ~/depths/
foreach ($item in Get-ChildItem -Recurse){$hash = Get-FileHash $item -a MD5 -ErrorAction SilentlyContinue; if ($hash.Hash -eq '25520151A320B5B0D21561F92C8F6224'){Write-Host $item}}

/home/elf/depths/produce/thhy5hll.txt

temperature?val=-33.5
I am one of many thousand similar txt's contained within the deepest of /home/elf/depths. 
Finding me will give you the most strength but doing so will require Piping all the FullName's to Sort Length.
                                      

Get-ChildItem -Recurse ./depths | sort {$_.FullName.length}

FullName  : /home/elf/depths/larger/cloud/behavior/beauty/enemy/produce/age/chair/unknown/escape/vote/long/writer/behind/ahead/thin/occasionally/explore/tape/wherever/practical/therefore/cool/plate/ice/play/truth/potatoes/beauty/fourth/careful/dawn/adult/either/burn/end/accurate/rubbed/cake/main/she/threw/eager/trip/to/soon/think/fall/is/greatest/become/accident/labor/sail/dropped/fox/

0jhj5xz6.txt
Name      : 0jhj5xz6.txt

Get process information to include Username identification. Stop Process to show me you're skilled and in this order they must be killed:

bushy
alabaster
minty
holly

Do this for me and then you /shall/see .

Get-Process -includeUserName
Stop-Process foo

Get the .xml children of /etc - an event log to be found. Group all .Id's and the last thing will be in the Properties of the lonely unique event Id.

Get-ChildItem -Filter "*.xml" -Recurse ./etc

$path = /etc/systemd/system/timers.target.wants/EventLog.xml

$event = Import-Clixml -P $path

$event | Where-Object -Value Id -eq 1

"`$correct_gases_postbody = @{`n    O=6`n    H=7`n    He=3`n    N=4`n    Ne=22`n    Ar=11`n    Xe=10`n    F=20`n    Kr=8`n    Rn=9`n}`n"
```