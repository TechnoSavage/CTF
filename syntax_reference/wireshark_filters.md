# wireshark filters

## Detecting NMAP scans

### Nmap tcp connect (-sT)

```
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024
```

### tcp syn (-sS)

```
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024
```

### UDP scan (-sU)

```
icmp.type==3 and icmp.code==3
```

### port range search

```
udp.dstport >= 50 and udp.dstport <=70
```

## HTTP

### look for http POST request with form data that might contain variations in username|password

```
http and eth.dst == 00:0c:29:e2:18:b4 and http.request.method == POST and (urlencoded-form.key contains "nam" or urlencoded-form.key contains "ass")
```
## ARP

### all arp requests from mac source

```
eth.src == 00:0c:29:e2:18:b4 and arp and not arp.opcode == 2
```
### arp scanning

```
arp.dst.hw_mac==00:00:00:00:00:00
```

### arp poisoning

```
arp.duplicate-address-detected or arp.duplicate-address-frame
```

### arp flooding

```
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == <target-mac-address>)
```

## Kerberos

### Kerberos user name search

```
kerberos.CNameString and !(kerberos.CNameString contains "$" )
```

## ICMP

### icmp greater than 64 bytes

```
data.len > 64 and icmp
```

## DNS

```
dns contains "dnscat"
```

```
dns contains "dns2tcp"
```

### Long dns names

```
dns.qry.name.len > 15 and !mdns
```

## FTP

### ftp logon

```
ftp.response.code == 230
```

### user and password

```
ftp.request.command == "USER"
```

```
ftp.request.command == "PASS"
```

```
ftp.request.arg == "password"
```

### failed logins

```
ftp.response.code == 530
```

```
(ftp.response.code == 530) and (ftp.response.arg contains "username")
```

```
(ftp.request.command == "PASS" ) and (ftp.request.arg == "password")
```

### check for skiddie user agents

```
(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")
```

## Log4j

```
(ip contains "jndi") or ( ip contains "Exploit")
```

```
(frame contains "jndi") or ( frame contains "Exploit")
```

```
(http.user_agent contains "$") or (http.user_agent contains "==")
```

## TLS

### client hello

```
(http.request or tls.handshake.type == 1) and !(ssdp)
```

### server hello

```
(http.request or tls.handshake.type == 2) and !(ssdp)
```