# tcpdump

## Basic Structure

```
tcpdump -i <interface|vlan|any> -nn -s 0 -vv host|src|dst <ip address> port <port number> -w <filename>
```

`-n` no hostname resolution 

`-nn` no hostname or port

`-s 0` for all packet length including files/binaries

`-v` verbose

`-vv` very verbose

## All traffic from any set of hosts on given ports and include link-layer info

```
tcpdump -i any -s 0 -e (host <ip address> or host <ip address>) and (port 80 or port 443)
```

## Capture first 100 packets on eth0

```
tcpdump -i eth0 -c 100
```

## Capture all SSH traffic from source network to destination host

```
tcpdump -i any -s 0 -e src net x.x.x.x/24 and dst host x.x.x.x and tcp dst port 22
```

## Capture traffic except ARP

```
tcpdump -ni any not proto arp
```
