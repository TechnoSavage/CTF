## Pcap Commands:

Identify Data Exfiltration:

```
tshark -r data-exfil.pcap -T fields -e ip.src -e ip.dst -e ip.len ip.src == 192.168.0.0/16 or ip.src == 10.0.0.0/8 or ip.src == 172.16.0.0/12 | sort | datamash -g 1,2 sum 3 | sort -k 3 -rn | head
```