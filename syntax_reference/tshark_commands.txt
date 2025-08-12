Pcap Commands:
----------------

Identify Data Exfiltration:
---------------------------
tshark -r data-exfil.pcap -T fields -e ip.src -e ip.dst -e ip.len ip.src == 192.168.0.0/16 or ip.src == 10.0.0.0/8 or ip.src == 172.16.0.0/12 | sort | datamash -g 1,2 sum 3 | sort -k 3 -rn | head


Most commonly used ports in a PCAP file:
----------------------------------------

ls -alh sample-packets.pcap

tcpdump -qtnp -r sample-packets.pcap 2>/dev/null | wc -l

tcpdump -qtnp -r sample-packets.pcap 2>/dev/null | egrep -v '(^ARP|ICMP6)' | sed -e 's/UDP,/udp/' | awk '{print $2 " " $5 "\n" $4 " " $5}' | sed -e 's/: / /' -e 's/^.*\.//' | sort | uniq -c | sort -nr | head -20

tcpdump -qtnp -r sample-packets.pcap 'tcp port 443' 2>/dev/null | head -1