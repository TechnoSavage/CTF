#!/bin/bash -x

ipaddress="94.237.49.182"
port="58822"
for i in {000..104}; do
r=$(echo $i | nc $ipaddress $port -q 5)
line=$(echo $r | cut -d ":" -f 3)
letter=$( echo $line | cut -d " " -f 1)
echo $letter >> flag.txt
done
flag=$(tr -d '\n' < flag.txt)
echo $flag 