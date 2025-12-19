# Snort Syntax reference

## Configuration

`snort -V`

`snort -c /etc/snort/snort.conf -T`

-V | --version	This parameter provides information about your instance version.

-c	Identifying the configuration file

-T	Snort's self-test parameter, you can test your setup with this parameter.

-q	Quiet mode prevents snort from displaying the default banner and initial information about your setup.

Start in background mode

`sudo snort -c /etc/snort/snort.conf -D`

## Sniffer Mode

-v	Verbose. Display the TCP/IP output in the console.

-d	Display the packet data (payload).

-e	Display the link-layer (TCP/IP/UDP/ICMP) headers.

-X	Display the full packet details in HEX.

-i	This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff. 

Specify an interface to sniff

`sudo snort -v -i eth0`

Show packets in verbose mode

`sudo snort -v`

```
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=64)
12/01-20:10:13.846653 192.168.175.129:34316 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:23826 IpLen:20 DgmLen:64 DF
Len: 36
=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

12/01-20:10:13.846794 192.168.175.129:38655 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:23827 IpLen:20 DgmLen:64 DF
Len: 36
===============================================================================
Snort exiting
```

Run in dumping packet data mode

`sudo snort -d`

```
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=67)

12/01-20:45:42.068675 192.168.175.129:37820 -> 192.168.175.2:53
UDP TTL:64 TOS:0x0 ID:53099 IpLen:20 DgmLen:56 DF
Len: 28
99 A5 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  .............goo
67 6C 65 03 63 6F 6D 00 00 1C 00 01              gle.com.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-20:45:42.070742 192.168.175.2:53 -> 192.168.175.129:44947
UDP TTL:128 TOS:0x0 ID:63307 IpLen:20 DgmLen:72
Len: 44
FE 64 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  .d...........goo
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........
00 01 00 00 00 05 00 04 D8 3A CE CE              .........:..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

dump and link layer header mode

`snort -d -e`

```
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=70)
12/01-20:55:26.958773 00:0C:29:A5:B7:A2 -> 00:50:56:E1:9B:9D type:0x800 len:0x46
192.168.175.129:47395 -> 192.168.175.2:53 UDP TTL:64 TOS:0x0 ID:64294 IpLen:20 DgmLen:56 DF
Len: 28
6D 9C 01 00 00 01 00 00 00 00 00 00 06 67 6F 6F  m............goo
67 6C 65 03 63 6F 6D 00 00 01 00 01              gle.com.....

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-20:55:26.965226 00:50:56:E1:9B:9D -> 00:0C:29:A5:B7:A2 type:0x800 len:0x56
192.168.175.2:53 -> 192.168.175.129:47395 UDP TTL:128 TOS:0x0 ID:63346 IpLen:20 DgmLen:72
Len: 44
6D 9C 81 80 00 01 00 01 00 00 00 00 06 67 6F 6F  m............goo
67 6C 65 03 63 6F 6D 00 00 01 00 01 C0 0C 00 01  gle.com.........
00 01 00 00 00 05 00 04 D8 3A D6 8E              .........:..
```

full packet dump mode

`snort -X`

```
Running in packet dump mode

        --== Initializing Snort ==--
...
Commencing packet processing (pid=76)
WARNING: No preprocessors configured for policy 0.
12/01-21:07:56.806121 192.168.175.1:58626 -> 239.255.255.250:1900
UDP TTL:1 TOS:0x0 ID:48861 IpLen:20 DgmLen:196
Len: 168
0x0000: 01 00 5E 7F FF FA 00 50 56 C0 00 08 08 00 45 00  ..^....PV.....E.
0x0010: 00 C4 BE DD 00 00 01 11 9A A7 C0 A8 AF 01 EF FF  ................
0x0020: FF FA E5 02 07 6C 00 B0 85 AE 4D 2D 53 45 41 52  .....l....M-SEAR
0x0030: 43 48 20 2A 20 48 54 54 50 2F 31 2E 31 0D 0A 48  CH * HTTP/1.1..H
0x0040: 4F 53 54 3A 20 32 33 39 2E 32 35 35 2E 32 35 35  OST: 239.255.255
0x0050: 2E 32 35 30 3A 31 39 30 30 0D 0A 4D 41 4E 3A 20  .250:1900..MAN: 
0x0060: 22 73 73 64 70 3A 64 69 73 63 6F 76 65 72 22 0D  "ssdp:discover".
0x0070: 0A 4D 58 3A 20 31 0D 0A 53 54 3A 20 75 72 6E 3A  .MX: 1..ST: urn:
0x0080: 64 69 61 6C 2D 6D 75 6C 74 69 73 63 72 65 65 6E  dial-multiscreen
0x0090: 2D 6F 72 67 3A 73 65 72 76 69 63 65 3A 64 69 61  -org:service:dia
0x00A0: 6C 3A 31 0D 0A 55 53 45 52 2D 41 47 45 4E 54 3A  l:1..USER-AGENT:
0x00B0: 20 43 68 72 6F 6D 69 75 6D 2F 39 35 2E 30 2E 34   Chromium/95.0.4
0x00C0: 36 33 38 2E 36 39 20 57 69 6E 64 6F 77 73 0D 0A  638.69 Windows..
0x00D0: 0D 0A                                            ..

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

WARNING: No preprocessors configured for policy 0.
12/01-21:07:57.624205 216.58.214.142 -> 192.168.175.129
ICMP TTL:128 TOS:0x0 ID:63394 IpLen:20 DgmLen:84
Type:0  Code:0  ID:15  Seq:1  ECHO REPLY
0x0000: 00 0C 29 A5 B7 A2 00 50 56 E1 9B 9D 08 00 45 00  ..)....PV.....E.
0x0010: 00 54 F7 A2 00 00 80 01 24 13 D8 3A D6 8E C0 A8  .T......$..:....
0x0020: AF 81 00 00 BE B6 00 0F 00 01 2D E4 A7 61 00 00  ..........-..a..
0x0030: 00 00 A4 20 09 00 00 00 00 00 10 11 12 13 14 15  ... ............
0x0040: 16 17 18 19 1A 1B 1C 1D 1E 1F 20 21 22 23 24 25  .......... !"#$%
0x0050: 26 27 28 29 2A 2B 2C 2D 2E 2F 30 31 32 33 34 35  &'()*+,-./012345
0x0060: 36 37                                            67

=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
```

## Packet Capture Mode

## Logging Mode

-l	Logger mode, target log and alert output directory. Default output folder is /var/log/snort. The default action is to dump as tcpdump format in /var/log/snort

-K ASCII	Log packets in ASCII format.

-r	Reading option, read the dumped logs in Snort.

-n	Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.

Create log in current directory

`sudo snort -dev -l .`

Read log files

`sudo snort -r snort.log.file`

Read log files with tcpdump

`tcpdump -r snort.log.file -ntc 10`

Read log files with BPF filters

`sudo snort -r logname.log -X`
`sudo snort -r logname.log icmp`
`sudo snort -r logname.log tcp`
`sudo snort -r logname.log 'udp and port 53'`

Read log file and first 10 packets

`snort -dvr logname.log -n 10`

## NIDS Mode

-c	
Defining the configuration file.

-T	Testing the configuration file.

-N	Disable logging.

-D	Background mode.

-A	Alert modes
>- **full**: Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.
>- **fast**:  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers.

>- **console**: Provides fast style alerts on the console screen.

>- **cmg**: CMG style, basic header details with payload in hex and text format.

>- **none**: Disabling alerting.

## Reading PCAPs

-r / --pcap-single=	Read a single pcap

--pcap-list=""	Read pcaps provided in command (space separated).

--pcap-show	Show pcap name on console during processing.

`snort -r icmp-test.pcap`

`sudo snort -c /etc/snort/snort.conf -q -r icmp-test.pcap -A console -n 10`

`sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console -n 10`

PCAP show (sort results by source PCAP)

`sudo snort -c /etc/snort/snort.conf -q --pcap-list="icmp-test.pcap http2.pcap" -A console --pcap-show`

## Snort Rule examples

Format

`alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

Action	

>- **alert**: Generate an alert and log the packet.

>- **log**: Log the packet.

>- **drop**: Block and log the packet.

>- **reject**: Block the packet, log it and terminate the packet session. 

Protocol	

>- IP
>- TCP
>- UDP
>- ICMP

-> Source to destination flow.
<> Bidirectional flow

IP Filtering


`alert icmp 192.168.1.56 any <> any any  (msg: "ICMP Packet From "; sid: 100001; rev:1;)`

Filter an IP range

`alert icmp 192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

Filter multiple IP ranges

`alert icmp [192.168.1.0/24, 10.1.1.0/24] any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

Exclude IP addresses/ranges

"negation operator" is used for excluding specific addresses and ports. Negation operator is indicated with "!"

`alert icmp !192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

Port Filtering	

`alert tcp any any <> any 21  (msg: "FTP Port 21 Command Activity Detected"; sid: 100001; rev:1;)`

Exclude a specific port	

`alert tcp any any <> any !21  (msg: "Traffic Activity Without FTP Port 21 Command Channel"; sid: 100001; rev:1;)`

Filter a port range (Type 1)	

`alert tcp any any <> any 1:1024   (msg: "TCP 1-1024 System Port Activity"; sid: 100001; rev:1;)`

Filter a port range (Type 2)	

`alert tcp any any <> any :1024   (msg: "TCP 0-1024 System Port Activity"; sid: 100001; rev:1;)`


Filter a port range (Type 3)	

`alert tcp any any <> any 1025: (msg: "TCP Non-System Port Activity"; sid: 100001; rev:1;)`

This rule will create an alert for each TCP packet sent to source port higher than or equal to 1025.

Filter a port range (Type 4)	

`alert tcp any any <> any [21,23] (msg: "FTP and Telnet Port 21-23 Activity Detected"; sid: 100001; rev:1;)`

Filter for FTP login failure

`alert tcp any any <> any 21 (msg: "FTP failed login."; content: "530"; sid: 100001; rev:1;`

Filter for FTP successful login

`alert tcp any any <> any 21 (msg: "FTP successful login."; content: "230"; sid: 100001; rev:1;)`

FTP username accepted, need password

`alert tcp any any <> any 21 (msg: "FTP username accepted, password needed."; content: "331"; sid: 100001; rev:1;)`

FTP Administrator username accepted, password needed

`alert tcp any any <> any 21 (msg: "Administrator username accepted, password needed."; content: "331"; content: "administrator"; nocase; sid: 100001; rev:1;)`

PNG file detected

`alert tcp any any <> any any  (msg: "PNG file found"; content: "PNG"; nocase; sid: 100001; rev:1;)`

GIF file detected

`alert tcp any any <> any any  (msg: "GIF file found"; content: "GIF"; nocase; sid: 100001; rev:1;)`

Bittorrent packets

`alert tcp any any <> any any (msg: "torrent detected"; content: "announce"; sid: 100001; rev:1;)`

MS1710 Eternalblue

```
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; pcre:"/|57 69 6e 64 6f 77 73 20 37 20 48 6f 6d 65 20 50|/"; pcre: "/|72 65 6d 69 75 6d 20 37 36 30 31 20 53 65 72 76|/"; pcre:"/|69 63 65 20 50 61 63 6b 20 31|/"; sid: 2094284; rev: 2;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "IPC$"; sid:2094285; rev: 3;)
alert tcp any any -> any 445 (msg: "Exploit Detected!"; flow: to_server, established; content: "NTLMSSP";sid: 2094286; rev: 2;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "WindowsPowerShell";sid: 20244223; rev: 3;)
alert tcp any any -> any any (msg: "Exploit Detected!"; flow: to_server, established; content: "ADMIN$";sid:20244224; rev: 2;)
```

`alert tcp any any <> any any (msg:"\IPC$ detected"; content:"|5c 49 50 43 24|"; sid:100001;rev:1;)`

Log4j

```
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:ldap://"; fast_pattern:only; flowbits:set, fox.apachelog4j.rce; priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003726; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; pcre:"/\$\{jndi\:(rmi|ldaps|dns)\:/"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003728; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)"; flow:established, to_server; content:"${jndi:"; fast_pattern; content:!"ldap://"; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, twitter.com/stereotype32/status/1469313856229228544; metadata:CVE 2021-44228; metadata:created_at 2021-12-10; metadata:ids suricata; sid:21003730; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Defense-Evasive Apache Log4J RCE Request Observed (URL encoded bracket) (CVE-2021-44228)"; flow:established, to_server; content:"%7bjndi:"; nocase; fast_pattern; flowbits:set, fox.apachelog4j.rce; threshold:type limit, track by_dst, count 1, seconds 3600;  priority:3; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003731; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header"; flow:established, to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003732; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI"; flow:established,to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; flowbits:set, fox.apachelog4j.rce.loose;  priority:3; threshold:type limit, track by_dst, count 1, seconds 3600; reference:url, http://www.lunasec.io/docs/blog/log4j-zero-day/; reference:url, https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; sid:21003733; rev:1;) 

# Better and stricter rules, also detects evasion techniques
alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in HTTP Header (strict)"; flow:established,to_server; content:"${"; http_header; fast_pattern; content:"}"; http_header; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Hi"; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003734; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in URI (strict)"; flow:established, to_server; content:"${"; http_uri; fast_pattern; content:"}"; http_uri; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Ui"; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-11; metadata:ids suricata; priority:3; sid:21003735; rev:1;) 

alert tcp any any -> any any (msg:"FOX-SRT – Exploit – Possible Apache Log4j Exploit Attempt in Client Body (strict)"; flow:to_server; content:"${"; http_client_body; fast_pattern; content:"}"; http_client_body; distance:0; pcre:"/(\$\{\w+:.*\}|jndi)/Pi"; flowbits:set, fox.apachelog4j.rce.strict; reference:url,www.lunasec.io/docs/blog/log4j-zero-day/; reference:url,https://twitter.com/testanull/status/1469549425521348609; metadata:CVE 2021-44228; metadata:created_at 2021-12-12; metadata:ids suricata; priority:3; sid:21003744; rev:1;)
```

`alert tcp any any <> any any (msg:"payload between 770 and 850 bytes"; dsize:770<>850; sid: 100001; rev:1;)`

### General Options

**Msg** - The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarises the event.

**Sid** - Snort rule IDs (SID) come with a pre-defined scope, and each rule must have a SID in a proper format. There are three different scopes for SIDs shown below.


    <100: Reserved rules
    100-999,999: Rules came with the build.
    >=1,000,000: Rules created by user.
    Briefly, the rules we will create should have sid greater than 100.000.000. Another important point is; SIDs should not overlap, and each id must be unique. 

**Reference** - Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a Common Vulnerabilities and Exposures (CVE) id or external information. Having references for the rules will always help analysts during the alert and incident investigation.

**Rev**	- Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique rev number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. Rev option is only an indicator of how many times the rule had revisions.

alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; rev:1;)

### Payload detection options

**Content**	- Payload data. It matches specific payload data by ASCII, HEX or both. It is possible to use this option multiple times in a single rule. However, the more you create specific pattern match features, the more it takes time to investigate a packet.

Following rules will create an alert for each HTTP packet containing the keyword "GET". This rule option is case sensitive!

    ASCII mode - `alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)`

    HEX mode - `alert tcp any any <> any 80  (msg: "GET Request Found"; content:"|47 45 54|"; sid: 100001; rev:1;)`

    Nocase	- Disabling case sensitivity. Used for enhancing the content searches. `alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; nocase; sid: 100001; rev:1;)`

    Fast_pattern - Prioritise content search to speed up the payload search operation. By default, Snort uses the biggest content and evaluates it against the rules. "fast_pattern" option helps you select the initial packet match with the specific value for further investigation. This option always works case insensitive and can be used once per rule. Note that this option is required when using multiple "content" options. 

    The following rule has two content options, and the fast_pattern option tells to snort to use the first content option (in this case, "GET") for the initial packet match.

    `alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; fast_pattern; content:"www";  sid:100001; rev:1;)`

### Non-payload options

**ID**	- Filtering the IP id field. `alert tcp any any <> any any (msg: "ID TEST"; id:123456; sid: 100001; rev:1;)`

#### Flags	
Filtering the TCP flags.

F - FIN
S - SYN
R - RST
P - PSH
A - ACK
U - URG
 
`alert tcp any any <> any any (msg: "FLAG TEST"; flags:S;  sid: 100001; rev:1;)`

#### Dsize	
Filtering the packet payload size.

dsize:min<>max;
dsize:>100
dsize:<100
`alert ip any any <> any any (msg: "SEQ TEST"; dsize:100<>300;  sid: 100001; rev:1;)`

#### Sameip	
Filtering the source and destination IP addresses for duplication.

`alert ip any any <> any any (msg: "SAME-IP TEST";  sameip; sid: 100001; rev:1;)`


## Config

Points to Remember

Main Components of Snort

Packet Decoder - Packet collector component of Snort. It collects and prepares the packets for pre-processing.

Pre-processors - A component that arranges and modifies the packets for the detection engine.

Detection Engine - The primary component that process, dissect and analyse the packets by applying the rules.

Logging and Alerting - Log and alert generation component.

Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component.

There are three types of rules available for snort

Community Rules - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
Registered Rules - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
Subscriber Rules (Paid) - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).
You can download and read more on the rules here.

Note: Once you install Snort2, it automatically creates the required directories and files. However, if you want to use the community or the paid rules, you need to indicate each rule in the snort.conf file.

Since it is a long, all-in-one configuration file, editing it without causing misconfiguration is troublesome for some users. That is why Snort has several rule updating modules and integration tools. To sum up, never replace your configured Snort configuration files; you must edit your configuration files manually or update your rules with additional tools and modules to not face any fail/crash or lack of feature.

snort.conf: Main configuration file.

local.rules: User-generated rules file.

Main configuration file (snort.conf) /etc/snort/snort.conf

#### Network variables
This section manages the scope of the detection and rule paths.

TAG NAME	INFO	EXAMPLE

HOME_NET - Network being protected.

EXTERNAL_NET - external network; must be 'any' or '!$HOME_NET'.

RULE_PATH - Hardcoded rule path. e.g. /etc/snort/rules

SO_RULE_PATH - These rules come with registered and subscriber rules. e.g. $RULE_PATH/so_rules

PREPROC_RULE_PATH - These rules come with registered and subscriber rules. e.g. $RULE_PATH/plugin_rules

#### Decoder 
In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.

TAG NAME	INFO	EXAMPLE
#config daq:	IPS mode selection.	afpacket
#config daq_mode:	Activating the inline mode	inline
#config logdir:	Hardcoded default log path.	/var/logs/snort
Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.

There are six DAQ modules available in Snort;

Pcap: Default mode, known as Sniffer mode.

Afpacket: Inline mode, known as IPS mode.

Ipq: Inline mode on Linux by using Netfilter. It replaces the snort_inline patch. 

Nfq: Inline mode on Linux.

Ipfw: Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.

Dump: Testing mode of inline and normalisation.

**note** The most popular modes are the default (pcap) and inline/IPS (Afpacket).

`sudo snort -c /path/to/rules/ -Q --daq afpacket -i interface1:interface2 -A full`

#### output plugins

This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently. 

Navigate to the "Step #7: Customise your ruleset" section.

TAG NAME	INFO	EXAMPLE
# site specific rules
Hardcoded local and user-generated rules path.	include $RULE_PATH/local.rules
#include $RULE_PATH/
Hardcoded default/downloaded rules path.
include $RULE_PATH/rulename
Note that "#" is commenting operator. You should uncomment a line to activate it.