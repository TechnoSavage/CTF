# Shadow Trace (Easy)


## File Analysis

Open PEStudio and load windows_update.exe

### What is the architecture of the binary file windows-update.exe?

This can be seen right at the bottom of the PESTUDIO interface

`64-bit`

### What is the hash (sha-256) of the file windows-update.exe?

This is found in the main interface of PESTUDIO and can be grabbed with a right-click > copy value

`b2a88de3e3bcfae4a4b38fa36e884c586b5cb2c2c283e71fba59efdb9ea64bfc`

### Identify the URL within the file to use it as an IOC

Navigate to the "strings" section of PESTDIO, it can help to sort on bits for longer strings.

A couple of URLs pop out as noteworthy...

`http://tryhatme.com/update/security-update.exe`

`tryhatme.com/VEhNe3lvdV9nMHRfc29tZV9JT0NzX2ZyaWVuZH0=`

### With the URL identified, can you spot a domain that can be used as an IOC?

Also found in the "strings" section we see an interesting subdomain.

`responses.tryhatme.com`

### Input the decoded flag from the suspicious domain

Taking the Base64 encoded portion of the previously discovered URL and decoding it will present this flag.

`THM{you_g0t_some_IOCs_friend}`

### What library related to socket communication is loaded by the binary?

Navigate to the libraries section of PESTUDIO and look for the DLL related to network sockets.

`WS2_32.dll`

## Alerts Analysis

### Can you identify the malicious URL from the trigger by the process powershell.exe?

`https://tryhatme.com/dev/main.exe`

### Can you identify the malicious URL from the alert triggered by chrome.exe?

`https://reallysecureupdate.tryhatme.com/update.exe`

### What's the name of the file saved in the alert triggered by chrome.exe?

`test.txt`