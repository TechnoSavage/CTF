# ItsyBitsy (Medium)

## How many events were returned for the month of March 2022?

- Set "Absolute" date range filter to start on March 1, 2022

`1482`

![Log Events](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/itsybitsy/1.png?raw=true)

## What is the IP associated with the suspected user in the logs?

- Check the only 2 source IPs

`192.166.65.54`

## The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

- Seen as the User-Agent for logs with source 192.166.65.54

`bitsadmin`

## The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

- Seen in the host field of logs with source 192.166.65.54

`pastebin.com`

## What is the full URL of the C2 to which the infected host is connected?

- combine with URI path

`pastebin.com/yTg0Ah6a`

![Answers 2-4](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/itsybitsy/2.png?raw=true)

## A file was accessed on the filesharing site. What is the name of the file accessed?

- Browse to the full URL

`secret.txt`

## The file contains a secret code with the format THM{_____}.

- The contents are visibile on the same file page

`THM{SECRET__CODE}`

![Pastebin](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/itsybitsy/3.png?raw=true)