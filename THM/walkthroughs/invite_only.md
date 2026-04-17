# Invite Only (Easy)

## 

Flagged IP: 101[.]99[.]76[.]120
Flagged SHA256 hash: 5d0509f68a9b7c415a726be75a078180e3f02e59866f193b0a99eee8e39c874f

Launch TryDetectThis2.0

## What is the name of the file identified with the flagged SHA256 hash?

- Search the hash in Virustotal offline

`syshelpers.exe`

## What is the file type associated with the flagged SHA256 hash?

`Win32 EXE`

## What are the execution parents of the flagged hash? List the names chronologically, using a comma as a separator. Note down the hashes for later use.

- Navigate to the "Relations" tab and look for "Execution Parents"

Hashes of the following files:
- 361GJX7J - `047c5eec0445746862710d20e50a5dd04510b7e625fa5c1f5d48ce078001c0de`
- installer.exe - `fa102d4e3cfbe85f5189da70a52c1d266925f3efd122091cdc8fe0fc39033942`

`361GJX7J,installer.exe`

## What is the name of the file being dropped? Note down the hash value for later use.

- Navigate to the "Bahavior" tab and check the first GET request made

`AClient.exe`

## Research the second hash in question 3 and list the four malicious dropped files in the order they appear (from up to down), separated by commas.

- Go to relations tab after searching the second hash and scroll down.

- Use the one with the red text and exclamations beside them

- Another broken answer in TryHackMe

- Filename is "nat1.vbs" not "nat.vbs"

`searchHost.exe, syshelpers.exe, nat.vbs, runsys.vbs`

## Analyse the files related to the flagged IP. What is the malware family that links these files?

- Community tab after searching the IP address

`Asyncrat`

## What is the title of the original report where these flagged indicators are mentioned? Use Google to find the report.

`From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery`

## Which tool did the attackers use to steal cookies from the Google Chrome browser?

google search

`ChromeKatz`

## Which phishing technique did the attackers use? Use the report to answer the question.

`ClickFix` google search

## What is the name of the platform that was used to redirect a user to malicious servers?

- Report

`Discord`

