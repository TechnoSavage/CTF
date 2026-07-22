# Benign (Medium)

## How many logs are ingested from the month of March, 2022?

Set the date range to March of 2022 and create a search for `index=win_eventlogs`

![Log Events](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/benign/1.png?raw=true)

`13959`

## Imposter Alert: There seems to be an imposter account observed in the logs, what is the name of that user?

Let's start by returning the top 20 rare usernames for review, this immediately surfaces a suspicious looking username

```
index="win_eventlogs" | rare limit=20 UserName
```

![Imposter](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/benign/2.png?raw=true)

`Amel1a`

## Which user from the HR department was observed to be running scheduled tasks?

Do a search for schtasks.exe

![schtasks](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/benign/3.png?raw=true)

`Chris.fort`

## Which user from the HR department executed a system process (LOLBIN) to download a payload from a file-sharing host.

LOLBINs are "Living off the Land binaries", legitimate tools that can be used for malicious purposes.

On Windows, certutil.exe is a common binary that is abused for downloading files

![lolbin](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/benign/4.png?raw=true)

`haroon`

## To bypass the security controls, which system process (lolbin) was used to download a payload from the internet?

`certutil.exe`

## What was the date that this binary was executed by the infected host? format (YYYY-MM-DD)

`2022-03-04`

## Which third-party site was accessed to download the malicious payload?

`controlc.com`

## What is the name of the file that was saved on the host machine from the C2 server during the post-exploitation phase?

`benign.exe`

## The suspicious file downloaded from the C2 server contained malicious content with the pattern THM{..........}; what is that pattern?

Navigate to the download URL to evaluate the file

![suspicious file](https://github.com/TechnoSavage/CTF/blob/main/THM/walkthroughs/images/benign/5.png?raw=true)

`THM{KJ&*H^B0}`

## What is the URL that the infected host connected to?

`https://controlc.com/e4d11035`