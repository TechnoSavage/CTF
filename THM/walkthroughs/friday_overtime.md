# Friday Overtime Walkthrough (easy)

Q: Who shared the malware samples?

Once logging into DocIntel the latest documents shows the most recent "Urgent" where the individual who shared the files introduces themselves as

```
Oliver Bennett
```

Q: What is the SHA1 hash of the file "pRsm.dll" inside samples.zip?

Download "samples.zip" from the above message

- unzip the archive with the provided password of `Panda321!`
- get the sha1 hash with the following command

```
9d1ecbbe8637fed0d89fca1af35ea821277ad2e8
```

Q: Which malware framework utilizes these DLLs as add-on modules?

- Search the SHA1 hash on Virustotal; the top returned entries mention family labels of `MgBot`

```

```

Q: Which MITRE ATT&CK Technique is linked to using pRsm.dll in this malware framework?

- Some additional research was needed to figure out which of the techniques pRsm.dll factors into within the mgbot malware.
- Some googling returns an [ESET article](https://www.welivesecurity.com/2023/04/26/evasive-panda-apt-group-malware-updates-popular-chinese-software/) discussing the campaign by Evasive Panda/BRONZE HIGHLAND/Daggerfly and this breaks down the plugin usage 
- In this context pRsm.dll was used for capturing input and output audio streams so the Mitre technique ID is...

```
T1123
```

Q: What is the CyberChef defanged URL of the malicious download location first seen on 2020-11-02?

- The same article mentions the first observed URL link earlier on
- Drop the URL in Cyberchef with Defang URL to get the needed format...

```
hxxp[://]update[.]browser[.]qq[.]com/qmbs/QQ/QQUrlMgr_QQ88_4296.exe	
```

What is the CyberChef defanged IP address of the C&C server first detected on 2020-09-14 using these modules?

- This article is a wealth of knowledge and documents the know C2 server IPs with dates; we just need to pop a few braces around the remaining periods

```
122[.]10[.]90[.]12
```

What is the md5 hash of the spyagent family spyware hosted on the same IP targeting Android devices in Jun 2025?

- Back to Virustotal to search the C2 IP we just found
- Under the relations tab, click on the Name of the  Type = Android entry listed
- Switch to details tab to grab the MD5 hash

```
951f41930489a8bfe963fced5d8dfd79
```