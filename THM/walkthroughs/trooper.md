# Trooper Walkthrough (easy)

Q: What kind of phishing campaign does APT X use as part of their TTPs?

- Read the provided report

```
spear-phishing emails
```

Q: What is the name of the malware used by APT X?

```
USBferry
```

Q: What is the malware's STIX ID?

- Over to OpenCTI, search for USBferry and open the malware entry

```
malware--5d0ea014-1ce9-5d5c-bcc7-f625a07907d0
```

Q: With the use of a USB, what technique did APT X use for initial access?

- In ATT&CK Navigator search for USBferry to highlight the relevant techniques
- The Initial Access technique that is highlighted is...

```
Replication Through Removable Media
```

Q: What is the identity of APT X?

- The OpenCTI entry for USBferry explains that it is malware employed by...

```
Tropic Trooper
```

Q: On OpenCTI, how many Attack Pattern techniques are associated with the APT?

- Search Tropic Trooper in OpenCTI and switch to the knowledge tab to find that the number of attack pattern techniques is...

```
39
```

Q: What is the name of the tool linked to the APT?

- Click on Tools under Arsenal in the right sidebar to get the name...

```
BITSAdmin
```

Q: Load up the Navigator. What is the sub-technique used by the APT under Valid Accounts?

- Search Tropic Trooper and click 'vew' for the threat group entry
- Scroll to Valid Accounts to find the subtechnique T1078.003 which is...

```
Local Accounts
```

Q: Under what Tactics does the technique above fall?

- Click on the Local Accounts link to find the associated tactics

```
Initial Access, Persistence,  Defense Evasion and Privilege Escalation
```

Q: What technique is the group known for using under the tactic Collection?

- Highlighted in ATT&CK Navigator for Tropic Trooper

```
Automated Collection
```