# The Greenholt Phish (easy)

Q: What is the Transfer Reference Number listed in the email's Subject?

There are lots of ways to view the email content but given the file provided in the challege, I just like to use the CLI

The email can also be opened in Thunderbird for a more colorful experience

```
$cd ~/Desktop
$cat challenge.eml | grep -i subject

Subject: webmaster@redacted.org your: Transfer Reference Number:(09674321)
```

`09674321`

Q: Who is the email from?

```
$cat challenge.eml | grep -i from
X-Atlas-Received: from 10.201.192.162 by atlas125.free.mail.bf1.yahoo.com with http; Wed, 10 Jun 2020 05:58:55 +0000
Received: from x.x.x.x (EHLO sub.redacted.com)
 spf=fail smtp.mailfrom=mutawamarine.com;
Received: from 10.197.41.148  (EHLO sub.redacted.com) (x.x.x.x)
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810 helo=mutawamarine.com)
	(envelope-from <info@mutawamarine.com>)
From: "Mr. James Jackson" <info@mutawamarine.com>
 -0.9 AWL                    AWL: Adjusted score from AWL reputation of From: address
><span style=3D"vertical-align: inherit;">From Account: 3105234819</span></=
```

`Mr. James Jackson`

Q: What is his email address?

See above

`info@mutawamarine.com`

Q: What email address will receive a reply to this email? 

```
$cat challenge.eml | grep -i reply-to
Reply-To: "Mr. James Jackson" <info.mutawamarine@mail.com>
```

`info.mutawamarine@mail.com`

Q: What is the Originating IP?

refer back to the above "from" output

`192.119.71.157`

Q: Who is the owner of the Originating IP? (Do not include the "." in your answer.)

This is hinted at in the email "Received" fields but a whois lookup on the IP provides the actual answer

*Note* this seems to be case sensitive when entering

`Hostwinds LLC`

Q: What is the SPF record for the Return-Path domain?

Use an online tool to look up the SPF record for *info@mutawamarine.com*

I used mxtoolbox.com

`v=spf1 include:spf.protection.outlook.com -all`

Q: What is the DMARC record for the Return-Path domain?

As I'm using mxtoolbox.com, I just switch my search to DMARC lookup

`v=DMARC1; p=quarantine; fo=1`

Q: What is the name of the attachment?

```
$cat challenge.eml | grep -i attachment
Content-Disposition: attachment; filename="SWT_#09674321____PDF__.CAB"
```

`SWT_#09674321____PDF__.CAB`

Q: What is the SHA256 hash of the file attachment?

Ok, at this point it's faster to open the email in Thunderbird to get the attachment

Download to the desktop (or some other location)

```
sha256sum SWT_#09674321____PDF__.CAB 
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f  SWT_#09674321____PDF__.CAB
```


`2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

Q: What is the attachments file size? (Don't forget to add "KB" to your answer, NUM KB)

Take that sha256 hash and drop it into VirusTotal

`400.26 KB`

Q: What is the actual file extension of the attachment?

```
$file SWT_#09674321____PDF__.CAB
SWT_#09674321____PDF__.CAB: RAR archive data, v5
```

`RAR`
