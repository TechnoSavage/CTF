[OpTinselTrace-1](https://github.com/TechnoSavage/CTF/blob/main/HTB/Sherlocks_writeups/operation_tinseltrace.md#optinseltrace-1)


# OpTinselTrace-1

## Description: 

<p>An elf named "Elfin" has been acting rather suspiciously lately. He's been working at odd hours and seems to be bypassing some of Santa's security protocols. Santa's network of intelligence elves has told Santa that the Grinch got a little bit too tipsy on egg nog and made mention of an insider elf! Santa is very busy with his naughty and nice list, so he’s put you in charge of figuring this one out. Please audit Elfin’s workstation and email communications.</p>

## 1: What is the name of the email client that Elfin is using?

- Open elfidence_collection > TriageData > C > Users > Elfin > appData > Roaming to see list of application data
- **eM Client** contains data pertaining to email

### Answer: `eM Client`

## 2: What is the email the threat is using?

- I opted to get a Powershell console and a Debian Linux shell (WSL) open to help navigate the data and work with files

- Linux
```
cd eM\ Client/Local\ Folders
sqlite3 contact_index.dat
.tables
.schema ContactEmailIndex
select email from ContactEmailIndex;
    customerserviceteam@waitrose.co.uk
    elfuttinmastermind@yahoo.com
    melfinsuperstar@proton.me
    definitelynotthegrinch@gmail.com
```
- The Grinch looks obvious and fits the theme; let's try it...


### Answer: `definitelynotthegrinch@gmail.com`

## 3: When does the threat actor reach out to Elfin?

<p>Rapidly realizing that using the sqlite3 cli was going to take a long time I installed **db browser for sqlite**; this makes it much faster to search through the .dat files in order to find interesting information.</p>

- After some searching I came across `elfidence_collection/TriageData/C/users/Elfin/Appdata/Roaming/eM Client/32969170-c98d-4a48-b444-526374e467e4/23848ff4-bf57-4577-bdb7-06e8a178560d/mail-fti.dat` which contains the email messages in readable format

- Filter the messages with the attacker email above

- The first message from the attacker has a timestamp of `27/11/2023 17:27:26`

### Answer: `2023-11-27 17:27:26`

## 4: What is the name of Elfin's boss?

- Scrolling through the entries in the same database a message starting with **"ok boss"** stands out

- reviewing the message it appears that Elfin's boss's name is `elfuttin bigelf` with an email of `elfuttinmastermind@yahoo.com`

### Answer: `elfuttin bigelf`

## 5: What is the title of the email in which Elfin first mentions his access to Santas special files?

- In the email string starting with **"Hi Wendy"** Elfin mentions having access to the secret file to Wendy (the Grinch); this is in a response and subject is **"work"**

- To reliably get the full email subject lines we will have to reference the main-index.dat file in the same folder or switch to the MailSubjectIndex in **mail-fti.dat**

- Cross referencing between the two we locate the reply message and see the subject is (logically) `re: work`

### Answer: `re: work`

## 6: The threat actor changes their name, what is the new name + the date of the first email Elfin receives with it?

- Again, scanning the email previews in **mail-index.dat** or the message contents in **mail-fti.dat** we come across a message starting with **"what happened to your name?"**

- It seems that the Grinch posing as Wendy has been sending email with the name `Grinch Grincher` but signing as Wendy since the beginning. After Elfin notices this the Grinch changes the name to `Wendy Elflower` claiming that friends were playing a prank

- The timestamp for the first email under this new nom de plume is `28/11/2023 10:00:21` in the email with subject **"binaries"** 

### Answer: `Wendy Elflower, 2023-11-28 10:00:21`

## 7: What is the name of the bar that Elfin offers to meet the threat actor at?

- In the continuance of the conversation above Elfin suggests the `SnowGlobe` bar for a mean eggnog after exclaiming that the name change joke was funny

### Answer: `SnowGlobe`

## 8: When does Elfin offer to send the secret files to the actor?

- We can get the timestamp for Elfin's offer to Grinch/Wendy in the email starting with **"Definitely!"** `28 Nov 2023 at 16:56`

- Unfortunately, we're missing the seconds for this one so, having identified the message, we have to find the complete timestamp elsewhere (or brute force the last digits)

### Answer: `2023-11-28 16:56:13`

## 9: What is the search string for the first suspicious google search from Elfin? (Format: string)

- On Windows, Chrome stores the browser history in `Appdata\Local\Google\Chrome\User Data\History` and it just so happens we can open this file with sqlite as well

- The `cluster_keywords` table has the info we need for this question

- Arguably things start to look fishy regarding the VPN but if we try a few in the answer field we find it is `how to get around work security` that HTB is looking for.

### Answer: `how to get around work security`

## 10: What is the name of the author who wrote the article from the CIA field manual?

- Switching to the urls table will make it easy to identify where the CIA field manual was hosted

- We find it at `https://www.corporate-rebels.com/blog/cia-field-manual`

- Visiting the site we quickly ascertain the article author's name

### Answer: `Joost Minnaar`

## 11: What is the name of Santas secret file that Elfin sent to the actor?

- This is in the `Appdata\Roaming\top-secret` folder

### Answer: `santa-deliveries.zip`

## 12: According to the filesystem, what is the exact CreationTime of the secret file on Elfins host?

- Using Eric Zimmerman's **MFTEcmd** will help with this one but it's worth grabbing all of his tools: https://www.sans.org/tools/ez-tools/

- In Powershell
    cd <location\of\MFTEcmd.exe>
    .\MFTEcmd.exe -f \elfidence_collection\TriageData\C\$MFT --csv <path\to\save\file>

- Open CSV output and filter by `santas_deliveries`; the timestamp under the `LastAccess0x10` provides the answer

- Alternatively you can use **MFT Explorer** for a graphical interface but MFTEcmd is significantly faster

### Answer: `2023-11-28 17:01:29`

## 13: What is the full directory name that Elfin stored the file in?

- As mentioned above the secret zip archive can be found here 

### Answer: `C:\users\Elfin\Appdata\Roaming\top-secret`

## 14: Which country is Elfin trying to flee to after he exfiltrates the file?

- This is also found in the browser history as Elfin searches for nicer climates and travel arrangements

### Answer: `Greece`

## 15: What is the email address of the apology letter the user (elfin) wrote out but didn’t send?

- While browsing during the above exercises I came across an, apparently, unfinished email message where a guilt-ridden Elfin apologizes to Santa for what he is about to do. In the **mail_index.dat** database and **MailItems** table we see the subject for this is **"I can't do this"**, note the ID is `50`.

- By switching to the **MailCategoryNames** table and referencing **ID 50** we can see that this email has a category name of **\Draft**, confirming it was never sent.

- Switching to the **MailAddresses** table we can filter the list of email addresses by `santa` (there is no display name associated) to return the answer

### Answer: `Santa.claus@gmail.com`

## 16: The head elf PixelPeppermint has requested any passwords of Elfins to assist in the investigation down the line. What’s the windows password of Elfin’s host?

- We have a copy of the **SAM**, **SYSTEM**, and **SECURITY** files so we can extract hashes `\elfidence_collection\TriageData\C\Windows\system32\config\SAM`

- I copied the above 3 files to my Kali VM where I already had **impacket** and **hashcat** ready

```
python3 ./secretsdump.py -sam /path/to/SAM -security /path/to/SYSTEM -system /path/to/SYSTEM LOCAL -outputfile elfidence_hashes

[*] Target system bootKey: 0x1679d0a0bee2b5804325deeddb0ec9fe
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:95199bba413194e567908de6220d677e:::
Elfin:1001:aad3b435b51404eeaad3b435b51404ee:529848fe56902d9595be4a608f9fbe89:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] Cleaning up...
```
- Now we can crack the hashes with **hashcat** and, fortunately, **rockyou.txt** works for this
```
hashcat -m 1000 /path/to/elfidence_hashes.sam /path/to/wordlists/rockyou.txt

529848fe56902d9595be4a608f9fbe89:Santaknowskungfu
```

### Answer: `Santaknowskungfu`

