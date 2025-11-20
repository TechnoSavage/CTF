# Snapped Phish-ing Line (easy)

Q: Who is the individual who received an email attachment containing a PDF?

grep each email for "\.pdf" (to key off the file extension)

We get a hit on the Quote email 

```
$cat Quote\ for\ Services\ Rendered\ processed\ on\ June\ 29\ 2020\ 100132\ AM.eml | grep "\.pdf"
Content-Type: text/html; name="Quote.pdf"
```

Now we need the name of the person that received the email 

```
$cat Quote\ for\ Services\ Rendered\ processed\ on\ June\ 29\ 2020\ 100132\ AM.eml | grep To:
 i=goudo-k@po3.across.or.jp;	bh=cnwJ7WfEMCDPZ2GATvJORtH2t6HFtZ/E9HM2qt2JIRE=;h=Content-Type:From:To:Subject:Message-ID:Date:MIME-Version;	b=cgJW+4kMBHinVuKmA8Ru1aMH3qgb9F9QXLvO2LsrROxsnVgoB6zuyQpOEYrL1H6VQ	
To: "William McClean" <william.mcclean@swiftspend.finance>
```

`William McClean`

Q: What email address was used by the adversary to send the phishing emails?

```
$cat Quote\ for\ Services\ Rendered\ processed\ on\ June\ 29\ 2020\ 100132\ AM.eml | grep -A2 From:
 i=goudo-k@po3.across.or.jp;	bh=cnwJ7WfEMCDPZ2GATvJORtH2t6HFtZ/E9HM2qt2JIRE=;h=Content-Type:From:To:Subject:Message-ID:Date:MIME-Version;	b=cgJW+4kMBHinVuKmA8Ru1aMH3qgb9F9QXLvO2LsrROxsnVgoB6zuyQpOEYrL1H6VQ	
 U/ThdHIrmVhBcjXRF8avzy/zdrr4XZZnj2tr+YhyQCZ0zQ7IApAJTWN9EGBmrbiO0g	
 WdRYInwsVNmhLGyYj2JR/4o7QYMbAm1tYYhfFBMNB0CkdrUZI5WQ73no5CRuOkMlaw	
--
From: "Group Marketing Online Accounts Payable"
 <Accounts.Payable@groupmarketingonline.icu>
To: "William McClean" <william.mcclean@swiftspend.finance>
```

`Accounts.Payable@groupmarketingonline.icu`

Q: What is the redirection URL to the phishing page for the individual Zoe Duncan? (defanged format)

Let's open this email in Thunderbird and download the attached html file to our Phishing folder

then we can cat the contents

```
$cat Direct\ Credit\ Advice.html 
\<!DOCTYPE hxxl>
\<html>
\<head>
	\<title>Redirecting. . .\</title>
	\<meta http-equiv="refresh" content="0;URL='http://kennaroads.buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe.duncan@swiftspend.finance&error'" />
\</head>
\<body>
	\<h1>Redirecting. . .</h1>
	\<p>If you are not redirected automatically, please click \<a href="http://kennaroads.buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe.duncan@swiftspend.finance&error">here\</a>.\</p>
\</body>
\</html>
```

That's a sizable URL so I dropped it in CyberChef for a quick 'Defang URL'

`hxxp[://]kennaroads[.]buzz/data/Update365/office365/40e7baa2f826a57fcf04e5202526f8bd/?email=zoe[.]duncan@swiftspend[.]finance&error`

Q: What is the URL to the .zip archive of the phishing kit? (defanged format)

Take the above URL and start working from the root forward

in the /data directory we find a zip 

copy the link location and defang to get...

`hxxp[://]kennaroads[.]buzz/data/Update365[.]zip`

Q: What is the SHA256 hash of the phishing kit archive?

Let's grab the zip now and grab a sha256 hash

```
$sha256sum Update365.zip 
ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686  Update365.zip
```

`ba3c15267393419eb08c7b2652b8b6b39b406ef300ae8a18fee4d16b19ac9686`

Q: When was the phishing kit archive first submitted? (format: YYYY-MM-DD HH:MM:SS UTC)

Now let's drop that hash into VirusTotal, switch to the details tab and take the "First Submission" date found under "History"

`2020-04-08 21:55:50 UTC`

Q: When was the SSL certificate the phishing domain used to host the phishing kit archive first logged? (format: YYYY-MM-DD)

At the time of this writing the SSL cert is no longer available as the hint tells us. The hint also provides the answer

`2020-06-25`

Q: What was the email address of the user who submitted their password twice?

For this we need to go back to the website and navigate to the logs found at hxxp[://]kennaroads[.]buzz/data/Update365/log.txt

We'll find that Michael Ascot was persistent in trying to log in to the phishing site

`michael.ascot@swiftspend.finance`

Q: What was the email address used by the adversary to collect compromised credentials?

Now we need to actually dig into the contents of that zip archive

PHP scripts seem like a good place to look for any traces the attacker may have left and sure
enough, in Update365/office365/Validation/submit.php we can see that the harvested creds were forwarded to...

`m3npat@yandex.com`

Q: The adversary used other email addresses in the obtained phishing kit. What is the email address that ends in "@gmail.com"?

This is found in Update365/office365/script.st 

Knowing that we are hunting for a gmail address, I started grepping the files for 'gmail' to locate this one

`jamestanner2299@gmail.com`

Q: What is the hidden flag?

Following the same thought process as the previous question; we know from the answer format that the flag likely starts with "THM{" so grepping for that should get us to the goal

However, the flag isn't in the ZIP archive contents but rather on the fishing site

With a little investigate enumeration we can find flag.txt at 

http://kennaroads.buzz/data/Update365/office365/flag.txt

it contains a base64 encoded string

fUxSVV8zSHRfaFQxd195NExwe01IVAo=

so a quick decode 

```
$echo fUxSVV8zSHRfaFQxd195NExwe01IVAo= | base64 -d
}LRU_3Ht_hT1w_y4Lp{MHT
```
and we get the flag in reverse...ok, let's make a minor modification to our command...

```
$echo fUxSVV8zSHRfaFQxd195NExwe01IVAo= | base64 -d | rev
THM{pL4y_w1Th_tH3_URL}
```

`THM{pL4y_w1Th_tH3_URL}`
