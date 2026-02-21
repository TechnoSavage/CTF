# Whiterose

We get some initial clues that appear to be credentials
`Olivia Cortez:olivi8`

The episode plot of the Mr. Robot episode likely provides some clues as well; from this we know that our credentials reference Olivia Cortez, an employee at national cyprus bank

nmap reveals ssh on 22 and a webserver on port 80

connecting to 80 doesn't give us anything but the IP resolves to cyprusbank.thm, thanks to the page containing href.location="http://cyprusbank.thm"

we'll pop that in our /etc/hosts file and now we can bring up the page for the national bank of cyprus, which is under maintenance

let's try to further enumerate subdomains and/or directories on the webserver

gobuster doesn't have any luck with our common dirbuster or seclists wordlists but ffuf works a bit better with the following command:

`ffuf -u http://cyprusbank.thm/ -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.cyprusbank.thm" -fw 1`

Now we find "admin.cyprusbank.thm"...adding that to our /etc/hosts file allows us to browse there and we are greeted with a login page; a good place to try those creds.

A list of familiar names greets us and we appear so close to arriving at our first answer...

Q: What's Tyrell Wellick's phone number?

...but the number is obfuscated

The search tab offers us an input field however. A quick search shows that the search is being appended to the URL parameters. 
My first thought here is to try sqlmap but it's more simple than that. Similar to the search tab there is a messages tab as well. In the URL parameters there is a "c" value followed by an integer. Manually changing the integer affects how many of the prior messages are visible in the chat window. You can either change this to a fairly high number or set it to '0'. Either way it reveals something interesting...credentials for a privileged admin account.

`Gayle Bev: p~]P@5!6;rs558:q`

Just like that, the phone numbers are in clear text

```
842-029-5701
```

Now we need to compromise the machine to get...

Q: What is the user.txt flag?

We can try these new creds over SSH just to see if we get lucky. Olivia's didn't work for that and we'll find the case is the same for Gayle's.

Gayle does have permission to view something else that Olivia couldn't see though...the settings page; and it looks like we can reset passwords here.




