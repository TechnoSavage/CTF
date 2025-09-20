# tshark challenge 1: Teamwork

Q: What is the full URL of the malicious/suspicious domain address (defanged)?

- knowing that we are looking for domains start by filtering DNS queries

`tshark -r teamwork.pcap -Y "dns"`

- Immediately a suspect domain appears; it purports to be for a Paypal account recovery though the TLD is actually timeseawas.com

- Searching this domain is virustotal confirms it is a known malicious domain

defanged domain
```
www[.]paypal[.]com4uswebappsresetaccountrecovery[.]timeseaways[.]com
```

Q: When was the URL of the malicious/suspicious domain address first submitted to VirusTotal?

- searching VirusTotal once more as a URL (add http://) and looking under the "details" tab for the first submission date we find

```
2017-04-17 22:52:53 UTC
```
Q: Which known service was the domain trying to impersonate?

- As noted above the domain is clearly trying to impersonate...

```
paypal
```

Q: What is the IP address of the malicious domain (defanged)?

- Back to searching this as a domain; switch to the "relations" tab and the resolved IP can be seen 

```
184[.]154[.]127[.]226
```

Q: What is the email address that was used(defanged)?

- I found this question unclear as to what email it is after, initially thinking it wanted the registrant email (which incidentially can be found toward the bottom of the "Relations" tab in the historical whois lookup). Rather, what it is asking for is the email that was phished in the PCAP...back to tshark!

- We should be able to filter for the malicious IP and HTTP POST methods to find form submission data, indeed this filter returns only two packets. Adding the `-V` for verbose allows us to see the request data where the email stands out. Passing this to a simple grep for '@' is even faster

`tshark -r teamwork.pcap -Y 'ip.dst==184.154.127.226 && http.request.method=="POST"' -V`

`tshark -r teamwork.pcap -Y 'ip.dst==184.154.127.226 && http.request.method=="POST"' -V | grep @`

```
johnny5alive[at]gmail[.]com
```