# Name: Debugging Interface 
## Category: Hardware 
## Difficulty: Very Easy

### Download and extract zip archive that contains ```debugging_interface_signal.sal```
- .sal is the file extension for Saleae Logic
- Open Saleae Logic 2.x.x
- File > Open Capture > debugging_interface_signal.sal
- Switch to Analyzers
- From the challenge description we know that async serial is the appropriate analyzer to use
- Toggle Data to terminal output
- Zoom into the start of the transmission
- The first block of data measures at 32.02 microseconds (hover within block)
- Baud rate is measured in bits per second so let's try calculating this value in bits/s and selecting the closest baud rate
- 1 microsecond = 0.000001 seconds -> 1,000,000/32.03 = 31,230.48
- Click three dot menu beside analyzer name
- Make sure that "stream to terminal" and "ASCII" are checked
- click "edit"
- Set Baud rate to 31,230 and click save (this is using the default 8N1 with no parity bits which is the most common serial setting)
- The terminal output now shows a series of messages with the last message containing the flag
```HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}```