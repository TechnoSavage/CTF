# Name: Canvas
## Category: Misc 
## Difficulty: Easy
## Description: We want to update our website but we are unable to because the developer who coded this left today. Can you take a look?

### Download and extract zip archive that contains the web page files
- Browsing through the archive we see the dashboard and index HTML documents, the CSS folder containing the stylesheet, and the JS folder with the ```login.js``` script...interesting...
- Opening the ```login.js``` in an editor we can quickly see that all variables and strings are represented in hex
- Copy the contents and drop them directly into Cyberchef and add the "From Hex" operation
- This doesn't product the cleanest output but is sufficient for the purpose at hand
- Adding "Generic Code Beautify" helps with readability
- Scanning through the deobfuscated hex values the flag can be seen at the end of the script
```HTB{W3Lc0m3_70_J4V45CR1p7_d30bFu5C4710N}```