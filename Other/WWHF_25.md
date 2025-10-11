
## Badge CTF (23 challenges in all)

### Boot animation clues

```
MSFT(R) Win NT(TM)
(C)1985-96 MSFT Corp
C:\> net user Admin
User name      Admin
Full Name      Admin
Comment     L3tM31n!
User's comment
```

```
root@bt# ./warvox.rb
[*] Starting WarVOX
  << back | track 5
FALKEN'S MAZE
DESERT WARFARE
GLB THERMONUCLEAR WAR
```

```
MAIN  i5/OS Main Menu
Select one:
  1. User tasks
  2. iSeries Access
  3. Sign off
```

```
PPP  DDD  PPP   1  1 
P  P D  D P  P 11 11 
p  p D  D P  P  1  1 
PPP  D  D PPP   1  1 
P    D  D P     1  1 
p    D  D P     1  1 
P    DDD  P    111111
```

```
*** commodore  64 ***
64k ram system 10    
load"*",8,1:
searching for *
The Oregon Trail
---------------------
1. Travel the Trail
2. Learn the Trail
3. See the Top Ten
4. Turn sound off
```

```
Rtr#                 
Rtr# config term     
Rtr(config)# snmp-ser
ver community pub RO 
ver community priv RW
Rtr(config)# exit    
Rtr# copy run sta
```

```
root@kali# msfconsole
msf> use ms08-067
msf> exploit
[*] Meterpreter sessi
on 1 opened
msf> session -i 1
```

```
z/OS Z110 Level 8415 
    App Dev System   
         / OOO   SSS
        / O   O S   
  ZZZZ / O   O SSS  
   // / O   O    S  
 //  / O   O    S   
ZZZZ/  OOO  SSSS  
```

```
The IBM PC DOS       
Ver 1.10 (C)IBM 1981 
COMMAND COM SYS   COM
DEBUG   COM COMP  COM
DONKEY  BAS LINK  EXE
COMM    BAS BASIC COM
```

```
Error loading OS     
BOOTMGR is missing   
Press Ctrl+Alt+Del to
No boot device found 
F1 to retry boot.    
F2 for setup utility.
F5 for diagnostics.
```

```  
bash-3.2$ uname -a   
Darwin BHIS-MacBook-P
ro.local 15.4.0 Darwi
n Kernel Version 15.4
.0: Fri Feb 26 22:08:
05 CST 2016; root:xnu
-3248.40.184~3/RELEAS
E_X86_64 x86_64
```

```
MAN(1)    Manual Page
  man - an interface
  to the system refer
  ence manuals
  man [man options] [[
```

```
(gdb) disas main
Dump of assembler cod
e for function main: 
0x1135 +0: push %rbp 
0x1136 +1: mov %rsp,%
0x1139 +4: sub $0x10,
0x113d +8: movl $0x0,
0x1144 +15: jmp 0x115
```

```
Copyright (C) 1985   
Commodore-Amiga, Inc.
All rights reserved. 
Version 27.3         
Use DATE to set date 
Sun 01-Apr-90 03:11  
      c (dir)
```

```
# sshnuke 10.2.2.2 -r
ootpw="Z10N0101"   
Conn to 10.2.2.2:ssh 
Exploit SSHv1 CRC32  
Reset pw "Z10N0101"
Sys open: Level (9)  
[*] Success
```

```
# ssh root@10.2.2.2  
 /       \
((--,,,--))
 {} 0 0 {}______
   \ _ /        |\
    o_o\  MSF   | \
        \ ____  |  *
         ||  WW||
```

```
 TO SCAN FOR CARRIER 
  TONES, PLEASE LIST 
 DESIRED AREA CODES  
    AND PREFIXES     
AREA                 
CODE  PRFX NUMBER    
(311) 399-0001
```

```       
        -----        
      /       \      
     |  0   0  |     
     |    ^    |     
     | \     / |     
     |   ---   |     
      \       / 
```

### Binary light display and Morse code

- Press top left button; LCD displays "initializing keyboard" (this prints an encoded string to console output)
-  the row of 8 LEDs flash the binary sequence
`10001111 10110111 10010110 10001100 10110111 10010110 10010001 10111000`

- converting to ascii is gibberish
- XOR the bits
01110000 01001000 01101001 01110011 01001000 01101001 01101110 01000111`

```
pHisHinG
```

- after the binary display the LED light flashes morse code in red
-.- .-. .- -.-. -.- . -.. 

```
KRACKED
```
### Ciphers displayed cycling lower right button

`Ovgr gvy Ohyyrg`

Rot13 

```
Bite the Bullet
```

`Gwjfp ymj nhj`

Rot47

```
Break the ice
```

`INZHSIDPOZSXEIDTOBUWY3DFMQQG22LMNM======`

Base

```
Cry Over Spilled Milk
```

`QmlyZCBpbiAgdGblICBoYW5k`

```
Bird in the Hand
```

`abaab baaaa babbaabbba baaba abbab`

Bacon Cipher "A|B"

```
KRYPTO
```

nRF Connect to device to find 3 services

- One states "--Crack the hash--"
The other two are hashes, both SHA1 

cdc5b000862320da91e4d66bc33792aabc224ff3 

*look into this one*

```
darkimage
```

f70f63def2543f77ff268579dd6ece12d0f7fc78

```
accessit
```

### JTAG/UART 

#### Boot screen

```
# VXpJMWRtUXllR3hhUjJSc1NVZHNla2xJUW5aa01sWjVTVkU5UFE9PQ==
#
3 Characteristics defined! Now you can read it in your phone!
ESP-ROM:esp32s3-20210327
Build:Mar 27 2021
rst:0x15 (USB_UART_CHIP_RESET),boot:0x8 (SPI_FAST_FLASH_BOOT)
Saved PC:0x420a0c0a
SPIWP:0xee
mode:DIO, clock div:1
load:0x3fce3808,len:0x4bc
load:0x403c9700,len:0xbd8
load:0x403cc700,len:0x2a0c
entry 0x403c98d0
# VXpJMWRtUXllR3hhUjJSc1NVZHNla2xJUW5aa01sWjVTVkU5UFE9PQ==
#
3 Characteristics defined! Now you can read it in your phone!
```

*note* the reference here that there are the 3 services available via nRF BLE

Plug is USB to access UART over serial 6400 8N1 | 115200 8N1

- Displays a base64 encoded string at boot and anytime the top left button is pressed (LCD displays "keyboard initializing")

Base64 decode three times to get

```
Knowledge is power!
```

Proceeds to scrolling values on screen which are readouts from the photodiode

USB JTAG interface

- dump flash with esptool


### Photodiode

- Covering photodiode reveals semaphore (this appears to happen when read values <= 40)

```
PIRATES OFF THE PORT BOW
```

- Shining bright light reveals a pigpen cipher (this appears to occur when read values >=4000)

```
SNORT IS IN MY SECURITY PIGPEN
```

### Serial Error captured when trying to connect to BLE

```
E (54409) BT_SMP: smp_calculate_link_key_from_long_term_key failed to update link_key. Sec Mode = 2, sm4 = 0x00
2301
E (54409) BT_SMP: smp_derive_link_key_from_long_term_key failed

E (54415) BT_BTM: btm_proc_smp_cback received for unknown device
2309
E (54528) BT_BTM: Device not found
```

### Components Recon

- Chip just above power switch is a [BCDSEMI GH12E CMOS](https://www.alldatasheet.com/datasheet-pdf/pdf/453682/BCDSEMI/GH12E.html) (voltage regulator)
- Top left beside LCD is a photodiode
- ESP32 at bottom center 
- Flash chip (mid-board far left)
