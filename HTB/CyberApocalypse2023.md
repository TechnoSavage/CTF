PWN:
    Initialise Connection:
        nc 165.232.100.46 30002
        HTB{g3t_r34dy_f0r_s0m3_pwn}

    Questionnaire:
        nc 165.232.98.69 30697
        64-bit
        Dynamic
        vuln()
        0x20
        gg()
        fgets()
        40
        gdb ./test -> gdb p gg
        0x401176
        HTB{th30ry_bef0r3_4cti0n}

    

Web:
    Trapped Source:
        Keypad PIN hardcoded in page source:
            
            window.CONFIG = window.CONFIG || {
                buildNumber: "v20190816",
                debug: false,
                modelName: "Valencia",
                correctPin: "8291",
            }

        HTB{V13w_50urc3_c4n_b3_u53ful!!!}

    Gunhead:
        Source reveals that user input is passed directly to curl command via ping command
        execute arbitrary commands by appending to ping e.g. /ping localhost; whoami
        flag in /flag.txt -> /ping localhost; cat /flag.txt
        HTB{4lw4y5_54n1t1z3_u53r_1nput!!!}

    Drobots:
        Bypass login with SQL injection
        username: " or ""="
        password: " or ""="    
        HTB{p4r4m3t3r1z4t10n_1s_1mp0rt4nt!!!}

    Passman:


Forensics:

    Plaintext Treasure:
            Open wireshark
            Statistics -> Conversations (only two endpoints)
            tab TCP, notice port 1337
            Filter tcp.port == 1337 && http
            first packet is POST/token -> follow HTTP stream
            password is HTB{th3s3_4l13ns_st1ll_us3_HTTP}

    Alien Cradle:
            Open powershell script, find this line:
            'H' + 'T' + 'B' + '{p0w3rs' + 'h3ll' + '_Cr4d' + 'l3s_c4n_g3t' + '_th' + '3_j0b_d' + '0n3}
            Remove '+' signs and concatenate string:
            HTB{p0w3rsh3ll_Cr4dl3s_c4n_g3t_th3_j0b_d0n3}

Crypto:
    Ancient Encodings:
        Python script shows input text is base64 encoded then converted to hex:
        Use python or cyberchef or another tool:
        convert hex to string (from hex)
        base64 decode
        HTB{1n_y0ur_j0urn3y_y0u_wi1l_se3_th15_enc0d1ngs_ev3rywher3}
        
Reversing:
    Hunting License
        nc 206.189.112.129 31332 (questionnaire)
        Answers:
        elf
        x86_64
        libreadline.so.8 (ldd license | strings license | ghidra)
        00401172 (memory address of main, gdb license -> info functions | ghidra)
        5 (how many puts in main, gdb or ghidra)
        PasswordNumeroUno (strings license)
        0wTdr0wss4P (strings license)
        P4ssw0rdTw0 (reverse above)
        Third pass:
        G{zawR}wUz}r (strings license)
        0x13 (XOR key for above, cyberchef XOR brute force)
        ThirdAndFina.. (first half of password(?))
