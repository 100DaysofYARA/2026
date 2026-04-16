import "console"
import "pe"
rule bunnyLoader_granular {
    meta:
        author = "gavin"
        sha256 = "90e6ebc879283382d8b62679351ee7e1aaf7e79c23dd1e462e840838feaa5e69"
    strings:
        $hf1 = "/Bunny/TaskHandler.php?CommandID=" nocase ascii wide
        $hf2 = "/Bunny/Echoer.php" nocase  ascii wide
        $hf3 = "BunnyLoader" nocase  ascii wide
        $hf4 = "BunnyShell"  nocase  ascii wide
        $hf5 = "BunnyRequester" nocase ascii wide
        $hf6 = "\\BunnyLogs\\" nocase ascii wide
        $pdb = "\\Release\\Bunny.pdb" nocase ascii wide          
    condition:
        3 of ($hf*) and $pdb
}
rule bunnyLoader_granular_u {
    meta:
        author = "gavin"
        sha256 = "90e6ebc879283382d8b62679351ee7e1aaf7e79c23dd1e462e840838feaa5e69"
    strings:
        $hf1 = "/Bunny/TaskHandler.php?CommandID=" nocase wide 
        $hf2 = "/Bunny/Echoer.php" nocase  wide
        $hf3 = "BunnyLoader" nocase wide    
        $hf4 = "BunnyShell"  nocase wide
        $hf5 = "BunnyRequester" nocase wide
        $hf6 = "\\BunnyLogs\\" nocase wide
        $pdb = "C:\\Users\\user\\Desktop\\Bunny\\Bunny\\Release\\Bunny.pdb" nocase          
    condition:
        3 of them
}

/* notes

\Download
p870\rijndael_simd.c(
ANYRUN




C:\Users\user\Downloads\cryptopp870\rijndael_simd.cpp
6C:\Users\user\Downloads\cryptopp870\gcm_simd.cpp
C:\Users\user\Downloads\cryptopp870\sha_simd.cpp
C:\Users\user\Downloads\cryptopp870\gf2n_simd.cpp
C:\Users\user\Downloads\cryptopp870\sse_simd.cpp
I want to sleep to forget
Successfully moved to a new directory -->
BunnyLoader_
\AppData\Local\
C:\Users\
Download & Execute (Disk Execution)
TaskCompleted
&BotID=
http://37.139.129.145/Bunny/TaskHandler.php?CommandID=
Download & Execute (Fileless Execution)
exec
Bitcoin
Received Bitcoin command
^bc1[0-9a-zA-HJ-NP-Z]{25,39}$
Monero
^4([0-9]|[A-B])(.){93}
Ethereum
^0x[0-9a-fA-F]{40}$
Litecoin
^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$
Dogecoin
^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$
ZCash
(t1[0-9a-zA-Z]{33})|(zaddr1[0-9a-zA-Z]{76})
Tether (USDT)
^0x[a-fA-F0-9]{40}$
Run Stealer
Recovery command recived
Run Keylogger
CLIPPED
BunnyTasks
http://37.139.129.145/Bunny/Echoer.php
http://37.139.129.145/Bunny/ResultCMD.php
BunnyShell
HeartBeat_Sender
http://37.139.129.145/Bunny/Heartbeat.php
http://37.139.129.145/Bunny/TaskHandler.php?BotID=
BunnyLoader
http://37.139.129.145/Bunny/Add.php

BunnyRequester
http://ip-api.com/csv
http://api.ipify.org

wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName /value

\AppData\Local\BunnyLogs\Messages\Skype
\AppData\Local\BunnyLogs\Messages\Local Storage
\AppData\Roaming\Microsoft\Skype for Desktop\Local Storage
\AppData\Local\ngrok
\AppData\Local\BunnyLogs\ngrok.yml
\AppData\Local\ngrok\ngrok.yml
\AppData\Local\BunnyLogs\ngrok not found
ngrok not installed
\AppData\Local\ProtonVPN
\AppData\Local\BunnyLogs\VPNs\ProtonVPN
ProtonVPN.exe
\AppData\Local\BunnyLogs\VPNs\ProtonVPN\
\user.config
\AppData\Roaming\OpenVPN Connect\profiles
\AppData\Local\BunnyLogs\VPNs\OpenVPN
.ovpn
\AppData\Local\BunnyLogs\VPNs\OpenVPN\
\AppData\Local\Keystrokes.txt
');"
.zip
\AppData\Local\BunnyLogs_

\AppData\Local\BunnyLogs
\AppData\Local\BunnyLogs\Browser
\AppData\Local\BunnyLogs\Wallets
\AppData\Local\BunnyLogs\Messages
\AppData\Local\BunnyLogs\VPNs
\AppData\Local\BunnyLogs\Games
\AppData\Local\BunnyLogs\Information.txt

http://37.139.129.145/Bunny/StealerLogs/BunnyLogs_
&link=
&keys=
&vpn=
&messages=
&crypto=
&chromium=
http://37.139.129.145/Bunny/StealerRegistration.php?country=

C:\Users\user\Desktop\Bunny\Bunny\Release\Bunny.pdb

/
