rule ta_translucent_werewolf_deskrat
{
    meta:
        description = "Detects Translucent Werewolf (APT36) DeskRAT (StealthServer) malware"
        author = "@t3ft3lb"
        date = "2026-03-08"
        reference_1 = "https://blog.sekoia.io/transparenttribe-targets-indian-military-organisations-with-deskrat/"
        reference_2 = "https://blog.xlab.qianxin.com/apt-stealthserver-en/"
        hash1 = "567dfbe825e155691329d74d015db339e1e6db73b704b3246b3f015ffd9f0b33" // ELF64
        hash2 = "56260e90bba2c50af7c6d82e8656224ece23445f1d76e87a97c938ad9883005f" // PE64

    strings:
        $x0 = "D:/bossmaya/linuxnewdownloader" ascii fullword
        $x1 = "D:/bossmaya/newlinuxblkul/client" ascii fullword
        $x2 = "D:/bossmaya/client" ascii fullword
        $x3 = "D:/bossmaya/newblkul/client" ascii fullword
        $x4 = "/home/boss/Desktop/tgtfile" ascii fullword

        $s0 = "RunInStealthMode" ascii fullword
        $s1 = "installLinuxPersistence" ascii fullword
        $s2 = "init_linux_proc_simulation" ascii fullword
        $s3 = "InstallPersistenceFeatures" ascii fullword
        $s4 = "AddToCrontabScheduler" ascii fullword
        $s5 = "installPersistence" ascii fullword
        $s6 = "getCommandsFromServer" ascii fullword
        $s7 = "github.com/gorilla/websocket" ascii fullword
        $s8 = "obfFindWorkingServer" ascii fullword
        $s9 = "obfAntiDebugStrict" ascii fullword
        $s10 = "UltraConnectionObfuscator" ascii fullword
        $s11 = "UltraClientInfo" ascii fullword
        $s12 = "[ULTRA" ascii fullword

    condition:
        (
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) or
            uint32(0) == 0x464C457F
        ) and
        filesize > 4MB and filesize < 35MB and
        any of ($x*) and 3 of ($s*)
}